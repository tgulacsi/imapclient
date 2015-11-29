/*
Copyright 2014 Tamás Gulácsi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package imapclient is for listing folders, reading messages
// and moving them around (delete, unread, move).
package imapclient

import (
	"crypto/tls"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mxk/go-imap/imap"
	"github.com/tgulacsi/go/loghlp"
	"gopkg.in/inconshreveable/log15.v2"
)

var (
	// Log uses DiscardHandler (produces no output) by default.
	Log = log15.New("lib", "imapclient")

	// Timeout is the client timeout - 30 seconds by default.
	Timeout = 30 * time.Second

	// TLSConfig is the client's config for DialTLS.
	TLSConfig = tls.Config{InsecureSkipVerify: true}
)

func init() {
	Log.SetHandler(log15.DiscardHandler())
}

// Client interface declares the needed methods for listing messages,
// deleting and moving them around.
type Client interface {
	Connect() error
	Close(commit bool) error
	List(mbox, pattern string, all bool) ([]uint32, error)
	ReadTo(w io.Writer, msgID uint32) (int64, error)
	Mark(msgID uint32, seen bool) error
	Delete(msgID uint32) error
	Move(msgID uint32, mbox string) error
	SetLogMask(mask imap.LogMask) imap.LogMask
}

const (
	noTLS    = -1
	maybeTLS = 0
	forceTLS = 1
)

type client struct {
	host, username, password string
	port, tls                int
	noUTF8                   bool
	c                        *imap.Client
	created                  []string
	logMask                  imap.LogMask
}

// NewClient returns a new (not connected) Client, using TLS iff port == 143.
func NewClient(host string, port int, username, password string) Client {
	if port == 0 {
		port = 143
	}
	if port == 143 {
		return NewClientNoTLS(host, port, username, password)
	}
	return NewClientTLS(host, port, username, password)
}

// NewClientTLS returns a new (not connected) Client, using TLS.
func NewClientTLS(host string, port int, username, password string) Client {
	if port == 0 {
		port = 143
	}
	return &client{host: host, port: port, username: username, password: password, tls: forceTLS}
}

// NewClientNoTLS returns a new (not connected) Client, without TLS.
func NewClientNoTLS(host string, port int, username, password string) Client {
	if port == 0 {
		port = 143
	}
	return &client{host: host, port: port, username: username, password: password, tls: noTLS}
}

// String returns the connection parameters.
func (c client) String() string {
	return c.username + "@" + c.host + ":" + strconv.Itoa(c.port)
}

// SetLogMask allows setting the underlying imap.LogMask.
func (c client) SetLogMask(mask imap.LogMask) imap.LogMask {
	c.logMask = mask
	if c.c != nil {
		return c.c.SetLogMask(imap.LogAll)
	}
	return mask
}

// ReadTo reads the message identified by the given msgID, into the io.Writer.
func (c client) ReadTo(w io.Writer, msgID uint32) (int64, error) {
	var length int64
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	cmd, err := c.c.UIDFetch(set, "BODY.PEEK[]")
	if err != nil {
		return length, err
	}

	for cmd.InProgress() {
		// wait for server response
		if err = c.c.Recv(Timeout); err != nil {
			if err == io.EOF {
				break
			}
			return length, err
		}
		// Process data.
		for _, resp := range cmd.Data {
			//Log.Debug("resp", "resp", resp, "messageinfo", resp.MessageInfo(), "attrs", resp.MessageInfo().Attrs)
			n, err := w.Write(imap.AsBytes(resp.MessageInfo().Attrs["BODY[]"]))
			if err != nil {
				return length, err
			}
			length += int64(n)
		}
		cmd.Data = nil
	}

	// Check command completion status.
	if _, err = cmd.Result(imap.OK); err != nil {
		return length, err
	}
	return length, nil
}

// Move the msgID to the given mbox.
func (c *client) Move(msgID uint32, mbox string) error {
	created := false
	for _, k := range c.created {
		if mbox == k {
			created = true
			break
		}
	}
	if !created {
		Log.Info("Create", "mbox", mbox)
		c.created = append(c.created, mbox)
		if _, err := imap.Wait(c.c.Create(mbox)); err != nil {
			Log.Warn("Create", "mbox", mbox, "error", err)
		}
	}

	set := &imap.SeqSet{}
	set.AddNum(msgID)
	_, err := imap.Wait(c.c.UIDCopy(set, mbox))
	if err != nil {
		return err
	}
	_, err = imap.Wait(c.c.UIDStore(set, "+FLAGS", imap.Field(`\Deleted`)))
	return err
}

// List the messages from the given mbox, matching the pattern.
// Lists only new (UNSEEN) messages iff all is false.
func (c *client) List(mbox, pattern string, all bool) ([]uint32, error) {
	Log.Debug("List", "mbox", mbox, "pattern", pattern)
	_, err := imap.Wait(c.c.Select(mbox, false))
	if err != nil {
		return nil, err
	}
	var fields = make([]imap.Field, 0, 4)
	if all {
		fields = append(fields, imap.Field("NOT"), imap.Field("DELETED"))
	} else {
		fields = append(fields, imap.Field("UNSEEN"))
	}
	if pattern != "" {
		fields = append(fields, imap.Field("SUBJECT"), c.c.Quote(pattern))
	}
	ok := false
	var cmd *imap.Command
	if !c.noUTF8 {
		if cmd, err = imap.Wait(c.c.UIDSearch(fields...)); err != nil {
			Log.Debug("UIDSearch", "fields", fields, "error", err)
			if strings.Index(err.Error(), "BADCHARSET") >= 0 {
				c.noUTF8 = true
			} else {
				return nil, err
			}
		} else {
			ok = true
		}
	}
	if !ok && c.noUTF8 {
		if pattern != "" {
			fields[len(fields)-1] = c.c.Quote(imap.UTF7Encode(pattern))
		}
		cmd, err = imap.Wait(c.c.Send("UID SEARCH", fields))
		Log.Debug("UID SEARCH", "fields", fields, "error", err)
		if err != nil {
			return nil, err
		}
	}
	if _, err = cmd.Result(imap.OK); err != nil {
		return nil, err
	}
	Log.Debug("List", "data", cmd.Data)
	var uids []uint32
	for _, resp := range cmd.Data {
		uids = append(uids, resp.SearchResults()...)
	}
	return uids, nil
}

// Close closes the currently selected mailbox, then logs out.
func (c *client) Close(expunge bool) error {
	if c.c == nil {
		return nil
	}
	c.c.Close(expunge)
	_, err := imap.Wait(c.c.Logout(Timeout))
	c.c = nil
	return err
}

// Mark the message seen/unseed
func (c *client) Mark(msgID uint32, seen bool) error {
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	item := "+FLAGS"
	if !seen {
		item = "-FLAGS"
	}
	_, err := imap.Wait(c.c.UIDStore(set, item, imap.Field(`\Seen`)))
	return err
}

// Delete the message
func (c *client) Delete(msgID uint32) error {
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	_, err := imap.Wait(c.c.UIDStore(set, "+FLAGS", imap.Field(`\Deleted`)))
	return err
}

// Connect to the server.
func (c *client) Connect() error {
	addr := c.host + ":" + strconv.Itoa(c.port)
	var err error
	noTLS := c.tls == noTLS || c.tls == maybeTLS && c.port == 143
	if noTLS {
		c.c, err = imap.Dial(addr)
	} else {
		c.c, err = imap.DialTLS(addr, &TLSConfig)
		if err != nil {
			if strings.Contains(err.Error(), "oversized") {
				Log.Warn("Retry without TLS")
				c.c, err = imap.Dial(addr)
			}
		}
	}
	if err != nil {
		Log.Error("Connect", "addr", addr, "error", err)
		return err
	}
	c.c.SetLogger(loghlp.AsStdLog(Log, log15.LvlDebug))
	if c.logMask != 0 {
		c.c.SetLogMask(c.logMask)
	}
	// Print server greeting (first response in the unilateral server data queue)
	Log.Debug("Server says", "hello", c.c.Data[0].Info)
	c.c.Data = nil

	Log.Debug("server", "capabilities", c.c.Caps)
	// Enable encryption, if supported by the server
	if c.c.Caps["STARTTLS"] {
		Log.Info("Starting TLS")
		c.c.StartTLS(&TLSConfig)
	}

	// Authenticate
	if c.c.State() == imap.Login {
		sLog := Log.New("username", c.username)
		sLog.Info("Login")
		if _, err = c.c.Login(c.username, c.password); err != nil {
			sLog.Error("Login", "capabilities", c.c.Caps, "error", err)
			sLog.Info("CramAuth")
			if _, err = c.c.Auth(CramAuth(c.username, c.password)); err != nil {
				sLog.Error("Authenticate", "error", err)
				username, identity := c.username, ""
				if i := strings.IndexByte(username, '\\'); i >= 0 {
					identity, username = strings.TrimPrefix(username[i+1:], "\\"), username[:i]
				}
				pLog := Log.New("username", username, "identity", identity)
				pLog.Info("PlainAuth")
				if _, err = c.c.Auth(imap.PlainAuth(username, c.password, identity)); err != nil {
					pLog.Error("PlainAuth", "error", err)
					return err
				}
			}
		}
	}

	if c.c.Caps["COMPRESS=DEFLATE"] {
		if _, err := c.c.CompressDeflate(2); err != nil {
			Log.Info("CompressDeflate", "error", err)
		}
	}

	return nil
}
