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
	"strconv"
	"io"
	"strings"
	"time"

	"github.com/mxk/go-imap/imap"
	"github.com/tgulacsi/go/loghlp"
	"gopkg.in/inconshreveable/log15.v2"
)

var Log = log15.New("lib", "imapclient")

func init() {
	Log.SetHandler(log15.DiscardHandler())
}

// Client interface declares the needed methods for listing messages,
// deleting and moving them around.
type Client interface {
	Connect() error
	Close(commit bool) error
	ListNew(mbox, pattern string) ([]uint32, error)
	WriteTo(w io.Writer, msgID uint32) (int64, error)
	Mark(msgID uint32, seen bool) error
	Delete(msgID uint32) error
	Move(msgID uint32, mbox string) error
}

var TLSConfig = tls.Config{InsecureSkipVerify: true}

type client struct {
	host, username, password string
	port                     int
	noUTF8                   bool
	c                        *imap.Client
}

func NewClient(host string, port int, username, password string) Client {
	if port == 0 {
		port = 143
	}
	return &client{host: host, port: port, username: username, password: password}
}

func (c client) WriteTo(w io.Writer, msgID uint32) (int64,error) {
	var length int64
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	cmd, err := imap.Wait(c.c.UIDFetch(set, "BODY.PEEK[]"))
	if err != nil {
		return length, err
	}
	if _, err = cmd.Result(imap.OK); err != nil {
		return length, err
	}
	for _, resp := range cmd.Data {
		//Log.Debug("resp", "resp", resp, "messageinfo", resp.MessageInfo(), "attrs", resp.MessageInfo().Attrs)
		n, err := w.Write(imap.AsBytes(resp.MessageInfo().Attrs["BODY[]"]))
		if err != nil {
			return length, err
		}
		length += int64(n)
	}
	return length, nil
}

func (c client) Move(msgID uint32, mbox string) error {
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	_, err := imap.Wait(c.c.UIDCopy(set, mbox))
	if err != nil {
		return err
	}
	_, err = imap.Wait(c.c.UIDStore(set, "+FLAGS", imap.Field(`\Deleted`)))
	return err
}

func (c *client) ListNew(mbox, pattern string) ([]uint32, error) {
	_, err := imap.Wait(c.c.Select(mbox, false))
	if err != nil {
		return nil, err
	}
	var fields = make([]imap.Field, 1, 3)
	fields[0] = imap.Field("UNSEEN")
	if pattern != "" {
		fields = append(append(fields, imap.Field("SUBJECT")), c.c.Quote(pattern))
	}
	var cmd *imap.Command
	if !c.noUTF8 {
		cmd, err = imap.Wait(c.c.UIDSearch(fields...))
		if err != nil && strings.Index(err.Error(), "BADCHARSET") >= 0 {
			c.noUTF8 = true
		} else {
			return nil, err
		}
	}
	if c.noUTF8 {
		if len(fields) == 3 {
			fields[2] = c.c.Quote(imap.UTF7Encode(pattern))
		}
		cmd, err = imap.Wait(c.c.Send("UID SEARCH", fields))
		if err != nil {
			return nil, err
		}
	}
	if _, err = cmd.Result(imap.OK); err != nil {
		return nil, err
	}
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
	_, err := imap.Wait(c.c.Logout(30 * time.Second))
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

func (c *client) Connect() error {
	addr := c.host + ":" + strconv.Itoa(c.port)
	var err error
	if c.port == 143 {
		c.c, err = imap.Dial(addr)
	} else {
		c.c, err = imap.DialTLS(addr, &TLSConfig)
	}
	if err != nil {
		return err
	}
	c.c.SetLogger(loghlp.AsStdLog(Log, log15.LvlDebug))
	c.c.SetLogMask(imap.LogAll)
	// Print server greeting (first response in the unilateral server data queue)
	Log.Debug("Server says", "hello", c.c.Data[0].Info)
	c.c.Data = nil

	Log.Debug("server", "capabilities", c.c.Caps)
	// Enable encryption, if supported by the server
	if c.c.Caps["STARTTLS"] {
		c.c.StartTLS(nil)
	}

	// Authenticate
	if c.c.State() == imap.Login {
		if _, err = c.c.Login(c.username, c.password); err != nil {
			if _, err = c.c.Auth(CramAuth(c.username, c.password)); err != nil {
				return err
			}
		}
	}
	return nil
}
