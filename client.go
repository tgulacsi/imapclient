/*
Copyright 2017 Tamás Gulácsi

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
	"encoding/base64"
	"fmt"
	"io"
	stdlog "log"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/go-kit/kit/log"
	"github.com/mxk/go-imap/imap"
	"github.com/pkg/errors"
)

var (
	// Log uses DiscardHandler (produces no output) by default.
	Log = func(...interface{}) error { return nil }

	// Timeout is the client timeout - 30 seconds by default.
	Timeout = 30 * time.Second

	// TLSConfig is the client's config for DialTLS.
	TLSConfig = tls.Config{InsecureSkipVerify: true}
)

// Client interface declares the needed methods for listing messages,
// deleting and moving them around.
type Client interface {
	MinClient
	Connect() error
	List(mbox, pattern string, all bool) ([]uint32, error)
	ReadTo(w io.Writer, msgID uint32) (int64, error)
	SetLogger(*stdlog.Logger)
}

// MinClient is the minimal required methods for a client.
// You can make a full Client from it by wrapping in a MaxClient.
type MinClient interface {
	ConnectC(context.Context) error
	Close(commit bool) error
	ListC(ctx context.Context, mbox, pattern string, all bool) ([]uint32, error)
	Mailboxes(ctx context.Context, root string) ([]string, error)
	ReadToC(ctx context.Context, w io.Writer, msgID uint32) (int64, error)
	FetchArgs(ctx context.Context, what string, msgIDs ...uint32) (map[uint32]map[string][]string, error)
	Peek(ctx context.Context, w io.Writer, msgID uint32, what string) (int64, error)
	Mark(msgID uint32, seen bool) error
	Delete(msgID uint32) error
	Move(msgID uint32, mbox string) error
	SetLogMask(mask imap.LogMask) imap.LogMask
	SetLoggerC(ctx context.Context)
	Select(ctx context.Context, mbox string) error
	Watch(ctx context.Context) ([]uint32, error)
}

var _ = Client(MaxClient{})

type MaxClient struct {
	MinClient
}

func (c MaxClient) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	return c.ConnectC(ctx)
}
func (c MaxClient) List(mbox, pattern string, all bool) ([]uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	return c.ListC(ctx, mbox, pattern, all)
}
func (c MaxClient) ReadTo(w io.Writer, msgID uint32) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	return c.ReadToC(ctx, w, msgID)
}
func (c MaxClient) SetLogger(logger *stdlog.Logger) {
	c.SetLoggerC(CtxWithLogFunc(context.Background(), Log))
}

const (
	noTLS    = -1
	maybeTLS = 0
	forceTLS = 1
)

type client struct {
	host               string
	username, password string
	PathSep            string
	port, tls          int
	noUTF8             bool
	c                  *imap.Client
	created            []string
	logMask            imap.LogMask
	logger             *stdlog.Logger
}

func init() {
	imap.BufferSize = 1 << 20
	imap.DefaultLogger = stdlog.New(
		log.NewStdlibAdapter(log.LoggerFunc(Log)),
		"", 0)
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

// SetLogMaskC allows setting the underlying imap.LogMask,
// and also sets the standard logger's destination to the ctx's logger.
func (c client) SetLogMaskC(ctx context.Context, mask imap.LogMask) imap.LogMask {
	// Remove timestamp and other decorations of the std logger
	stdlog.SetFlags(0)

	Log := GetLog(ctx)
	stdlog.SetOutput(log.NewStdlibAdapter(log.LoggerFunc(Log)))

	c.logMask = mask
	if c.c == nil {
		imap.DefaultLogMask = c.logMask
	} else {
		return c.c.SetLogMask(c.logMask)
	}
	return mask
}

// SetLogMask allows setting the underlying imap.LogMask.
func (c client) SetLogMask(mask imap.LogMask) imap.LogMask {
	return c.SetLogMaskC(context.Background(), mask)
}

func (c client) SetLogger(logger *stdlog.Logger) {
	c.logger = logger
	if c.c == nil {
		imap.DefaultLogger = c.logger
	} else {
		c.c.SetLogger(c.logger)
	}
}

func (c client) SetLoggerC(ctx context.Context) {
	var ssl string
	if c.tls == forceTLS {
		ssl = "SSL"
	}
	logger := log.With(
		log.LoggerFunc(GetLog(ctx)),
		"imap_server",
		fmt.Sprintf("%s:%s:%d:%s", c.username, c.host, c.port, ssl),
	)
	c.logger = stdlog.New(log.NewStdlibAdapter(logger), "", 0)
	c.SetLogger(c.logger)
}

// Select selects the mailbox to use - it is needed before ReadTo
// (List includes this).
func (c client) Select(ctx context.Context, mbox string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd, err := c.c.Select(mbox, false)
	if err != nil {
		return errors.Wrapf(err, "SELECT %q", mbox)
	}
	_, err = c.WaitC(ctx, cmd)
	return err
}

// ReadToC reads the message identified by the given msgID, into the io.Writer,
// within the given context (deadline).
func (c client) ReadToC(ctx context.Context, w io.Writer, msgID uint32) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return c.Peek(ctx, w, msgID, "")
}

// Peek into the message. Possible what: HEADER, TEXT, or empty (both).
func (c client) Peek(ctx context.Context, w io.Writer, msgID uint32, what string) (int64, error) {
	var length int64
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	//Log := GetLogger(ctx)
	what = "BODY.PEEK[" + what + "]"
	//Log("msg","FETCH", "set", set, "what",what)
	cmd, err := c.c.UIDFetch(set, what)
	if err != nil {
		return length, errors.Wrapf(err, "UIDFetch %v %v", set, what)
	}
	var writeErr error
	ch := make(chan *imap.Response)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for resp := range ch {
			//Log("resp", resp)
			n, wErr := w.Write(imap.AsBytes(resp.MessageInfo().Attrs["BODY[]"]))
			if wErr != nil && writeErr == nil {
				writeErr = wErr
			}
			length += int64(n)
		}
	}()

	err = c.recvLoop(ctx, ch, cmd)
	wg.Wait()
	return length, err
}

// Fetch the message. Possible what: RFC3551 6.5.4 (RFC822.SIZE, ENVELOPE, ...). The default is "RFC822.SIZE ENVELOPE".
func (c client) FetchArgs(ctx context.Context, what string, msgIDs ...uint32) (map[uint32]map[string][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make(map[uint32]map[string][]string, len(msgIDs))
	set := &imap.SeqSet{}
	for _, msgID := range msgIDs {
		set.AddNum(msgID)
	}
	if what == "" {
		what = "RFC822.SIZE ENVELOPE"
	}

	//Log := GetLogger(ctx)
	//Log("msg","FETCH", "set",set, "what",what)
	cmd, err := c.c.UIDFetch(set, what)
	if err != nil {
		return nil, err
	}
	ch := make(chan *imap.Response, 1)
	go func() {
		for resp := range ch {
			mi := resp.MessageInfo()
			m := make(map[string][]string, len(mi.Attrs))
			for k, v := range mi.Attrs {
				switch x := v.(type) {
				case []imap.Field:
					m[k] = fieldsAsStrings(x)
				case imap.Field:
					m[k] = fieldsAsStrings([]imap.Field{x})
				default:
					m[k] = []string{fmt.Sprintf("%v", x)}
				}
			}
			result[mi.UID] = m
		}
	}()
	err = c.recvLoop(ctx, ch, cmd)
	return result, err
}

func (c client) recvLoop(ctx context.Context, dst chan<- *imap.Response, cmd *imap.Command) error {
	defer close(dst)
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Hour)
	}

	for cmd.InProgress() {
		if err := ctx.Err(); err != nil {
			return err
		}
		d := Timeout
		var last bool
		if e := time.Until(deadline); e < d {
			d = e
			last = true
		}

		// wait for server response
		if err := c.c.Recv(d); err != nil {
			if err == io.EOF {
				break
			} else if !last && strings.Contains(errors.Cause(err).Error(), "timeout") {
				continue
			}
			return errors.Wrap(err, "Recv "+cmd.String())
		}
		// Process data.
		for _, resp := range cmd.Data {
			if resp == nil {
				continue
			}
			//Log("resp", resp)
			dst <- resp
		}
		cmd.Data = cmd.Data[:0]
	}

	// Check command completion status.
	_, err := cmd.Result(imap.OK)
	return errors.Wrap(err, cmd.String())
}

func fieldsAsStrings(fields []imap.Field) []string {
	result := make([]string, len(fields))
	for i, f := range fields {
		if f == nil {
			continue
		}
		switch x := f.(type) {
		case string:
			result[i] = x
		case fmt.Stringer:
			result[i] = x.String()
		case uint32:
			result[i] = fmt.Sprintf("%d", x)
		default:
			result[i] = imap.AsString(f)
		}
	}
	return result
}

// ReadTo reads the message identified by the given msgID, into the io.Writer.
func (c client) ReadTo(w io.Writer, msgID uint32) (int64, error) {
	return c.ReadToC(context.Background(), w, msgID)
}

// Move the msgID to the given mbox.
func (c *client) Move(msgID uint32, mbox string) error {
	return c.MoveC(context.Background(), msgID, mbox)
}

// MoveC moves the msgid to the given mbox, within deadline.
func (c *client) MoveC(ctx context.Context, msgID uint32, mbox string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	created := false
	for _, k := range c.created {
		if mbox == k {
			created = true
			break
		}
	}
	if !created {
		Log("msg", "Create", "box", mbox)
		c.created = append(c.created, mbox)
		cmd, err := c.c.Create(mbox)
		if err == nil {
			_, err = c.WaitC(ctx, cmd)
		}
		if err != nil {
			Log("msg", "Create", "box", mbox, "error", err)
		}
	}

	set := &imap.SeqSet{}
	set.AddNum(msgID)
	cmd, err := c.c.UIDCopy(set, mbox)
	err = errors.Wrap(err, "copy "+mbox)
	if err == nil {
		_, err = c.WaitC(ctx, cmd)
	}
	if err != nil {
		return err
	}
	if cmd, err = c.c.UIDStore(set, "+FLAGS", imap.Field(`\Deleted`)); err != nil {
		c.WaitC(ctx, cmd)
		return err
	}
	_, err = c.WaitC(ctx, cmd)
	return err
}

// ListC the messages from the given mbox, matching the pattern.
// Lists only new (UNSEEN) messages iff all is false,
// withing the given context (deadline).
func (c *client) ListC(ctx context.Context, mbox, pattern string, all bool) ([]uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	//Log := GetLogger(ctx)
	//Log("msg","List", "box",mbox, "pattern",pattern)
	if err := c.Select(ctx, mbox); err != nil {
		return nil, errors.Wrapf(err, "SELECT %q", mbox)
	}
	var fields = make([]imap.Field, 0, 4)
	fields = append(fields, imap.Field("NOT DELETED"))
	if !all {
		fields = append(fields, imap.Field("UNSEEN"))
	}
	if pattern != "" {
		fields = append(fields, imap.Field("SUBJECT"), c.c.Quote(pattern))
	}
	ok := false
	var cmd *imap.Command
	var err error
	if !c.noUTF8 {
		if cmd, err = c.c.UIDSearch(fields...); err == nil {
			cmd, err = c.WaitC(ctx, cmd)
		}
		if err != nil {
			//Log("msg","UIDSearch", "fields",fields, "error",err)
			if strings.Contains(err.Error(), "BADCHARSET") {
				c.noUTF8 = true
			} else {
				return nil, errors.Wrapf(err, "UIDSearch(%v)", fields)
			}
		} else {
			ok = true
		}
	}
	if !ok && c.noUTF8 {
		if pattern != "" {
			fields[len(fields)-1] = c.c.Quote(imap.UTF7Encode(pattern))
		}
		if cmd, err = c.c.Send("UID SEARCH", fields); err == nil {
			cmd, err = c.WaitC(ctx, cmd)
		}
		//Log("msg","UID SEARCH", "fields", fields, "error",err)
		if err != nil {
			return nil, errors.Wrapf(err, "UIDSearch %v", fields)
		}
	}
	if _, err = cmd.Result(imap.OK); err != nil {
		return nil, err
	}
	//Log("msg","List", "data",cmd.Data)
	uids := make([]uint32, 0, len(cmd.Data))
	for _, resp := range cmd.Data {
		uids = append(uids, resp.SearchResults()...)
	}
	return uids, nil
}

// List the mailbox, where subject meets the pattern, and only unseen (when all is false).
func (c *client) List(mbox, pattern string, all bool) ([]uint32, error) {
	return c.ListC(context.Background(), mbox, pattern, all)
}

// Mailboxes returns the list of mailboxes under root
func (c *client) Mailboxes(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd, err := c.c.List(root, "*")
	if err != nil {
		return nil, errors.Wrapf(err, "LIST %q *", root)
	}
	if cmd, err = c.WaitC(ctx, cmd); err != nil {
		err = errors.Wrapf(err, "%q", cmd)
	}
	names := make([]string, 0, len(cmd.Data))
	for _, d := range cmd.Data {
		names = append(names, d.MailboxInfo().Name)
	}
	return names, err
}

// Close closes the currently selected mailbox, then logs out.
func (c *client) CloseC(ctx context.Context, expunge bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.c == nil {
		return nil
	}
	c.c.Close(expunge)
	cmd, err := c.c.Logout(getTimeout(ctx))
	if err != nil {
		return errors.Wrapf(err, "LOGOUT")
	}
	_, err = c.WaitC(ctx, cmd)
	if _, logoutErr := c.c.Logout(getTimeout(ctx)); logoutErr != nil && err == nil {
		err = logoutErr
	}
	c.c = nil
	return err
}

// Close closes the currently selected mailbox, then logs out.
func (c *client) Close(expunge bool) error {
	return c.CloseC(context.Background(), expunge)
}

// Mark the message seen/unseed
func (c *client) Mark(msgID uint32, seen bool) error {
	return c.MarkC(context.Background(), msgID, seen)
}

// MarkC marks the message seen/unseen, within the given context (deadline).
func (c *client) MarkC(ctx context.Context, msgID uint32, seen bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	item := "+FLAGS"
	if !seen {
		item = "-FLAGS"
	}
	cmd, err := c.c.UIDStore(set, item, imap.Field(`\Seen`))
	if err != nil {
		err = errors.Wrap(err, "\\Seen")
	} else {
		_, err = c.WaitC(ctx, cmd)
	}
	return err
}

// Delete the message
func (c *client) Delete(msgID uint32) error {
	return c.DeleteC(context.Background(), msgID)
}

// DeleteC deletes the message, within the given context (deadline).
func (c *client) DeleteC(ctx context.Context, msgID uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	cmd, err := c.c.UIDStore(set, "+FLAGS", imap.Field(`\Deleted`))
	if err != nil {
		err = errors.Wrap(err, "\\Deleted")
	} else {
		_, err = c.WaitC(ctx, cmd)
	}
	return err
}

// Watch the current mailbox for changes.
// Return on the first server notification.
func (c *client) Watch(ctx context.Context) ([]uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd, err := c.c.Idle()
	if err != nil {
		return nil, err
	}
	defer c.c.IdleTerm()

	done := make(chan error, 1)
	dst := make(chan *imap.Response, 1)
	go func() {
		defer close(done)
		done <- c.recvLoop(ctx, dst, cmd)
	}()

	var res []uint32
	Log := GetLog(ctx)
	select {
	case <-ctx.Done():
		return res, ctx.Err()
	case err = <-done:
		return res, err
	case resp := <-dst:
		Log("msg", "IDLE", "response", resp)
		if resp != nil && resp.Type == imap.Data && len(resp.Fields) > 0 {
			if u := imap.AsNumber(resp.Fields[0]); u == 0 {
				Log("error", string(resp.Raw))
			} else {
				res = append(res, u)
			}
		}
	}
	return res, err
}

// Connect to the server.
func (c *client) Connect() error {
	return c.ConnectC(context.Background())
}

// ConnectC connects to the server, within the given context (deadline).
func (c *client) ConnectC(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.c != nil {
		c.c.Logout(1 * time.Second)
		c.c = nil
	}
	Log := GetLog(ctx)
	addr := c.host + ":" + strconv.Itoa(c.port)
	var err error
	noTLS := c.tls == noTLS || c.tls == maybeTLS && c.port == 143
	if noTLS {
		c.c, err = imap.Dial(addr)
	} else {
		c.c, err = imap.DialTLS(addr, &TLSConfig)
	}
	err = errors.Wrap(err, addr)
	if err != nil && !noTLS {
		select {
		case <-ctx.Done():
			return err
		default:
		}
		if strings.Contains(err.Error(), "oversized") {
			Log("msg", "Retry without TLS")
			var noTLSErr error
			if c.c, noTLSErr = imap.Dial(addr); noTLSErr == nil {
				err = nil
			}
		}
	}
	if err != nil {
		Log("msg", "Connect", "addr", addr, "error", err)
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if c.logMask != 0 {
		c.SetLogMaskC(ctx, c.logMask)
	}
	if c.logger != nil {
		c.SetLogger(c.logger)
	}
	// Print server greeting (first response in the unilateral server data queue)
	//Log("msg","Server says", "info",c.c.Data[0].Info)
	c.c.Data = nil

	//Log("msg", "server", "capabilities", c.c.Caps)
	// Enable encryption, if supported by the server
	if c.c.Caps["STARTTLS"] {
		Log("msg", "Starting TLS")
		c.c.StartTLS(&TLSConfig)
	}

	// Authenticate
	if c.c.State() == imap.Login {
		if err = c.login(ctx); err != nil {
			return err
		}
	}

	if c.c.Caps["COMPRESS=DEFLATE"] {
		if _, err = c.c.CompressDeflate(2); err != nil {
			Log("msg", "CompressDeflate", "error", err)
		}
	}

	cmd, err := c.c.List("", "")
	if err != nil {
		return errors.Wrap(err, "List")
	}
	if _, err = c.WaitC(ctx, cmd); err != nil {
		return errors.Wrap(err, cmd.String())
	}
	c.PathSep = cmd.Data[0].MailboxInfo().Delim

	return nil
}

func (c client) login(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	Log("caps", c.c.Caps)
	Log := log.With(log.LoggerFunc(Log), "username", c.username).Log
	order := []string{"login", "xoauth2", "cram-md5", "plain"}
	if len(c.password) > 40 {
		order[0], order[1] = order[1], order[0]
	}

	var err error
	for _, method := range order {
		switch method {
		case "login":
			Log("msg", "Login")
			cmd, loginErr := c.c.Login(c.username, c.password)
			if loginErr != nil {
				err = loginErr
			} else {
				if _, err = c.WaitC(ctx, cmd); err == nil {
					return nil
				}
				Log("msg", "Login", "error", err)
			}

		case "xoauth2":
			Log("user", c.username, "passw", c.password)
			// https://msdn.microsoft.com/en-us/library/dn440163.aspx
			if c.c.Caps["AUTH=XOAUTH2"] {
				c.c.SetLogMask(imap.LogAll)
				_, err = c.c.Auth(XOAuth2Auth(c.username, c.password))
				c.SetLogMaskC(ctx, c.logMask)
				if err == nil {
					return nil
				}
				Log("msg", "XOAuth2", "error", err)
			}

		case "cram-md5":
			if c.c.Caps["AUTH=CRAM-MD5"] {
				Log("msg", "Login CramAuth", "capabilities", c.c.Caps, "error", err)
				if _, err = c.c.Auth(CramAuth(c.username, c.password)); err == nil {
					return nil
				}
				Log("msg", "Authenticate", "error", err)
			}

		case "plain":
			if c.c.Caps["AUTH=PLAIN"] {
				username, identity := c.username, ""
				if i := strings.IndexByte(username, '\\'); i >= 0 {
					identity, username = strings.TrimPrefix(username[i+1:], "\\"), username[:i]
				}

				Log("msg", "PlainAuth", "username", username, "identity", identity)
				if _, err = c.c.Auth(imap.PlainAuth(username, c.password, identity)); err == nil {
					return nil
				}
				Log("msg", "PlainAuth", "username", username, "identity", identity, "error", err)
			}
		}
	}
	if err != nil {
		return err
	}
	return errors.New("could not log in")
}

func getTimeout(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return Timeout
	}
	now := time.Now()
	if deadline.After(now.Add(Timeout)) {
		return Timeout
	}
	return deadline.Sub(now)
}

// WaitC waits to the response for the command, within context (deadline).
func (c client) WaitC(ctx context.Context, cmd *imap.Command) (*imap.Command, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	Log := GetLog(ctx)
	if !cmd.InProgress() {
		return imap.Wait(cmd, nil)
	}
	deadline := time.Now().Add(getTimeout(ctx))
	var err error
Loop:
	for cmd.InProgress() && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			if err = c.c.Recv(time.Second); err == nil || err != imap.ErrTimeout {
				if err != nil {
					Log("msg", "Recv", "error", err)
				}
				break Loop
			}
		}
	}
	return imap.Wait(cmd, errors.Wrap(err, cmd.String()))
}

func GetLog(ctx context.Context) func(...interface{}) error {
	if Log, _ := ctx.Value(logCtxKey).(func(...interface{}) error); Log != nil {
		return Log
	}
	return Log
}

// XOAuth2Auth returns an imap.SASL that authenticates with a username and a bearer token.
func XOAuth2Auth(username, bearer string) imap.SASL {
	return xoauth2Auth("user=" + username + "\x01auth=Bearer " + bearer + "\x01\x01")
}

type xoauth2Auth []byte

func (a xoauth2Auth) Start(s *imap.ServerInfo) (mech string, ir []byte, err error) {
	b := make([]byte, base64.StdEncoding.EncodedLen(len(a)))
	base64.StdEncoding.Encode(b, a)
	return "XOAUTH2", b, nil
}

func (a xoauth2Auth) Next(challenge []byte) (response []byte, err error) {
	return nil, errors.Errorf("unexpected challenge: %s", challenge)
}
