// Copyright 2021, 2022 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package imapclient is for listing folders, reading messages
// and moving them around (delete, unread, move).
package imapclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/go-logr/logr"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-sasl"
)

type LogMask bool

const LogAll = LogMask(true)

var (
	logger = logr.Discard()

	// Timeout is the client timeout - 30 seconds by default.
	Timeout = 30 * time.Second

	// TLSConfig is the client's config for DialTLS.
	TLSConfig = tls.Config{InsecureSkipVerify: true} //nolint:gas
)

func SetLogger(lgr logr.Logger) { logger = lgr }

// Client interface declares the needed methods for listing messages,
// deleting and moving them around.
type Client interface {
	MinClient
	Connect() error
	MoveC(ctx context.Context, msgID uint32, mbox string) error
	MarkC(ctx context.Context, msgID uint32, seen bool) error
	List(mbox, pattern string, all bool) ([]uint32, error)
	ReadTo(w io.Writer, msgID uint32) (int64, error)
	SetLogger(logr.Logger)
	SetLogMaskC(context.Context, LogMask) LogMask
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
	SetLogMask(mask LogMask) LogMask
	SetLoggerC(ctx context.Context)
	Select(ctx context.Context, mbox string) error
	Watch(ctx context.Context) ([]uint32, error)
	WriteTo(ctx context.Context, mbox string, msg []byte, date time.Time) error
}

var _ = Client(MaxClient{})

type MaxClient struct {
	MinClient
}

func (c MaxClient) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	return c.MinClient.ConnectC(ctx)
}
func (c MaxClient) List(mbox, pattern string, all bool) ([]uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	return c.MinClient.ListC(ctx, mbox, pattern, all)
}
func (c MaxClient) ReadTo(w io.Writer, msgID uint32) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	return c.MinClient.ReadToC(ctx, w, msgID)
}
func (c MaxClient) SetLogger(logger logr.Logger) {
	c.MinClient.SetLoggerC(logr.NewContext(context.Background(), logger))
}
func (c MaxClient) SetLogMaskC(ctx context.Context, mask LogMask) LogMask {
	return c.MinClient.SetLogMask(mask)
}
func (c MaxClient) MoveC(ctx context.Context, msgID uint32, mbox string) error {
	return c.MinClient.Move(msgID, mbox)
}
func (c MaxClient) MarkC(ctx context.Context, msgID uint32, seen bool) error {
	return c.MinClient.Mark(msgID, seen)
}

type tlsPolicy int8

const (
	NoTLS    = tlsPolicy(-1)
	MaybeTLS = tlsPolicy(0)
	ForceTLS = tlsPolicy(1)
)

type imapClient struct {
	c      *client.Client
	status *imap.MailboxStatus
	logger logr.Logger
	ServerAddress
	created []string
	logMask LogMask
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

// FromServerAddress returns a new (not connected) Client, using the ServerAddress.
func FromServerAddress(sa ServerAddress) Client {
	return &imapClient{ServerAddress: sa}
}

// NewClientTLS returns a new (not connected) Client, using TLS.
func NewClientTLS(host string, port int, username, password string) Client {
	if port == 0 {
		port = 143
	}
	return FromServerAddress(ServerAddress{
		Host: host, Port: uint32(port),
		Username: username, Password: password,
		TLSPolicy: ForceTLS,
	})
}

// NewClientNoTLS returns a new (not connected) Client, without TLS.
func NewClientNoTLS(host string, port int, username, password string) Client {
	if port == 0 {
		port = 143
	}
	return FromServerAddress(ServerAddress{
		Host: host, Port: uint32(port),
		Username: username, Password: password,
		TLSPolicy: NoTLS,
	})
}

// ServerAddress represents the server's address.
type ServerAddress struct {
	Host                   string
	Username, Password     string
	ClientID, ClientSecret string
	Port                   uint32
	TLSPolicy              tlsPolicy
}

// URL representation of the server address.
func (m ServerAddress) URL() *url.URL {
	if m.Port == 0 {
		m.Port = 993
	}
	u := url.URL{
		User: url.UserPassword(m.Username, m.Password),
		Host: fmt.Sprintf("%s:%d", m.Host, m.Port),
	}
	if m.Port == 143 {
		u.Scheme = "imap"
	} else {
		u.Scheme = "imaps"
	}
	if m.ClientID != "" {
		u.RawQuery = fmt.Sprintf("clientID=%s&clientSecret=%s",
			url.QueryEscape(m.ClientID), url.QueryEscape(m.ClientSecret))
	}
	return &u
}
func (m ServerAddress) String() string {
	return m.URL().String()
}

// Mailbox is the ServerAddress with Mailbox info appended.
type Mailbox struct {
	Mailbox string
	ServerAddress
}

func (m Mailbox) String() string {
	u := m.URL()
	u.Path = "/" + m.Mailbox
	return u.String()
}

// ParseMailbox parses an imaps://user:passw@host:port/mailbox URL.
func ParseMailbox(s string) (Mailbox, error) {
	var m Mailbox
	u, err := url.Parse(s)
	if err != nil {
		return m, err
	}
	host, portS, err := net.SplitHostPort(u.Host)
	if err != nil {
		return m, err
	}
	m.Host = host
	if portS == "" {
		m.Port = 993
	} else if port, err := strconv.Atoi(portS); err != nil {
		return m, err
	} else {
		m.Port = uint32(port)
	}
	if u.Scheme == "imaps" {
		m.TLSPolicy = ForceTLS
	} else if u.Scheme == "imap" {
		m.TLSPolicy = NoTLS
	}
	if u.User != nil {
		m.Username = u.User.Username()
		m.Password, _ = u.User.Password()
	}
	m.Mailbox = strings.TrimLeft(u.Path, "/")
	q := u.Query()
	m.ClientID = q.Get("clientID")
	m.ClientSecret = q.Get("clientSecret")
	return m, nil
}

func (m Mailbox) Connect(ctx context.Context) (Client, error) {
	c := FromServerAddress(m.ServerAddress).(*imapClient)
	if err := c.ConnectC(ctx); err != nil {
		c.Close(false)
		return nil, err
	}
	if err := c.Select(ctx, m.Mailbox); err == nil {
		return c, nil
	}
	if err := c.c.Create(m.Mailbox); err != nil {
		c.Close(false)
		return nil, err
	}
	return c, c.Select(ctx, m.Mailbox)
}

// String returns the connection parameters.
func (c *imapClient) String() string {
	return c.ServerAddress.String()
}

// SetLogMaskC allows setting the underlying imap.LogMask,
// and also sets the standard logger's destination to the ctx's logger.
func (c *imapClient) SetLogMaskC(ctx context.Context, mask LogMask) LogMask {
	c.logMask = mask
	c.SetLoggerC(ctx)
	if c.c != nil {
		if c.logMask {
			c.c.SetDebug(loggerWriter{c.logger})
		} else {
			c.c.SetDebug(nil)
		}
	}
	return mask
}

// SetLogMask allows setting the underlying imap.LogMask.
func (c *imapClient) SetLogMask(mask LogMask) LogMask {
	return c.SetLogMaskC(context.Background(), mask)
}

func (c *imapClient) SetLogger(logger logr.Logger) {
	c.logger = logger
	if c.c != nil {
		c.c.ErrorLog = stdlog.New(loggerWriter{c.logger}, "ERR ", 0)
	}
}

func (c *imapClient) SetLoggerC(ctx context.Context) {
	var ssl string
	if c.TLSPolicy == ForceTLS {
		ssl = "SSL"
	}
	logger := GetLogger(ctx).WithValues(
		"imap_server", fmt.Sprintf("%s:%s:%d:%s", c.Username, c.Host, c.Port, ssl),
	)
	c.SetLogger(logger)
}

// Select selects the mailbox to use - it is needed before ReadTo
// (List includes this).
func (c *imapClient) Select(ctx context.Context, mbox string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	c.status, err = c.c.Select(mbox, false)
	if err != nil {
		return fmt.Errorf("SELECT %q: %w", mbox, err)
	}
	return nil
}

// ReadToC reads the message identified by the given msgID, into the io.Writer,
// within the given context (deadline).
func (c *imapClient) ReadToC(ctx context.Context, w io.Writer, msgID uint32) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return c.Peek(ctx, w, msgID, "")
}

// Peek into the message. Possible what: HEADER, TEXT, or empty (both) -
// see http://tools.ietf.org/html/rfc3501#section-6.4.5
func (c *imapClient) Peek(ctx context.Context, w io.Writer, msgID uint32, what string) (int64, error) {
	section := &imap.BodySectionName{BodyPartName: imap.BodyPartName{Specifier: imap.PartSpecifier(what)}, Peek: true}
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	ch := make(chan *imap.Message, 1)
	done := make(chan error, 1)
	c.setTimeout(ctx)
	go func() { done <- c.c.UidFetch(set, []imap.FetchItem{section.FetchItem()}, ch) }()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case err := <-done:
		return 0, err
	case msg, ok := <-ch:
		if !ok {
			return 0, io.EOF
		}
		if msg != nil {
			return io.Copy(w, msg.GetBody(section))
		}
	}
	return 0, nil
}

// Fetch the message. Possible what: RFC3551 6.5.4 (RFC822.SIZE, ENVELOPE, ...). The default is "RFC822.SIZE ENVELOPE".
func (c *imapClient) FetchArgs(ctx context.Context, what string, msgIDs ...uint32) (map[uint32]map[string][]string, error) {
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
	ss := strings.Fields(what)
	items := make([]imap.FetchItem, len(ss))
	for i, s := range ss {
		items[i] = imap.FetchItem(s)
	}

	done := make(chan error, 1)
	ch := make(chan *imap.Message, 1)
	c.setTimeout(ctx)
	go func() { defer close(ch); done <- c.c.UidFetch(set, items, ch) }()
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	case err := <-done:
		return result, err
	case msg := <-ch:
		m := make(map[string][]string)
		result[msg.Uid] = m

		if msg.Size != 0 {
			m[string(imap.FetchRFC822Size)] = []string{fmt.Sprintf("%d", msg.Size)}
		}
		if msg.Uid != 0 {
			m[string(imap.FetchUid)] = []string{fmt.Sprintf("%d", msg.Uid)}
		}
		if !msg.InternalDate.IsZero() {
			m[string(imap.FetchInternalDate)] = []string{msg.InternalDate.Format(time.RFC3339)}
		}
		for k, v := range msg.Items {
			m[string(k)] = []string{fmt.Sprintf("%v", v)}
		}
		if b := msg.BodyStructure; b != nil {
			m["BODY.MIME-TYPE"] = []string{b.MIMEType + "/" + b.MIMESubType}
			m["BODY.CONTENT-ID"] = []string{b.Id}
			m["BODY.CONTENT-DESCRIPTION"] = []string{b.Description}
			m["BODY.CONTENT-ENCODING"] = []string{b.Encoding}
			m["BODY.CONTENT-LENGTH"] = []string{fmt.Sprintf("%d", b.Size)}
			m["BODY.CONTENT-DISPOSITION"] = []string{b.Disposition}
			m["BODY.CONTENT-LANGUAGE"] = b.Language
			m["BODY.LOCATION"] = b.Location
			m["BODY.MD5"] = []string{b.MD5}
		}

		if env := msg.Envelope; env != nil {
			m["ENVELOPE.DATE"] = []string{env.Date.Format(time.RFC3339)}
			m["ENVELOPE.SUBJECT"] = []string{env.Subject}
			m["ENVELOPE.FROM"] = formatAddressList(nil, env.From)
			m["ENVELOPE.SENDER"] = formatAddressList(nil, env.Sender)
			m["ENVELOPE.REPLY-TO"] = formatAddressList(nil, env.ReplyTo)
			m["ENVELOPE.TO"] = formatAddressList(nil, env.To)
			m["ENVELOPE.CC"] = formatAddressList(nil, env.Cc)
			m["ENVELOPE.BCC"] = formatAddressList(nil, env.Bcc)
			m["ENVELOPE.IN-REPLY-TO"] = []string{env.InReplyTo}
			m["ENVELOPE.MESSAGE-ID"] = []string{env.MessageId}
		}
	}
	return result, nil
}

func formatAddressList(dst []string, addrs []*imap.Address) []string {
	for _, addr := range addrs {
		dst = append(dst, formatAddress(addr))
	}
	return dst
}

func formatAddress(addr *imap.Address) string {
	s := "<" + addr.MailboxName + "@" + addr.HostName + ">"
	if addr.PersonalName != "" {
		return addr.PersonalName + " " + s
	}
	return s
}

// ReadTo reads the message identified by the given msgID, into the io.Writer.
func (c *imapClient) ReadTo(w io.Writer, msgID uint32) (int64, error) {
	return c.ReadToC(context.Background(), w, msgID)
}

// Move the msgID to the given mbox.
func (c *imapClient) Move(msgID uint32, mbox string) error {
	return c.MoveC(context.Background(), msgID, mbox)
}

// MoveC moves the msgid to the given mbox, within deadline.
func (c *imapClient) MoveC(ctx context.Context, msgID uint32, mbox string) error {
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
		logger.Info("Create", "box", mbox)
		c.created = append(c.created, mbox)
		if err := c.c.Create(mbox); err != nil {
			logger.Error(err, "Create", "box", mbox)
		}
	}

	set := &imap.SeqSet{}
	set.AddNum(msgID)
	if err := c.c.UidCopy(set, mbox); err != nil {
		return fmt.Errorf("copy %s: %w", mbox, err)
	}
	return c.DeleteC(ctx, msgID)
}

// ListC the messages from the given mbox, matching the pattern.
// Lists only new (UNSEEN) messages iff all is false,
// withing the given context (deadline).
func (c *imapClient) ListC(ctx context.Context, mbox, pattern string, all bool) ([]uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	//Log := GetLogger(ctx)
	//Log("msg","List", "box",mbox, "pattern",pattern)
	if err := c.Select(ctx, mbox); err != nil {
		return nil, fmt.Errorf("SELECT %q: %w", mbox, err)
	}

	crit := imap.NewSearchCriteria()
	crit.WithoutFlags = append(crit.WithoutFlags, imap.DeletedFlag)
	if !all {
		crit.WithoutFlags = append(crit.WithoutFlags, imap.SeenFlag)
	}
	if pattern != "" {
		crit.Header.Set("Subject", pattern)
	}
	// The response contains a list of message sequence IDs
	return c.c.UidSearch(crit)
}

// List the mailbox, where subject meets the pattern, and only unseen (when all is false).
func (c *imapClient) List(mbox, pattern string, all bool) ([]uint32, error) {
	return c.ListC(context.Background(), mbox, pattern, all)
}

// Mailboxes returns the list of mailboxes under root
func (c *imapClient) Mailboxes(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ch := make(chan *imap.MailboxInfo, 1)
	done := make(chan error, 1)
	go func() { done <- c.c.List(root, "*", ch) }()
	var names []string
	select {
	case <-ctx.Done():
		return names, ctx.Err()
	case err := <-done:
		return names, err
	case mi := <-ch:
		if mi != nil {
			names = append(names, mi.Name)
		}
	}
	return names, nil
}

// Close closes the currently selected mailbox, then logs out.
func (c *imapClient) CloseC(ctx context.Context, expunge bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.c == nil {
		return nil
	}
	var err error
	if expunge {
		err = c.c.Expunge(nil)
	}
	if closeErr := c.c.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if logoutErr := c.c.Logout(); logoutErr != nil && err == nil {
		err = logoutErr
	}
	c.c = nil
	return err
}

// Close closes the currently selected mailbox, then logs out.
func (c *imapClient) Close(expunge bool) error {
	return c.CloseC(context.Background(), expunge)
}

// Mark the message seen/unseed
func (c *imapClient) Mark(msgID uint32, seen bool) error {
	return c.MarkC(context.Background(), msgID, seen)
}

// MarkC marks the message seen/unseen, within the given context (deadline).
func (c *imapClient) MarkC(ctx context.Context, msgID uint32, seen bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	item := imap.FormatFlagsOp(imap.AddFlags, true)
	if !seen {
		item = imap.FormatFlagsOp(imap.RemoveFlags, true)
	}
	flags := []interface{}{imap.SeenFlag}
	return c.c.UidStore(set, item, flags, nil)
}

// Delete the message
func (c *imapClient) Delete(msgID uint32) error {
	return c.DeleteC(context.Background(), msgID)
}

// DeleteC deletes the message, within the given context (deadline).
func (c *imapClient) DeleteC(ctx context.Context, msgID uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	set := &imap.SeqSet{}
	set.AddNum(msgID)
	item := imap.FormatFlagsOp(imap.AddFlags, true)
	flags := []interface{}{imap.DeletedFlag}
	return c.c.UidStore(set, item, flags, nil)
}

// Watch the current mailbox for changes.
// Return on the first server notification.
func (c *imapClient) Watch(ctx context.Context) ([]uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ch := make(chan client.Update, 1)
	var uids []uint32
	c.c.Updates = ch
	select {
	case <-ctx.Done():
		c.c.Updates = nil
		return uids, ctx.Err()
	case upd := <-ch:
		switch x := upd.(type) {
		case *client.MessageUpdate:
			uids = append(uids, x.Message.Uid)
		}
	}
	c.c.Updates = nil
	return uids, nil
}

// WriteTo appends the message the given mailbox.
func (c *imapClient) WriteTo(ctx context.Context, mbox string, msg []byte, date time.Time) error {
	return c.c.Append(mbox, nil, date, literalBytes(msg))
}

// Connect to the server.
func (c *imapClient) Connect() error {
	return c.ConnectC(context.Background())
}

// ConnectC connects to the server, within the given context (deadline).
func (c *imapClient) ConnectC(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.c != nil {
		c.c.Logout()
		c.c = nil
	}
	logger := GetLogger(ctx)
	addr := c.Host + ":" + strconv.Itoa(int(c.Port))
	var err error
	noTLS := c.TLSPolicy == NoTLS || c.TLSPolicy == MaybeTLS && c.Port == 143
	if noTLS {
		c.c, err = client.Dial(addr)
	} else {
		c.c, err = client.DialTLS(addr, &TLSConfig)
	}
	if err != nil {
		err = fmt.Errorf("%s: %w", addr, err)
	}
	if err != nil {
		logger.Error(err, "Connect", "addr", addr)
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	c.SetLogMaskC(ctx, c.logMask)
	c.c.Timeout = time.Minute
	// Enable encryption, if supported by the server
	if ok, _ := c.c.SupportStartTLS(); ok {
		logger.Info("Starting TLS")
		c.c.StartTLS(&TLSConfig)
	}

	// Authenticate
	return c.login(ctx)
}

var errNotLoggedIn = errors.New("not logged in")

func (c *imapClient) login(ctx context.Context) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	logger := GetLogger(ctx).WithValues("username", c.Username)
	order := []string{"login", "oauthbearer", "xoauth2", "cram-md5", "plain"}
	if len(c.Password) > 40 {
		order[0], order[1], order[2] = order[1], order[2], order[0]
	}

	oLogMask := c.logMask
	defer func() { c.SetLogMaskC(ctx, oLogMask) }()
	c.SetLogMaskC(ctx, LogAll)

	for _, method := range order {
		logger := logger.WithValues("method", method)
		logger.Info("try logging in")
		err = errNotLoggedIn

		switch method {
		case "login":
			err = c.c.Login(c.Username, c.Password)

		case "xoauth2":
			// https://msdn.microsoft.com/en-us/library/dn440163.aspx
			if ok, _ := c.c.SupportAuth("XOAUTH2"); ok {
				err = c.c.Authenticate(sasl.NewXoauth2Client(c.Username, c.Password))
			}

		case "oauthbearer":
			if ok, _ := c.c.SupportAuth("OAUTHBEARER"); ok {
				err = c.c.Authenticate(sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{
					Username: c.Username, Token: c.Password,
				}))
			}

		case "cram-md5":
			if ok, _ := c.c.SupportAuth("CRAM-MD5"); ok {
				err = c.c.Authenticate(CramAuth(c.Username, c.Password))
			}

		case "plain":
			if ok, _ := c.c.SupportAuth("PLAIN"); ok {
				username, identity := c.Username, ""
				if i := strings.IndexByte(username, '\\'); i >= 0 {
					identity, username = strings.TrimPrefix(username[i+1:], "\\"), username[:i]
				}
				logger = logger.WithValues("method", method, "identity", identity)

				err = c.c.Authenticate(sasl.NewPlainClient(identity, username, c.Password))
			}
		}

		if err == nil || strings.Contains(err.Error(), "Already logged in") {
			logger.Info("logged in", "method", method, "error", err)
			return nil
		}
		logger.Error(err, "login failed", "method", method)
	}
	if err != nil {
		return err
	}
	return errNotLoggedIn
}

func (c *imapClient) setTimeout(ctx context.Context) {
	d, ok := ctx.Deadline()
	if !ok {
		return
	}
	c.c.Timeout = time.Until(d)
}

func literalBytes(msg []byte) imap.Literal {
	return literal{Reader: bytes.NewReader(msg), length: len(msg)}
}

type literal struct {
	io.Reader
	length int
}

func (lit literal) Len() int { return lit.length }

func GetLogger(ctx context.Context) logr.Logger {
	if lgr, err := logr.FromContext(ctx); err == nil {
		return lgr
	}
	return logger
}

var _ = io.Writer(loggerWriter{})

type loggerWriter struct {
	logr.Logger
}

func (lg loggerWriter) Write(p []byte) (int, error) {
	lg.Logger.Info(string(p))
	return len(p), nil
}
