// Copyright 2021, 2023 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package o365

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-message"
	"github.com/tgulacsi/imapclient/v2"
)

var _ = imapclient.Client((*oClient)(nil))

type oClient struct {
	*client
	u2s      map[uint32]string
	s2u      map[string]uint32
	selected string
	mu       sync.Mutex
}

func NewIMAPClient(c *client) imapclient.Client {
	return &oClient{
		client: c,
		u2s:    make(map[uint32]string),
		s2u:    make(map[string]uint32),
	}
}

var ErrNotSupported = errors.New("not supported")

func (c *oClient) Watch(context.Context) ([]uint32, error)      { return nil, ErrNotSupported }
func (c *oClient) Connect(context.Context) error                { return nil }
func (c *oClient) Close(ctx context.Context, commit bool) error { return nil }
func (c *oClient) List(ctx context.Context, mbox, pattern string, all bool) ([]uint32, error) {
	ids, err := c.client.List(ctx, mbox, pattern, all)
	c.mu.Lock()
	defer c.mu.Unlock()
	uids := make([]uint32, len(ids))
	for i, msg := range ids {
		s := msg.ID
		if u := c.s2u[s]; u != 0 {
			uids[i] = u
			continue
		}
		u := uint32(i + 1)
		c.u2s[u] = s
		c.s2u[s] = u
		uids[i] = u
	}
	return uids, err
}
func (c *oClient) ReadTo(ctx context.Context, w io.Writer, msgID uint32) (int64, error) {
	s, err := c.uidToStr(msgID)
	if err != nil {
		return 0, err
	}
	msg, err := c.client.Get(ctx, s)
	if err != nil {
		return 0, err
	}
	var n int64
	hdr := [][2]string{
		{"From", rcpt(msg.Sender)},
		{"Categories", strings.Join(msg.Categories, ", ")},
		{"Change-Key", msg.ChangeKey},
		{"Conversation-Id", msg.ConversationID},
		{"Id", msg.ID},
		{"Importance", string(msg.Importance)},
		{"Inference-Classification", string(msg.InferenceClassification)},
		//{"Delivery-Receipt-Requested", msg.IsDeliveryReceiptRequested},
		{"Subject", msg.Subject},
		{"Web-Link", msg.WebLink},
	}
	T := func(key string, tim *time.Time) {
		if tim != nil && !tim.IsZero() {
			hdr = append(hdr, [2]string{key, tim.Format(time.RFC3339)})
		}
	}
	T("Created", msg.Created)
	T("LastModified", msg.LastModified)
	T("Received", msg.Received)
	T("Sent", msg.Sent)

	A := func(key string, rcpts []Recipient) {
		for _, rcp := range rcpts {
			if s := rcpt(&rcp); s != "" {
				hdr = append(hdr, [2]string{key, s})
			}
		}
	}
	A("Bcc", msg.Bcc)
	A("Cc", msg.Cc)
	A("Reply-To", msg.ReplyTo)
	A("To", msg.To)

	for _, kv := range hdr {
		i, _ := fmt.Fprintf(w, `%s: %s\n`, kv[0], kv[1])
		n += int64(i)
	}
	i, err := io.WriteString(w, msg.Body.Content)
	return n + int64(i), err
}
func rcpt(r *Recipient) string {
	if r == nil {
		return ""
	}
	if r.EmailAddress.Name == "" {
		return "<" + r.EmailAddress.Address + ">"
	}
	return fmt.Sprintf(`%q <%s>`, r.EmailAddress.Name, r.EmailAddress.Address)
}
func (c *oClient) Peek(ctx context.Context, w io.Writer, msgID uint32, what string) (int64, error) {
	return c.ReadTo(ctx, w, msgID)
}
func (c *oClient) Delete(ctx context.Context, msgID uint32) error {
	s, err := c.uidToStr(msgID)
	if err != nil {
		return err
	}
	return c.client.Delete(ctx, s)
}
func (c *oClient) Move(ctx context.Context, msgID uint32, mbox string) error {
	s, err := c.uidToStr(msgID)
	if err != nil {
		return err
	}
	return c.client.Move(ctx, s, mbox)
}

func (c *oClient) uidToStr(msgID uint32) (string, error) {
	c.mu.Lock()
	s := c.u2s[msgID]
	c.mu.Unlock()
	if s == "" {
		return "", fmt.Errorf("unknown msgID %d", msgID)
	}
	return s, nil
}
func (c *oClient) SetLogMask(mask imapclient.LogMask) imapclient.LogMask { return false }
func (c *oClient) SetLogger(lgr *slog.Logger)                            { c.logger = lgr }
func (c *oClient) Select(ctx context.Context, mbox string) error {
	c.mu.Lock()
	c.selected = mbox
	c.mu.Unlock()
	return nil
}
func (c *oClient) FetchArgs(ctx context.Context, what string, msgIDs ...uint32) (map[uint32]map[string][]string, error) {
	return nil, ErrNotImplemented
}
func (c *oClient) Mark(ctx context.Context, msgID uint32, seen bool) error {
	s, err := c.uidToStr(msgID)
	if err != nil {
		return err
	}
	return c.client.Update(ctx, s, map[string]any{
		"IsRead": seen,
	})
}
func (c *oClient) Mailboxes(ctx context.Context, root string) ([]string, error) {
	folders, err := c.client.ListFolders(ctx, root)
	names := make([]string, len(folders))
	for i, f := range folders {
		names[i] = f.Name
	}
	return names, err
}

func (c *oClient) WriteTo(ctx context.Context, mbox string, p []byte, date time.Time) error {
	m, err := message.Read(bytes.NewReader(p))
	if err != nil {
		return err
	}
	from, _ := mail.ParseAddress(m.Header.Get("From"))
	to, _ := parseAddressList(m.Header.Get("To"))
	cc, _ := parseAddressList(m.Header.Get("Cc"))
	bcc, _ := parseAddressList(m.Header.Get("Bcc"))
	replyTo, _ := parseAddressList(m.Header.Get("Reply-To"))
	dt, _ := mail.ParseDate(m.Header.Get("Date"))
	msg := Message{
		Created: &dt,
		From:    &Recipient{EmailAddress: EmailAddress{Name: from.Name, Address: from.Address}},
		To:      to, Cc: cc, Bcc: bcc,
		Subject: m.Header.Get("Subject"),
		ID:      m.Header.Get("Message-ID"),
		ReplyTo: replyTo,
	}
	var buf bytes.Buffer
	m.Walk(func(path []int, ent *message.Entity, err error) error {
		if err != nil {
			if c.logger != nil {
				c.logger.Error("walk", "error", err)
			}
			return nil
		}
		buf.Reset()
		if _, err = io.Copy(&buf, ent.Body); err != nil && c.logger != nil {
			c.logger.Error("read body: %w", err)
		}
		if msg.Body.Content == "" {
			msg.Body.Content = buf.String()
			msg.Body.ContentType = ent.Header.Get("Content-Type")
		} else {
			_, params, _ := mime.ParseMediaType(ent.Header.Get("Content-Disposition"))
			_, isInline := params["inline"]
			msg.Attachments = append(msg.Attachments, Attachment{
				ContentType: ent.Header.Get("Content-Type"),
				Name:        nvl(params["filename"], params["name"]),
				Size:        int32(buf.Len()),
				IsInline:    isInline,
			})
		}
		return nil
	})
	return c.client.Send(ctx, msg)
}

func parseAddressList(s string) ([]Recipient, error) {
	aa, err := mail.ParseAddressList(s)
	rr := make([]Recipient, 0, len(aa))
	for _, a := range aa {
		rr = append(rr, Recipient{EmailAddress: EmailAddress{Name: a.Name, Address: a.Address}})
	}
	return rr, err
}

var ErrNotImplemented = errors.New("not implemented")

func nvl[T comparable](a T, b ...T) T {
	var z T
	if a != z {
		return a
	}
	for _, a := range b {
		if a != z {
			return a
		}
	}
	return a
}
