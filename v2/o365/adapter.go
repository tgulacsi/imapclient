// Copyright 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package o365

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
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
func (c *oClient) SetLogger(lgr log.Logger)                              {}
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
	return c.client.Update(ctx, s, map[string]interface{}{
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

func (c *oClient) WriteTo(ctx context.Context, mbox string, msg []byte, date time.Time) error {
	return ErrNotImplemented
}

var ErrNotImplemented = errors.New("not implemented")
