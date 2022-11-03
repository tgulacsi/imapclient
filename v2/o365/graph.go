// Copyright 2022 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package o365

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"

	"github.com/go-logr/logr"

	"github.com/tgulacsi/imapclient/graph"
	"github.com/tgulacsi/imapclient/v2"

	"github.com/manicminer/hamilton/odata"
)

type graphMailClient struct {
	graph.GraphMailClient

	userID  string
	folders []graph.Folder
	u2s     map[uint32]string
	s2u     map[string]uint32
	seq     uint32
}

func NewGraphMailClient(ctx context.Context, conf *oauth2.Config, tenantID, userID string) (*graphMailClient, error) {
	gmc, err := graph.NewGraphMailClient(ctx, tenantID, conf.ClientID, conf.ClientSecret)
	if err != nil {
		return nil, err
	}

	logger := logr.FromContextOrDiscard(ctx)
	if strings.IndexByte(userID, '@') >= 0 {
		users, err := gmc.Users(ctx)
		if err != nil {
			return nil, err
		}
		var found bool
		for _, u := range users {
			logger.V(1).Info("users", "name", u.DisplayName, "mail", u.Mail)
			if u.Mail != nil && string(*u.Mail) == userID {
				userID, found = *u.ID, true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no user found with %q mail address", userID)
		}
	}
	logger.V(1).Info("NewGraphMailClient", "userID", userID)
	return &graphMailClient{GraphMailClient: gmc, userID: userID}, nil
}

var _ imapclient.Client = (*graphMailClient)(nil)

func (g *graphMailClient) init(ctx context.Context) error {
	if g.folders != nil {
		return nil
	}
	if g.u2s == nil {
		g.u2s = make(map[uint32]string)
		g.s2u = make(map[string]uint32)
	}
	// https://www.c-sharpcorner.com/article/read-email-from-mailbox-folders-using-microsoft-graph-api/
	var err error
	if g.folders, err = g.GraphMailClient.ListMailFolders(ctx, g.userID, odata.Query{}); err != nil {
		return fmt.Errorf("MailFolders.Get: %w", err)
	}
	return nil
}
func (g *graphMailClient) SetLogger(logr.Logger)                            {}
func (g *graphMailClient) SetLogMask(imapclient.LogMask) imapclient.LogMask { return false }
func (g *graphMailClient) Close(ctx context.Context, commit bool) error     { return ErrNotSupported }
func (g *graphMailClient) Mailboxes(ctx context.Context, root string) ([]string, error) {
	if err := g.init(ctx); err != nil {
		return nil, err
	}
	folders := make([]string, 0, len(g.folders))
	for _, mf := range g.folders {
		folders = append(folders, mf.DisplayName)
	}
	return folders, nil
}
func (g *graphMailClient) FetchArgs(ctx context.Context, what string, msgIDs ...uint32) (map[uint32]map[string][]string, error) {
	logger := logr.FromContextOrDiscard(ctx)
	m := make(map[uint32]map[string][]string, len(msgIDs))
	var wantMIME bool
	for _, f := range strings.Fields(what) {
		wantMIME = wantMIME || f == "RFC822.HEADER" || f == "RFC822.SIZE" || f == "RFC822.BODY"
	}
	var firstErr error
	for _, mID := range msgIDs {
		s := g.u2s[mID]
		if wantMIME {
			var buf strings.Builder
			size, err := g.GraphMailClient.GetMIMEMessage(ctx, &buf, g.userID, s)
			if err != nil {
				return m, fmt.Errorf("GetMIMEMessage(%q): %w", s, err)
			}
			s := buf.String()
			i := strings.Index(s, "\r\n\r\n")
			m[mID] = map[string][]string{
				"RFC822.HEADER": []string{s[:i+4]},
				"RFC822.BODY":   []string{s[i+4:]},
				"RFC822.SIZE":   []string{strconv.FormatInt(size, 10)},
			}
		} else {
			hdrs, err := g.GraphMailClient.GetMessageHeaders(ctx, g.userID, s, odata.Query{})
			if err != nil {
				logger.Error(err, "GetMessageHeaders", "msgID", s)
				if firstErr == nil {
					firstErr = err
				}
				continue
			}

			m[mID] = hdrs
			if strings.Contains(what, "RFC822.SIZE") {
				m[mID]["RFC822.SIZE"] = []string{"0"}
			}
			if strings.Contains(what, "RFC822.HEADER") {
				var buf strings.Builder
				for k, vv := range hdrs {
					k = textproto.CanonicalMIMEHeaderKey(k)
					for _, v := range vv {
						buf.WriteString(k)
						buf.WriteString(":\t")
						buf.WriteString(v)
						buf.WriteString("\r\n")
					}
				}
				buf.WriteString("\r\n")
				m[mID]["RFC822.HEADER"] = []string{buf.String()}
			}
		}
	}
	if len(m) == 0 {
		return nil, firstErr
	}
	return m, nil
}
func (g *graphMailClient) Peek(ctx context.Context, w io.Writer, msgID uint32, what string) (int64, error) {
	return 0, ErrNotImplemented
}
func (g *graphMailClient) Delete(ctx context.Context, msgID uint32) error {
	return ErrNotImplemented
}
func (g *graphMailClient) Select(ctx context.Context, mbox string) error {
	return nil
}
func (g *graphMailClient) Watch(ctx context.Context) ([]uint32, error) {
	return nil, ErrNotSupported
}
func (g *graphMailClient) WriteTo(ctx context.Context, mbox string, msg []byte, date time.Time) error {
	return ErrNotImplemented
}
func (g *graphMailClient) Connect(ctx context.Context) error {
	return g.init(ctx)
}
func (g *graphMailClient) Move(ctx context.Context, msgID uint32, mbox string) error {
	mID, err := g.m2s(mbox)
	if err != nil {
		return nil
	}
	_, err = g.GraphMailClient.MoveMessage(ctx, g.userID, g.u2s[msgID], mID)
	return err
}
func (g *graphMailClient) Mark(ctx context.Context, msgID uint32, seen bool) error {
	var buf strings.Builder
	buf.WriteString(`{"isRead":`)
	if seen {
		buf.WriteString(`true}`)
	} else {
		buf.WriteString(`false}`)
	}
	_, err := g.GraphMailClient.UpdateMessage(ctx, g.userID, g.u2s[msgID], json.RawMessage(buf.String()))
	return err
}
func (g *graphMailClient) m2s(mbox string) (string, error) {
	for _, mf := range g.folders {
		if nm := mf.DisplayName; strings.EqualFold(nm, mbox) || (strings.EqualFold(mbox, "inbox") && nm == "Beérkezett üzenetek") {
			return mf.ID, nil
		}
	}
	return "", fmt.Errorf("mbox %q not found (have: %+v)", mbox, g.folders)
}
func (g *graphMailClient) List(ctx context.Context, mbox, pattern string, all bool) ([]uint32, error) {
	if err := g.init(ctx); err != nil {
		return nil, err
	}
	logger := logr.FromContextOrDiscard(ctx)
	mID, err := g.m2s(mbox)
	if err != nil {
		return nil, err
	}
	logger.V(1).Info("folder", "id", mID, "name", mbox)
	query := odata.Query{Filter: "isRead eq false"}
	if pattern != "" {
		query.Filter += " and contains(subject, " + strings.ReplaceAll(strconv.Quote(pattern), `"`, "'") + ")"
	}
	msgs, err := g.GraphMailClient.ListMessages(ctx, g.userID, mID, query)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, nil
	}
	logger.V(1).Info("messages", "msgs", len(msgs))
	ids := make([]uint32, 0, len(msgs))
	for _, m := range msgs {
		s := m.ID
		u, ok := g.s2u[s]
		if !ok {
			u = atomic.AddUint32(&g.seq, 1)
			g.u2s[u] = s
		}
		ids = append(ids, u)
	}
	return ids, nil
}
func (g *graphMailClient) ReadTo(ctx context.Context, w io.Writer, msgID uint32) (int64, error) {
	return g.GraphMailClient.GetMIMEMessage(ctx, w, g.userID, g.u2s[msgID])
}
