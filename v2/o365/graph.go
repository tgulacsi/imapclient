// Copyright 2022, 2023 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package o365

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/textproto"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tgulacsi/imapclient/graph"
	"github.com/tgulacsi/imapclient/v2"

	"github.com/hashicorp/go-azure-sdk/sdk/odata"
)

type graphMailClient struct {
	graph.GraphMailClient `json:"-"`

	userID  string
	folders map[string]graph.Folder
	u2s     map[uint32]string
	s2u     map[string]uint32

	logger *slog.Logger

	seq uint32
}

func NewGraphMailClient(ctx context.Context, clientID, clientSecret, tenantID, userID string) (*graphMailClient, error) {
	gmc, users, err := graph.NewGraphMailClient(ctx,
		tenantID, clientID, clientSecret, "")
	if err != nil {
		return nil, err
	}

	logger := slog.Default()
	if strings.IndexByte(userID, '@') >= 0 {
		var found bool
		for _, u := range users {
			logger.Debug("users", "name", u.DisplayName, "mail", u.Mail)
			if u.Mail != nil && string(*u.Mail) == userID {
				userID, found = *u.ID(), true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no user found with %q mail address", userID)
		}
	}
	logger.Debug("NewGraphMailClient", "userID", userID)
	return &graphMailClient{
		GraphMailClient: gmc, userID: userID,
		logger: logger,
	}, nil
}

var _ imapclient.Client = (*graphMailClient)(nil)

func (g *graphMailClient) init(ctx context.Context, mbox string) error {
	if g.u2s == nil {
		g.u2s = make(map[uint32]string)
		g.s2u = make(map[string]uint32)
	}
	if g.folders == nil {
		g.folders = make(map[string]graph.Folder)
		if folders, err := g.GraphMailClient.ListMailFolders(ctx, g.userID, odata.Query{}); err != nil && len(folders) == 0 {
			return err
		} else {
			for _, f := range folders {
				g.folders[strings.ToLower(f.DisplayName)] = f
				g.folders["{"+f.ID+"}"] = f
			}
		}
	}
	if mbox == "" {
		return nil
	}
	if i := strings.IndexByte(mbox, '/'); i >= 0 {
		mbox = mbox[:i]
	}
	mbox = strings.ToLower(mbox)

	fID, err := g.m2s(mbox)
	if err != nil {
		return err
	}
	folders, err := g.GraphMailClient.ListChildFolders(ctx, g.userID, fID, true, odata.Query{})
	if err != nil {
		g.logger.Error("ListChildFolders", "userID", g.userID, "folder", fID, "folders", folders, "error", err)
		if len(folders) == 0 {
			return err
		}
	}
	for _, f := range folders {
		g.folders["{"+f.ID+"}"] = f
	}
	var path []string
	for _, f := range folders {
		var prefix string
		path = path[:0]
		if f.ParentFolderID != "" {
			for p := g.folders["{"+f.ParentFolderID+"}"]; p.ParentFolderID != ""; p = g.folders["{"+p.ParentFolderID+"}"] {
				path = append(path, strings.ToLower(p.DisplayName))
			}
			if len(path) != 0 {
				// reverse
				for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
					path[i], path[j] = path[j], path[i]
				}
				prefix = strings.Join(path, "/") + "/"
			}
		}
		g.folders[prefix+strings.ToLower(f.DisplayName)] = f
	}
	if err != nil {
		g.logger.Error("MailFolders.Get", "userID", g.userID, "folder", fID, "error", err)
		return fmt.Errorf("MailFolders.Get(%q): %w", g.userID, err)
	}

	// https://www.c-sharpcorner.com/article/read-email-from-mailbox-folders-using-microsoft-graph-api/
	return nil
}
func (g *graphMailClient) SetLogger(lgr *slog.Logger)                       { g.logger = lgr }
func (g *graphMailClient) SetLogMask(imapclient.LogMask) imapclient.LogMask { return false }
func (g *graphMailClient) Close(ctx context.Context, commit bool) error     { return ErrNotSupported }
func (g *graphMailClient) Mailboxes(ctx context.Context, root string) ([]string, error) {
	if err := g.init(ctx, root); err != nil {
		return nil, err
	}
	folders := make([]string, 0, len(g.folders))
	for k := range g.folders {
		if !(len(k) > 2 && k[0] == '{' && k[len(k)-1] == '}') {
			folders = append(folders, k)
		}
	}
	return folders, nil
}
func (g *graphMailClient) FetchArgs(ctx context.Context, what string, msgIDs ...uint32) (map[uint32]map[string][]string, error) {
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
				g.logger.Error("GetMessageHeaders", "msgID", s, "error", err)
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
	if err := g.init(ctx, ""); err != nil {
		return err
	}
	mID, err := g.m2s("deleted items")
	if err != nil {
		return err
	}
	_, err = g.GraphMailClient.MoveMessage(ctx, g.userID, "", g.u2s[msgID], mID)
	return err
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
	return g.init(ctx, "")
}
func (g *graphMailClient) Move(ctx context.Context, msgID uint32, mbox string) error {
	if err := g.init(ctx, mbox); err != nil {
		return err
	}
	mID, err := g.m2s(mbox)
	if err != nil {
		return nil
	}
	_, err = g.GraphMailClient.MoveMessage(ctx, g.userID, "", g.u2s[msgID], mID)
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
	mbox = strings.ToLower(mbox)
	if mf, ok := g.folders[mbox]; ok {
		return mf.ID, nil
	}
	if mf, ok := g.folders["{"+mbox+"}"]; ok {
		return mf.ID, nil
	}
	for k, mf := range g.folders {
		if len(k) > 2 && k[0] == '{' && k[len(k)-1] == '}' {
			continue
		}
		if nm := mf.DisplayName; strings.EqualFold(nm, mbox) || (mbox == "inbox" && nm == "beérkezett üzenetek") {
			return mf.ID, nil
		}
	}
	folders := make([]string, 0, len(g.folders))
	for k := range g.folders {
		if !(len(k) > 2 && k[0] == '{' && k[len(k)-1] == '}') {
			folders = append(folders, k)
		}
	}
	return "", fmt.Errorf("mbox %q not found (have: %+v)", mbox, folders)
}
func (g *graphMailClient) List(ctx context.Context, mbox, pattern string, all bool) ([]uint32, error) {
	if err := g.init(ctx, mbox); err != nil {
		g.logger.Error("init", "mbox", mbox, "error", err)
		return nil, err
	}
	mID, err := g.m2s(mbox)
	if err != nil {
		g.logger.Error("m2s", "mbox", mbox, "error", err)
		return nil, err
	}
	query := odata.Query{Filter: "isRead eq false"}
	if pattern != "" {
		query.Filter += " and contains(subject, " + strings.ReplaceAll(strconv.Quote(pattern), `"`, "'") + ")"
	}
	msgs, err := g.GraphMailClient.ListMessages(ctx, g.userID, mID, query)
	if err != nil {
		g.logger.Error("folder", "id", mID, "name", mbox, "query", query, "error", err)
		return nil, err
	}
	g.logger.Debug("folder", "id", mID, "name", mbox, "query", query, "msgs", len(msgs))
	if len(msgs) == 0 {
		return nil, nil
	}
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
