package o365

import (
	"context"
	"fmt"
	"io"
	"net/textproto"
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
	logger.Info("NewGraphMailClient", "gmc", gmc, "userID", userID)
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
func (g *graphMailClient) Close(ctx context.Context, commit bool) error { return ErrNotSupported }
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
	var firstErr error
	for _, mID := range msgIDs {
		var err error
		s := g.u2s[mID]
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
	return nil, ErrNotImplemented
}
func (g *graphMailClient) WriteTo(ctx context.Context, mbox string, msg []byte, date time.Time) error {
	return ErrNotImplemented
}
func (g *graphMailClient) Connect(ctx context.Context) error {
	return g.init(ctx)
}
func (g *graphMailClient) Move(ctx context.Context, msgID uint32, mbox string) error {
	return ErrNotImplemented
}
func (g *graphMailClient) Mark(ctx context.Context, msgID uint32, seen bool) error {
	return ErrNotImplemented
}
func (g *graphMailClient) List(ctx context.Context, mbox, pattern string, all bool) ([]uint32, error) {
	if err := g.init(ctx); err != nil {
		return nil, err
	}
	logger := logr.FromContextOrDiscard(ctx)
	for _, mf := range g.folders {
		logger.Info("folder", "name", mf.DisplayName, "id", mf.ID, "unread", mf.UnreadItemCount, "total", mf.TotalItemCount)
		if nm := mf.DisplayName; !(strings.EqualFold(nm, mbox) || (strings.EqualFold(mbox, "inbox") && nm == "Beérkezett üzenetek")) {
			continue
		}
		msgs, err := g.GraphMailClient.ListMessages(ctx, g.userID, mf.ID, odata.Query{})
		if err != nil {
			return nil, err
		}
		if len(msgs) == 0 {
			logger.Info("MailFolder.GetMessages returned no messages!")
		}
		logger.Info("messages", "msgs", len(msgs))
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
	return nil, fmt.Errorf("%q not found", mbox)
}
func (g *graphMailClient) ReadTo(ctx context.Context, w io.Writer, msgID uint32) (int64, error) {
	return 0, ErrNotImplemented
}
func (g *graphMailClient) SetLogger(logr.Logger) {
}
func (g *graphMailClient) SetLogMask(imapclient.LogMask) imapclient.LogMask { return false }
