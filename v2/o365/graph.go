package o365

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"

	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-logr/logr"
	a "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/me"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	useritem "github.com/microsoftgraph/msgraph-sdk-go/users/item"
	"github.com/tgulacsi/imapclient/v2"
)

type graphMailClient struct {
	user *useritem.UserItemRequestBuilder
	me   *me.MeRequestBuilder

	folders []models.MailFolderable
	u2s     map[uint32]string
	s2u     map[string]uint32
	seq     uint32
}

func NewGraphMailClient(conf *oauth2.Config, tenantID, userID string) (*graphMailClient, error) {
	cred, err := azidentity.NewClientSecretCredential(
		tenantID,
		conf.ClientID,
		conf.ClientSecret,
		nil,
	)
	if err != nil {
		return nil, err
	}
	auth, err := a.NewAzureIdentityAuthenticationProviderWithScopes(cred, conf.Scopes)
	if err != nil {
		return nil, err
	}

	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(auth)
	if err != nil {
		return nil, err
	}
	client := msgraphsdkgo.NewGraphServiceClient(adapter)
	g := graphMailClient{}
	if userID != "" {
		g.user = client.UsersById(userID)
	} else {
		g.me = client.Me()
	}
	return &g, nil
}

var _ imapclient.Client = (*graphMailClient)(nil)

func printOdataError(err error) error {
	if err == nil {
		return nil
	}
	var oerr *odataerrors.ODataError
	if errors.As(err, &oerr) {
		if terr := oerr.GetError(); terr != nil {
			return fmt.Errorf("%s: (code=%s msg=%s): %w", oerr.Error(), *terr.GetCode(), *terr.GetMessage(), oerr)
		}
		return fmt.Errorf("%s: %w", oerr.Error(), oerr)
	}
	return fmt.Errorf("%T > error: %#v: %w", err, err, err)
}
func (g *graphMailClient) init(ctx context.Context) error {
	if g.folders != nil {
		return nil
	}
	if g.u2s == nil {
		g.u2s = make(map[uint32]string)
		g.s2u = make(map[string]uint32)
	}
	var resp models.MailFolderCollectionResponseable
	var err error
	if g.user == nil {
		resp, err = g.me.MailFolders().Get(ctx, nil)
	} else {
		resp, err = g.user.MailFolders().Get(ctx, nil)
	}
	if err != nil {
		return fmt.Errorf("MailFolders.Get: %w", printOdataError(err))
	}
	g.folders = resp.GetValue()
	return nil
}
func (g *graphMailClient) Close(ctx context.Context, commit bool) error { return ErrNotSupported }
func (g *graphMailClient) Mailboxes(ctx context.Context, root string) ([]string, error) {
	if err := g.init(ctx); err != nil {
		return nil, err
	}
	folders := make([]string, 0, len(g.folders))
	for _, mf := range g.folders {
		sp := mf.GetDisplayName()
		if sp == nil {
			continue
		}
		folders = append(folders, *sp)
	}
	return folders, nil
}
func (g *graphMailClient) FetchArgs(ctx context.Context, what string, msgIDs ...uint32) (map[uint32]map[string][]string, error) {
	m := make(map[uint32]map[string][]string, len(msgIDs))
	for _, mID := range msgIDs {
		var resp models.Messageable
		var err error
		s := g.u2s[mID]
		if g.me != nil {
			resp, err = g.me.MessagesById(s).Get(ctx, nil)
		} else {
			resp, err = g.user.MessagesById(s).Get(ctx, nil)
		}
		if err != nil {
			return m, fmt.Errorf("get %s: %w", s, err)
		}
		hdrs := resp.GetInternetMessageHeaders()
		hdr := make(map[string][]string, 8+len(hdrs))
		for _, h := range hdrs {
			nm := *h.GetName()
			hdr[nm] = append(hdr[nm], *h.GetValue())
		}

		hdr["Cc"] = recipients(resp.GetCcRecipients())
		hdr["Bcc"] = recipients(resp.GetBccRecipients())
		hdr["Reply-To"] = recipients(resp.GetReplyTo())
		hdr["To"] = recipients(resp.GetToRecipients())

		hdr["Conversation-Id"] = []string{*resp.GetConversationId()}
		hdr["From"] = recipients([]models.Recipientable{resp.GetFrom(), resp.GetSender()})
		hdr["Message-Id"] = []string{*resp.GetInternetMessageId()}
		hdr["Subject"] = []string{*resp.GetSubject()}

		m[mID] = hdr
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
		logger.Info("folder", "name", mf.GetDisplayName(), "id", *mf.GetId(), "unread", *mf.GetUnreadItemCount(), "total", *mf.GetTotalItemCount())
		if nm := *mf.GetDisplayName(); !(strings.EqualFold(nm, mbox) || (strings.EqualFold(mbox, "inbox") && nm == "Beérkezett üzenetek")) {
			continue
		}
		msgs := mf.GetMessages()
		if len(msgs) == 0 {
			logger.Info("MailFolder.GetMessages returned no messages!")
			var resp models.MessageCollectionResponseable
			var err error
			if g.me != nil {
				resp, err = g.me.Messages().Get(ctx, nil)
			} else {
				resp, err = g.user.Messages().Get(ctx, nil)
			}
			if err != nil {
				return nil, err
			}
			msgs = resp.GetValue()
		}
		logger.Info("messages", "msgs", len(msgs))
		ids := make([]uint32, 0, len(msgs))
		for _, m := range msgs {
			s := *m.GetId()
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

func recipients(rcpts []models.Recipientable) []string {
	if len(rcpts) == 0 {
		return nil
	}
	ss := make([]string, len(rcpts))
	for i, r := range rcpts {
		em := r.GetEmailAddress()
		if nm := *em.GetName(); nm == "" {
			ss[i] = *em.GetAddress()
		} else {
			ss[i] = nm + " <" + *em.GetAddress() + ">"
		}
	}
	return ss
}
