package o365

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"

	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-logr/logr"
	a "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/tgulacsi/imapclient/v2"
)

type graphMailClient struct {
	*msgraphsdkgo.GraphServiceClient
	folders []models.MailFolderable
	u2s     map[uint32]string
	s2u     map[string]uint32
	seq     uint32
}

func NewGraphMailClient(conf *oauth2.Config, tenantID string) (*graphMailClient, error) {
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
	return &graphMailClient{GraphServiceClient: msgraphsdkgo.NewGraphServiceClient(adapter)}, nil
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
	resp, err := g.GraphServiceClient.Me().MailFolders().Get(ctx, nil)
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
	return nil, ErrNotImplemented
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
	for _, mf := range g.folders {
		if *mf.GetDisplayName() == mbox {
			msgs := mf.GetMessages()
			ids := make([]uint32, len(msgs))
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
	}
	return nil, fmt.Errorf("%q not found", mbox)
}
func (g *graphMailClient) ReadTo(ctx context.Context, w io.Writer, msgID uint32) (int64, error) {
	return 0, ErrNotImplemented
}
func (g *graphMailClient) SetLogger(logr.Logger) {
}
func (g *graphMailClient) SetLogMask(imapclient.LogMask) imapclient.LogMask { return false }
