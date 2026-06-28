// Copyright 2026 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package smtp_proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	// "sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	pconfig "github.com/tgulacsi/imapclient/cmd/graph-proxy/lib"
	"github.com/tgulacsi/imapclient/graph"

	"github.com/UNO-SOFT/zlog/v2"
)

func New(ctx context.Context, config pconfig.ProxyConfig) (*proxy, error) {
	done := ctx.Done()
	logger := zlog.SFromContext(ctx)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = zlog.NewSContext(ctx, logger)
	P := proxy{
		ctx:      ctx,
		clientID: config.ClientID,
	}
	go func() { <-done; cancel(); P.srv.Close() }()
	var err error
	if P.clients, err = pconfig.NewClientCache(config); err != nil {
		return nil, err
	}
	P.srv = smtp.NewServer(&P)
	P.srv.AllowInsecureAuth = true
	P.srv.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	P.srv.TLSConfig = nil
	if logger.Enabled(ctx, slog.LevelDebug) {
		// Raw ingress and egress data will be written to this writer, if any.
		// Note, this may include sensitive information such as credentials used
		// during authentication.
		P.srv.Debug = pconfig.NewSLogDebugWriter(logger)
	}
	return &P, nil
}

type proxy struct {
	ctx      context.Context
	srv      *smtp.Server
	clients  *pconfig.ClientCache
	clientID string

	// mu sync.RWMutex
}

func (P *proxy) Close() error {
	srv := P.srv
	P.srv = nil
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		srv.Shutdown(ctx)
		cancel()
		return srv.Close()
	}
	return nil
}
func (P *proxy) ListenAndServe(addr string) error {
	P.srv.Addr = addr
	zlog.SFromContext(P.ctx).Info("listen", "addr", addr)
	return P.srv.ListenAndServe()
}

var _ smtp.Backend = (*proxy)(nil)

func (P *proxy) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	return &session{p: P, ss: conn.Session()}, nil
}

type session struct {
	p      *proxy
	ss     smtp.Session
	client graph.GraphMailClient
	from   string
	to     []string
}

var _ smtp.AuthSession = (*session)(nil)

func (S *session) Reset() {
	S.from, S.to = "", nil
	if S.ss != nil {
		S.ss.Reset()
	}
}
func (S *session) Logout() error {
	S.client = graph.GraphMailClient{}
	ss := S.ss
	S.ss = nil
	if ss != nil {
		return ss.Logout()
	}
	return nil
}
func (S *session) AuthMechanisms() []string {
	return []string{"PLAIN"}
}
func (S *session) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		logger := zlog.SFromContext(S.p.ctx)
		logger.Warn("auth", "identity", identity, "username", username, "password", password)
		var tenantID string
		for _, sep := range []string{"\x0a", "%0A", ":"} {
			if s, p, ok := strings.Cut(username, sep); ok {
				username, tenantID = s, p
				break
			}
		}
		if tenantID == "" {
			return fmt.Errorf("%w: username=%q does not contain tenantID:clientSecret", smtp.ErrAuthFailed, username)
		}
		var err error
		if S.client, _, err = S.p.clients.Get(
			S.p.ctx, tenantID, password, username,
		); err != nil {
			return err
		}
		return nil
	}), nil
}

// Set return path for currently processed message.
func (S *session) Mail(from string, opts *smtp.MailOptions) error {
	logger := zlog.SFromContext(S.p.ctx)
	logger.Info("Mail", "from", from, "opts", opts)
	if S.client == (graph.GraphMailClient{}) && opts.Auth == nil {
		logger.Error("Mail without Auth", "from", from, "opts", opts)
		return fmt.Errorf("%w: empty Auth", smtp.ErrAuthRequired)
	}
	S.from = from
	return nil
}

// Add recipient for currently processed message.
func (S *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	logger := zlog.SFromContext(S.p.ctx)
	logger.Info("Rcpt", "to", to)
	S.to = append(S.to, to)
	return nil
}

// Set currently processed message contents and send it.
//
// r must be consumed before Data returns.
func (S *session) Data(r io.Reader) error {
	logger := zlog.SFromContext(S.p.ctx)
	logger.Info("Data")
	return S.client.SendMail(S.p.ctx, "", r, true)
}
