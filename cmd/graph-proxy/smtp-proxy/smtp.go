// Copyright 2026 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package smtp_proxy

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

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
	go func() { <-done; cancel() }()
	P := proxy{
		ctx:      ctx,
		clientID: config.ClientID,
	}
	var err error
	if P.clients, err = pconfig.NewClientCache(config); err != nil {
		return nil, err
	}
	P.srv = smtp.NewServer(&P)
	return &P, nil
}

type proxy struct {
	ctx      context.Context
	srv      *smtp.Server
	clients  *pconfig.ClientCache
	clientID string

	mu sync.RWMutex
}

func (P *proxy) Close() error {
	srv := P.srv
	P.srv = nil
	if srv != nil {
		return srv.Close()
	}
	return nil
}
func (P *proxy) ListenAndServe(addr string) error {
	P.srv.Addr = addr
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

func (S *session) Reset() { S.from, S.to = "", nil; S.ss.Reset() }
func (S *session) Logout() error {
	S.client = graph.GraphMailClient{}
	return S.ss.Logout()
}

// Set return path for currently processed message.
func (S *session) Mail(from string, opts *smtp.MailOptions) error {
	if opts.Auth == nil {
		return fmt.Errorf("%w: empty Auth", smtp.ErrAuthRequired)
	}
	tenantID, clientSecret, ok := strings.Cut(*opts.Auth, ":")
	if !ok {
		return fmt.Errorf("%w: auth=%q does not contain tenantID:clientSecret", smtp.ErrAuthFailed, *opts.Auth)
	}
	var err error
	if S.client, _, err = S.p.clients.Get(
		S.p.ctx, tenantID, clientSecret, from,
	); err != nil {
		return err
	}
	S.from = from
	return nil
}

// Add recipient for currently processed message.
func (S *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	S.to = append(S.to, to)
	return nil
}

// Set currently processed message contents and send it.
//
// r must be consumed before Data returns.
func (S *session) Data(r io.Reader) error {
	// S.client.CreateMessage(S.p.ctx, "")
	return fmt.Errorf("not implemented")
}
