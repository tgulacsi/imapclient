// Copyright 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/UNO-SOFT/zlog/v2"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/tgulacsi/imapclient/graph"
)

func NewProxy(ctx context.Context, clientID string) *proxy {
	P := proxy{ctx: ctx, clientID: clientID}
	logger := P.logger()

	var token struct{}
	opts := imapserver.Options{
		// NewSession is called when a client connects.
		NewSession: P.newSession,
		// Supported capabilities. If nil, only IMAP4rev1 is advertised. This set
		// must contain at least IMAP4rev1 or IMAP4rev2.
		//
		// the following capabilities are part of IMAP4rev2 and need to be
		// explicitly enabled by IMAP4rev1-only servers:
		//
		//   - NAMESPACE
		//   - UIDPLUS
		//   - ESEARCH
		//   - LIST-EXTENDED
		//   - LIST-STATUS
		//   - MOVE
		//   - STATUS=SIZE
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: token, //imap.CapIMAP4rev2: token,
			imap.CapNamespace: token, imap.CapUIDPlus: token,
			imap.CapESearch: token, //imap.CapListExtended: token,
			//imap.CapListStatus: token,
			//imap.CapMove: token, imap.CapStatusSize: token,
		},
		// Logger is a logger to print error messages. If nil, log.Default is used.
		Logger: slog.NewLogLogger(logger.With("lib", "imapserver").Handler(), slog.LevelError),
		// TLSConfig is a TLS configuration for STARTTLS. If nil, STARTTLS is
		// disabled.
		TLSConfig: nil,
		// InsecureAuth allows clients to authenticate without TLS. In this mode,
		// the server is susceptible to man-in-the-middle attacks.
		InsecureAuth: true,
	}
	if logger.Enabled(ctx, slog.LevelDebug) {
		// Raw ingress and egress data will be written to this writer, if any.
		// Note, this may include sensitive information such as credentials used
		// during authentication.
		opts.DebugWriter = slogDebugWriter{logger}
	}

	P.srv = imapserver.New(&opts)
	return &P
}

func (P *proxy) ListenAndServe(addr string) error {
	// if P.client == nil && P.clientSecret != "" {
	// 	if err := P.connect(
	// 		P.ctx, P.tenantID, P.clientID, P.clientSecret,
	// 	); err != nil {
	// 		return err
	// 	}
	// }

	if addr == "" {
		addr = ":143"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-P.ctx.Done()
		ln.Close()
	}()
	return P.srv.Serve(ln)
}

const (
	delim  = '/'
	delimS = "/"
)

type Folder struct {
	Mailbox string
	graph.Folder
}

type proxy struct {
	ctx context.Context
	srv *imapserver.Server
	// client                           *graph.GraphMailClient
	//tenantID string
	clientID string

	mu      sync.Mutex
	clients map[string]clientUsers
}

func (P *proxy) logger() *slog.Logger {
	if lgr := zlog.SFromContext(P.ctx); lgr != nil {
		return lgr
	}
	return slog.Default()
}

func (P *proxy) connect(ctx context.Context, tenantID, clientSecret string) (graph.GraphMailClient, []graph.User, error) {
	logger := P.logger().With("tenantID", tenantID, "clientID", P.clientID, "clientSecretLen", len(clientSecret))
	start := time.Now()
	P.mu.Lock()
	defer P.mu.Unlock()
	key := tenantID + "\t" + clientSecret
	if clu, ok := P.clients[key]; ok {
		return clu.Client, clu.Users, nil
	}
	cl, err := graph.NewGraphMailClient(ctx, tenantID, P.clientID, clientSecret)
	if err != nil {
		logger.Error("NewGraphMailClient", "dur", time.Since(start).String(), "error", err)
		return graph.GraphMailClient{}, nil, err
	}
	logger.Debug("NewGraphMailClient", "dur", time.Since(start).String())
	start = time.Now()
	users, err := cl.Users(ctx)
	if err != nil {
		logger.Error("Users", "dur", time.Since(start).String(), "error", err)
	} else {
		logger.Debug("Users", "dur", time.Since(start).String())
	}
	if P.clients == nil {
		P.clients = make(map[string]clientUsers)
	}
	P.clients[key] = clientUsers{Client: cl, Users: users}
	return cl, users, err
}

type clientUsers struct {
	Client graph.GraphMailClient
	Users  []graph.User
}

type slogDebugWriter struct{ *slog.Logger }

func (s slogDebugWriter) Write(p []byte) (int, error) {
	s.Logger.Debug(string(p))
	return len(p), nil
}
