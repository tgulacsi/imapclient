// Copyright 2024, 2026 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package imap_proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/UNO-SOFT/filecache"
	"github.com/UNO-SOFT/zlog/v2"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	pconfig "github.com/tgulacsi/imapclient/cmd/graph-proxy/lib"
	"github.com/tgulacsi/imapclient/graph"
)

func New(
	ctx context.Context, config pconfig.ProxyConfig,
	cacheDir string, cacheSizeMiB int,
) (*proxy, error) {
	done := ctx.Done()
	logger := zlog.SFromContext(ctx)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = zlog.NewSContext(ctx, logger)
	go func() { <-done; cancel() }()
	P := proxy{
		ctx:      ctx,
		clientID: config.ClientID,
		folders:  make(map[string]map[string]*Folder),
	}
	var err error
	if P.clients, err = pconfig.NewClientCache(config); err != nil {
		return nil, err
	}
	os.MkdirAll(cacheDir, 0750)
	if cacheSizeMiB < 1 {
		cacheSizeMiB = 512
	}
	if P.cache, err = filecache.Open(
		cacheDir,
		filecache.WithMaxSize(int64(cacheSizeMiB)<<20),
		filecache.WithLogger(slog.New(
			zlog.NewLevelHandler(slog.LevelError, logger.Handler()))),
	); err != nil {
		return nil, fmt.Errorf("open cache %q: %w", cacheDir, err)
	}

	if P.idm, err = newUIDMap(ctx, cacheDir+".db"); err != nil {
		return nil, fmt.Errorf("open uidMap %q: %w", cacheDir+".db", err)
	}

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
			//imap.CapMove: token,
			imap.CapStatusSize: token,
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
	if false && logger.Enabled(ctx, slog.LevelDebug) {
		// Raw ingress and egress data will be written to this writer, if any.
		// Note, this may include sensitive information such as credentials used
		// during authentication.
		opts.DebugWriter = slogDebugWriter{logger}
	}

	P.srv = imapserver.New(&opts)
	P.logger().Debug("imapserver.New", "opts", opts)
	return &P, nil
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
	P.logger().Info("listen", "addr", addr)
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
	graph.Folder
	Mailbox string
}

type proxy struct {
	ctx     context.Context
	srv     *imapserver.Server
	cache   *filecache.Cache
	clients *pconfig.ClientCache
	folders map[string]map[string]*Folder
	// client                           *graph.GraphMailClient
	//tenantID string
	idm      *uidMap
	clientID string

	mu sync.RWMutex
}

func (P *proxy) Close() error {
	um := P.idm
	P.idm = nil
	if um != nil {
		return um.Close()
	}
	return nil
}

func (P *proxy) logger() *slog.Logger { return zlog.SFromContext(P.ctx) }

func (P *proxy) connect(ctx context.Context, user, tenantID, clientSecret string) (graph.GraphMailClient, []graph.User, map[string]*Folder, error) {
	P.mu.Lock()
	defer P.mu.Unlock()
	key := P.clients.Key(tenantID, clientSecret)
	if P.folders == nil {
		P.folders = make(map[string]map[string]*Folder)
	}
	cl, users, err := P.clients.Get(ctx, tenantID, clientSecret, user)
	if err != nil {
		return cl, nil, nil, err
	}
	if P.folders[key] == nil {
		P.folders[key] = make(map[string]*Folder)
	}
	return cl, users, P.folders[key], err
}

type slogDebugWriter struct{ *slog.Logger }

func (s slogDebugWriter) Write(p []byte) (int, error) {
	s.Logger.Debug(string(p))
	return len(p), nil
}
