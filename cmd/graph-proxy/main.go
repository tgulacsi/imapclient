// Copyright 2024, 2026 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/UNO-SOFT/zlog/v2"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"

	"github.com/tgulacsi/imapclient/cmd/graph-proxy/imap-proxy"
	"github.com/tgulacsi/imapclient/cmd/graph-proxy/lib"
	"github.com/tgulacsi/imapclient/cmd/graph-proxy/smtp-proxy"
)

var concurrency int = 8

func main() {
	if err := Main(); err != nil {
		slog.Error("Main", "error", err)
		os.Exit(1)
	}
}

func Main() error {
	var verbose zlog.VerboseVar
	logger := zlog.NewLogger(zlog.MaybeConsoleHandler(&verbose, os.Stderr)).SLog()
	cd, err := os.UserCacheDir()
	if err != nil {
		logger.Error("UserCacheDir", "error", err)
	} else {
		cd = filepath.Join(cd, "graph-proxy")
	}
	var proxyConf config.ProxyConfig
	FS := ff.NewFlagSet("graph-proxy")
	FS.IntVar(&concurrency, 0, "concurrency", concurrency, "concurrency")
	FS.Float64Var(&proxyConf.RateLimit, 0, "rate-limit", 10, "mas number of http calls per second")
	flagCacheDir := FS.StringLong("cache-dir", cd, "cache directory")
	flagCacheSizeMiB := FS.IntLong("cache-max-mb", 512, "cache max size in MiB")
	FS.StringVar(&proxyConf.ClientID, 0, "client-id", "34f2c0c1-b509-43c5-aae8-56c10fa19ed7", "ClientID")
	FS.StringVar(&proxyConf.ClientCert, 0, "client-cert", "", "client certificate .pem")
	// flagRedirectURI := flag.String("redirect-uri", "http://localhost:19414/auth-response", "The redirect URI you send in the request to the login server")
	// flagClientSecret := flag.String("client-secret", "", "ClientSecret")
	// flagTenantID := flag.String("tenant-id", "", "TenantID")
	// flagUserID := flag.String("user-id", "", "UserID")
	FS.StringVar(&proxyConf.RedirectURI, 0, "redirect-uri", "http://localhost", "redirectURI (if client secret is empty)")
	FS.Value(0, "verbose", &verbose, "verbosity")
	flagPprofURL := FS.StringLong("pprof", "", "pprof URL to listen on")
	flagSMTPAddr := FS.StringLong("smtp", ":1025", "SMTP address to listen on")
	app := ff.Command{Name: "graph-proxy", Flags: FS,
		Usage: "prefix env vars with GRAPH_PROXY_",
		Exec: func(ctx context.Context, args []string) error {
			if *flagPprofURL != "" {
				go http.ListenAndServe(*flagPprofURL, nil)
			}

			addr := ":1143"
			if len(args) != 0 {
				addr = args[0]
			}
			logger.Info("Listen", "IMAP", addr, "SMTP", *flagSMTPAddr)
			slog.SetDefault(logger)
			ctx = zlog.NewSContext(ctx, logger)

			grp, ctx := errgroup.WithContext(ctx)
			if *flagSMTPAddr != "" {
				p, err := smtp_proxy.New(ctx, proxyConf)
				if err != nil {
					return err
				}
				grp.Go(func() error {
					defer p.Close()
					return p.ListenAndServe(*flagSMTPAddr)
				})
			}

			p, err := imap_proxy.New(ctx, proxyConf, *flagCacheDir, *flagCacheSizeMiB)
			if err != nil {
				return err
			}
			grp.Go(func() error {
				defer p.Close()
				return p.ListenAndServe(addr)
			})
			return grp.Wait()
		},
	}

	if err := app.Parse(os.Args[1:], ff.WithEnvVarPrefix("GRAPH_PROXY")); err != nil {
		if errors.Is(err, ff.ErrHelp) {
			ffhelp.Command(&app).WriteTo(os.Stderr)
			return nil
		}
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGKILL)
	defer cancel()

	return app.Run(ctx)
}
