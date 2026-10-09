// Copyright 2024, 2026 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"flag"
	"github.com/UNO-SOFT/cli"
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
	FS := flag.NewFlagSet("graph-proxy", flag.ContinueOnError)
	FS.IntVar(&concurrency, "concurrency", concurrency, "concurrency")
	FS.Float64Var(&proxyConf.RateLimit, "rate-limit", 10, "mas number of http calls per second")
	flagCacheDir := FS.String("cache-dir", cd, "cache directory")
	flagCacheSizeMiB := FS.Int("cache-max-mb", 512, "cache max size in MiB")
	FS.StringVar(&proxyConf.ClientID, "client-id", "34f2c0c1-b509-43c5-aae8-56c10fa19ed7", "ClientID")
	FS.StringVar(&proxyConf.ClientCert, "client-cert", "", "client certificate .pem")
	// flagRedirectURI := flag.String("redirect-uri", "http://localhost:19414/auth-response", "The redirect URI you send in the request to the login server")
	// flagClientSecret := flag.String("client-secret", "", "ClientSecret")
	// flagTenantID := flag.String("tenant-id", "", "TenantID")
	// flagUserID := flag.String("user-id", "", "UserID")
	FS.StringVar(&proxyConf.RedirectURI, "redirect-uri", "http://localhost", "redirectURI (if client secret is empty)")
	FS.Var(&verbose, "verbose", "verbosity")
	flagPprofURL := FS.String("pprof", "", "pprof URL to listen on")
	flagSMTPAddr := FS.String("smtp", ":1025", "SMTP address to listen on")
	app := cli.Command{Name: "graph-proxy", Flags: FS,
		Usage: "prefix env vars with GRAPH_PROXY_",
		Exec: func(ctx context.Context, state *cli.State) error {
			args := state.Args
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

	if err := cli.Parse(&app, os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			cli.PrintHelp(os.Stderr, &app)
			return nil
		}
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGKILL)
	defer cancel()

	return cli.Run(ctx, &app, nil)
}
