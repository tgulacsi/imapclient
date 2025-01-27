// Copyright 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/UNO-SOFT/zlog/v2"
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
	flag.IntVar(&concurrency, "concurrency", concurrency, "concurrency")
	flagRateLimit := flag.Float64("rate-limit", 10, "mas number of http calls per second")
	flagCacheDir := flag.String("cache-dir", cd, "cache directory")
	flagCacheSize := flag.Int("cache-max-mb", 512, "cache max size in MiB")
	flagClientID := flag.String("client-id", nvl(os.Getenv("AZURE_CLIENT_ID"), "34f2c0c1-b509-43c5-aae8-56c10fa19ed7"), "ClientID")
	// flagRedirectURI := flag.String("redirect-uri", "http://localhost:19414/auth-repsonse", "The redirect URI you send in the request to the login server")
	// flagClientSecret := flag.String("client-secret", "", "ClientSecret")
	// flagTenantID := flag.String("tenant-id", "", "TenantID")
	// flagUserID := flag.String("user-id", "", "UserID")
	flagRedirectURI := flag.String("redirect-uri", "http://localhost", "redirectURI (if client secret is empty)")
	flag.Var(&verbose, "v", "verbosity")
	flagPprofURL := flag.String("pprof", "", "pprof URL to listen on")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGKILL)
	defer cancel()

	if *flagPprofURL != "" {
		go http.ListenAndServe(*flagPprofURL, nil)
	}

	addr := ":1143"
	if flag.NArg() != 0 {
		addr = flag.Arg(0)
	}
	logger.Info("Listen", "addr", addr)
	p, err := NewProxy(
		zlog.NewSContext(ctx, logger),
		*flagClientID, *flagRedirectURI,
		*flagCacheDir, *flagCacheSize, *flagRateLimit,
	)
	if err != nil {
		return err
	}
	defer p.Close()
	return p.ListenAndServe(addr)
}

func nvl[T comparable](a T, b ...T) T {
	var zero T
	if a != zero {
		return a
	}
	for _, a := range b {
		if a != zero {
			return a
		}
	}
	return a
}
