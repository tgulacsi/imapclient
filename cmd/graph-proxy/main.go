// Copyright 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/UNO-SOFT/zlog/v2"
)

func main() {
	if err := Main(); err != nil {
		slog.Error("Main", "error", err)
		os.Exit(1)
	}
}

func Main() error {
	var verbose zlog.VerboseVar
	logger := zlog.NewLogger(zlog.MaybeConsoleHandler(&verbose, os.Stderr)).SLog()
	flagClientID := flag.String("client-id", nvl(os.Getenv("AZURE_CLIENT_ID"), "34f2c0c1-b509-43c5-aae8-56c10fa19ed7"), "ClientID")
	// flagRedirectURI := flag.String("redirect-uri", "http://localhost:19414/auth-repsonse", "The redirect URI you send in the request to the login server")
	// flagClientSecret := flag.String("client-secret", "", "ClientSecret")
	// flagTenantID := flag.String("tenant-id", "", "TenantID")
	// flagUserID := flag.String("user-id", "", "UserID")
	flagRedirectURI := flag.String("redirect-uri", "http://localhost", "redirectURI (if client secret is empty)")
	flag.Var(&verbose, "v", "verbosity")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGKILL)
	defer cancel()

	logger.Info("Listen", "addr", flag.Arg(0))
	return NewProxy(
		zlog.NewSContext(ctx, logger),
		*flagClientID, *flagRedirectURI,
	).ListenAndServe(flag.Arg(0))
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
