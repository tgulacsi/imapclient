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
	flagClientID := flag.String("client-id", "", "ClientID")
	// flagClientSecret := flag.String("client-secret", "", "ClientSecret")
	// flagTenantID := flag.String("tenant-id", "", "TenantID")
	// flagUserID := flag.String("user-id", "", "UserID")
	flag.Var(&verbose, "v", "verbosity")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGKILL)
	defer cancel()

	return NewProxy(
		zlog.NewSContext(ctx, logger),
		//*flagTenantID,*flagClientSecret,
		*flagClientID,
	).ListenAndServe(flag.Arg(0))
}
