package graph

import (
	"context"
	"flag"
	"testing"
	"time"
)

var (
	flagTenantID    = flag.String("tenant-id", "", "tenant ID")
	flagClientID    = flag.String("client-id", "34f2c0c1-b509-43c5-aae8-56c10fa19ed7", "client ID")
	flagRedirectURI = flag.String("redirect-uri", "http://localhost", "redirectURI")
)

func TestAuthTokenInteractive(t *testing.T) {
	flag.Parse()
	if *flagTenantID == "" {
		t.Skip("empty -client-id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	token, err := (&interactiveAuthorizer{ClientID: *flagClientID, TenantID: *flagTenantID, RedirectURI: *flagRedirectURI, Scopes: mailReadWriteScopes}).Token(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("token:", token)
}
