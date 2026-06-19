// Copyright 2026 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"context"
	"os"
	"sync"

	"github.com/tgulacsi/imapclient/graph"
	"golang.org/x/time/rate"
)

type ProxyConfig struct {
	ClientID, ClientCert string
	RedirectURI          string
	RateLimit            float64
}

func (config ProxyConfig) CredOpts() (graph.CredentialOptions, error) {
	credOpts := graph.CredentialOptions{RedirectURL: config.RedirectURI}
	if config.ClientCert == "" {
		return credOpts, nil
	}

	fh, err := os.Open(config.ClientCert)
	if err != nil {
		return credOpts, err
	}
	credOpts.Certs, credOpts.Key, err = graph.ParseCertificates(fh, "")
	fh.Close()
	return credOpts, err
}

type clientUsers struct {
	Client graph.GraphMailClient
	Users  []graph.User
}

type ClientCache struct {
	config   ProxyConfig
	credOpts graph.CredentialOptions
	clients  map[string]clientUsers
	mu       sync.Mutex
}

func NewClientCache(config ProxyConfig) (*ClientCache, error) {
	cache := ClientCache{config: config}
	var err error
	if cache.credOpts, err = cache.config.CredOpts(); err != nil {
		return nil, err
	}
	return &cache, nil
}

func (cache *ClientCache) Key(tenantID, clientSecret string) string {
	return tenantID + "\t" + clientSecret
}

func (cache *ClientCache) Get(ctx context.Context, tenantID, clientSecret, user string) (graph.GraphMailClient, []graph.User, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	key := cache.Key(tenantID, clientSecret)
	if clu, ok := cache.clients[key]; ok {
		return clu.Client, clu.Users, nil
	}
	credOpts := cache.credOpts
	credOpts.Secret = clientSecret
	if credOpts.IDOrPrincipalName == "" {
		credOpts.IDOrPrincipalName = user
	}
	cl, users, err := graph.NewGraphMailClient(
		ctx, tenantID, cache.config.ClientID, credOpts,
	)
	if err != nil {
		return graph.GraphMailClient{}, nil, err
	}
	cl.SetLimit(rate.Limit(cache.config.RateLimit))
	if cache.clients == nil {
		cache.clients = make(map[string]clientUsers)
	}
	cache.clients[key] = clientUsers{Client: cl, Users: users}
	return cl, users, err
}
