// Copyright 2022 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/go-logr/logr"

	"github.com/manicminer/hamilton/auth"
	"github.com/manicminer/hamilton/environments"
	"github.com/manicminer/hamilton/msgraph"
	"github.com/manicminer/hamilton/odata"
)

type GraphMailClient struct {
	BaseClient msgraph.Client
}

func NewGraphMailClient(ctx context.Context, tenantID, clientID, clientSecret string) (GraphMailClient, error) {
	logger := logr.FromContextOrDiscard(ctx)
	environment := environments.Global
	authConfig := &auth.Config{
		Environment:            environment,
		TenantID:               tenantID,
		ClientID:               clientID,
		ClientSecret:           clientSecret,
		EnableClientSecretAuth: true,
	}

	// https://learn.microsoft.com/hu-hu/azure/active-directory/develop/quickstart-register-app#add-a-certificate
	authorizer, err := authConfig.NewAuthorizer(ctx, environment.MsGraph)
	if err != nil {
		return GraphMailClient{}, err
	}
	tok, err := authorizer.Token()
	if err != nil {
		return GraphMailClient{}, err
	}
	logger.Info("authorizer", "token", tok)

	client := msgraph.NewClient(msgraph.VersionBeta, tenantID)
	client.Authorizer = authorizer
	client.RetryableClient.RetryMax = 3

	if logger.V(1).Enabled() {
		requestLogger := func(req *http.Request) (*http.Request, error) {
			if req != nil {
				dump, _ := httputil.DumpRequestOut(req, true)
				logger.V(1).Info("request", "method", req.Method, "URL", req.URL.String(), "body", dump)
			}
			return req, nil
		}

		responseLogger := func(req *http.Request, resp *http.Response) (*http.Response, error) {
			if resp != nil {
				dump, _ := httputil.DumpResponse(resp, true)
				logger.V(1).Info("response", "URL", resp.Request.URL.String(), "body", dump)
			}
			return resp, nil
		}

		client.RequestMiddlewares = &[]msgraph.RequestMiddleware{requestLogger}
		client.ResponseMiddlewares = &[]msgraph.ResponseMiddleware{responseLogger}
	}

	uClient := &msgraph.UsersClient{BaseClient: client}
	users, _, err := uClient.List(ctx, odata.Query{})
	if err != nil {
		return GraphMailClient{}, err
	}
	if users == nil {
		return GraphMailClient{}, fmt.Errorf("bad API response, nil result received")
	}
	for _, user := range *users {
		logger.Info("user", "id", *user.ID, "name", *user.DisplayName)
	}
	return GraphMailClient{BaseClient: client}, nil
}

func (g GraphMailClient) get(ctx context.Context, dest interface{}, entity string, query odata.Query) error {
	resp, status, _, err := g.BaseClient.Get(ctx, msgraph.GetHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		DisablePaging:          query.Top > 0,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: msgraph.Uri{
			Entity:      entity,
			HasTenantId: true,
		},
	})
	if err != nil {
		return fmt.Errorf("BaseClient.Get(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("io.ReadAll(): %w", err)
	}
	if err := json.Unmarshal(respBody, dest); err != nil {
		return fmt.Errorf("json.Unmarshal(): %w", err)
	}
	return nil
}

func (g GraphMailClient) GetMessage(ctx context.Context, userID, messageID string, query odata.Query) ([]Message, error) {
	var data struct {
		Messages []Message `json:"value"`
	}
	err := g.get(ctx, &data, fmt.Sprintf("/users/%s/messages/%s", userID, messageID), query)
	return data.Messages, err
}

func (g GraphMailClient) GetMessageHeaders(ctx context.Context, userID, messageID string, query odata.Query) (map[string][]string, error) {
	type kv struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var data struct {
		Headers []kv `json:"internetMessageHeaders"`
	}
	query.Select = append(query.Select, "internetMessageHeaders")
	err := g.get(ctx, &data, fmt.Sprintf("/users/%s/messages/%s", userID, messageID), query)
	if err != nil {
		return nil, err
	}
	m := make(map[string][]string, len(data.Headers))
	for _, kv := range data.Headers {
		m[kv.Name] = append(m[kv.Name], kv.Value)
	}
	return m, nil
}
func (g GraphMailClient) ListMessages(ctx context.Context, userID, folderID string, query odata.Query) ([]Message, error) {
	var data struct {
		Messages []Message `json:"value"`
	}
	err := g.get(ctx, &data, fmt.Sprintf("/users/%s/mailFolders/%s/messages", userID, folderID), query)
	return data.Messages, err
}

type Message struct {
	ID          string         `json:"id"`
	Subject     string         `json:"subject"`
	BodyPreview string         `json:"bodyPreview"`
	Body        Content        `json:"body"`
	Sender      EmailAddress   `json:"sender"`
	From        EmailAddress   `json:"from"`
	To          []EmailAddress `json:"toRecipients"`
	Cc          []EmailAddress `json:"bccRecipients"`
	Bcc         []EmailAddress `json:"ccRecipients"`
	UniqueBody  Content        `json:"uniqueBody"`
}
type Content struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}
type EmailAddress struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

func (g GraphMailClient) ListMailFolders(ctx context.Context, userID string, query odata.Query) ([]Folder, error) {
	var data struct {
		Folders []Folder `json:"value"`
	}
	err := g.get(ctx, &data, fmt.Sprintf("/users/%s/mailFolders", userID), query)
	return data.Folders, err
}

type Folder struct {
	ID               string `json:"id"`
	DisplayName      string `json:"displayName"`
	ParentFolderID   string `json:"parentFolderId"`
	ChildFolderCount int    `json:"childFolderCount"`
	UnreadItemCount  int    `json:"unreadItemCount"`
	TotalItemCount   int    `json:"unreadItemCount"`
	Hidden           bool   `json:"isHidden"`
}
