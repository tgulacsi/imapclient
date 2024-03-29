// Copyright 2022 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-logr/logr"

	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/hashicorp/go-azure-sdk/sdk/odata"
	"github.com/manicminer/hamilton/msgraph"
)

type GraphMailClient struct {
	BaseClient msgraph.Client
}

func NewGraphMailClient(ctx context.Context, tenantID, clientID, clientSecret string) (GraphMailClient, error) {
	logger := logr.FromContextOrDiscard(ctx)
	env := environments.AzurePublic()

	credentials := auth.Credentials{
		Environment:  *env,
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,

		EnableAuthenticatingUsingClientSecret: true,
	}
	// https://learn.microsoft.com/hu-hu/azure/active-directory/develop/quickstart-register-app#add-a-certificate
	authorizer, err := auth.NewAuthorizerFromCredentials(ctx, credentials, env.MicrosoftGraph)
	if err != nil {
		return GraphMailClient{}, err
	}
	client := msgraph.NewUsersClient()
	client.BaseClient.Authorizer = authorizer
	client.BaseClient.RetryableClient.RetryMax = 3

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

		client.BaseClient.RequestMiddlewares = &[]msgraph.RequestMiddleware{requestLogger}
		client.BaseClient.ResponseMiddlewares = &[]msgraph.ResponseMiddleware{responseLogger}
	}

	return GraphMailClient{BaseClient: client.BaseClient}, nil
}

func (g GraphMailClient) Users(ctx context.Context) ([]msgraph.User, error) {
	users, _, err := (&msgraph.UsersClient{BaseClient: g.BaseClient}).List(ctx, odata.Query{})
	if err != nil {
		return nil, err
	}
	if users == nil {
		return nil, fmt.Errorf("bad API response, nil result received")
	}
	return *users, nil
}
func (g GraphMailClient) get(ctx context.Context, dest interface{}, entity string, query odata.Query) error {
	resp, status, _, err := g.BaseClient.Get(ctx, msgraph.GetHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		DisablePaging:          query.Top > 0,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return nil
		}
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
func (g GraphMailClient) UpdateMessage(ctx context.Context, userID, messageID string, update json.RawMessage) (Message, error) {
	entity := "/users/" + url.PathEscape(userID) + "/messages/" + url.PathEscape(messageID)
	resp, status, _, err := g.BaseClient.Patch(ctx, msgraph.PatchHttpRequestInput{
		Body:                   []byte(update),
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		OData:                  odata.Query{},
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return Message{}, fmt.Errorf("BaseClient.Get(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Message{}, fmt.Errorf("io.ReadAll(): %w", err)
	}
	var data Message
	err = json.Unmarshal(respBody, &data)
	return data, err
}
func (g GraphMailClient) MoveMessage(ctx context.Context, userID, messageID, folderID string) (Message, error) {
	entity := "/users/" + url.PathEscape(userID) + "/messages/" + url.PathEscape(messageID) + "/move"
	resp, status, _, err := g.BaseClient.Post(ctx, msgraph.PostHttpRequestInput{
		Body:                   []byte(`{"destinationId":` + strconv.Quote(folderID) + "}"),
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		OData:                  odata.Query{},
		ValidStatusCodes:       []int{http.StatusOK, http.StatusCreated},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return Message{}, fmt.Errorf("BaseClient.Get(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Message{}, fmt.Errorf("io.ReadAll(): %w", err)
	}
	var data Message
	err = json.Unmarshal(respBody, &data)
	return data, err
}
func (g GraphMailClient) GetMIMEMessage(ctx context.Context, w io.Writer, userID, messageID string) (int64, error) {
	entity := "/users/" + url.PathEscape(userID) + "/messages/" + url.PathEscape(messageID) + "/$value"
	resp, status, _, err := g.BaseClient.Get(ctx, msgraph.GetHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		DisablePaging:          true,
		OData:                  odata.Query{},
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return 0, fmt.Errorf("BaseClient.Get(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	return io.Copy(w, resp.Body)
}

func (g GraphMailClient) GetMessage(ctx context.Context, userID, messageID string, query odata.Query) ([]Message, error) {
	var data struct {
		Messages []Message `json:"value"`
	}
	err := g.get(ctx, &data, "/users/"+url.PathEscape(userID)+"/messages/"+url.PathEscape(messageID), query)
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
	err := g.get(ctx, &data, "/users/"+url.PathEscape(userID)+"/messages/"+url.PathEscape(messageID), query)
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
	err := g.get(ctx, &data, "/users/"+url.PathEscape(userID)+"/mailFolders/"+url.PathEscape(folderID)+"/messages", query)
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

func (g GraphMailClient) ListChildFolders(ctx context.Context, userID, folderID string, recursive bool, query odata.Query) ([]Folder, error) {
	var data struct {
		Folders []Folder `json:"value"`
	}
	path := "/users/" + url.PathEscape(userID) + "/mailFolders"
	if err := g.get(ctx, &data, path+"/"+url.PathEscape(folderID)+"/childFolders", query); err != nil || !recursive {
		return data.Folders, err
	}
	folders := append([]Folder(nil), data.Folders...)
	toList := make([]Folder, 0, len(folders))
	for _, f := range folders {
		if f.ChildFolderCount != 0 {
			toList = append(toList, f)
		}
	}
	if len(toList) == 0 {
		return folders, nil
	}
	var nextList []Folder
	seen := make(map[string]struct{})
	logger := logr.FromContextOrDiscard(ctx)
	for len(toList) != 0 {
		logger.V(1).Info("toList", "toList", len(toList))
		nextList = nextList[:0]
		for _, f := range toList {
			if _, ok := seen[f.ID]; ok {
				continue
			}
			seen[f.ID] = struct{}{}
			logger.V(2).Info("get", "name", f.DisplayName, "path", path+"/"+url.PathEscape(f.ID)+"/childFolders")
			if err := g.get(ctx, &data, path+"/"+url.PathEscape(f.ID)+"/childFolders", query); err != nil {
				if strings.Contains(err.Error(), "nil *Response with nil error") {
					continue
				}
				return folders, err
			}
			folders = append(folders, data.Folders...)
			for _, f := range data.Folders {
				if f.ChildFolderCount != 0 {
					nextList = append(nextList, f)
				}
			}
		}
		toList = nextList
	}
	return folders, nil
}

func (g GraphMailClient) ListMailFolders(ctx context.Context, userID string, query odata.Query) ([]Folder, error) {
	var data struct {
		Folders []Folder `json:"value"`
	}
	path := "/users/" + url.PathEscape(userID) + "/mailFolders"
	err := g.get(ctx, &data, path, query)
	return data.Folders, err
}

type Folder struct {
	ID               string `json:"id"`
	DisplayName      string `json:"displayName"`
	ParentFolderID   string `json:"parentFolderId"`
	ChildFolderCount int    `json:"childFolderCount"`
	UnreadItemCount  int    `json:"unreadItemCount"`
	TotalItemCount   int    `json:"totalItemCount"`
	Hidden           bool   `json:"isHidden"`
}
