// Copyright 2022, 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	msal "github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"golang.org/x/oauth2"

	"github.com/UNO-SOFT/zlog/v2"
	"github.com/google/renameio/v2"
	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/hashicorp/go-azure-sdk/sdk/odata"
	"github.com/manicminer/hamilton/msgraph"
	// "github.com/microsoftgraph/msgraph-sdk-go"
)

type (
	// Query is a re-export of odata.Query to save the users of importing that package, too.
	Query   = odata.Query
	OrderBy = odata.OrderBy
	User    = msgraph.User
)

const (
	Ascending  = odata.Ascending
	Descending = odata.Descending
)

func EscapeSingleQuote(s string) string { return odata.EscapeSingleQuote(s) }

// WellKnownFolders folder names
var WellKnownFolders = map[string][]string{
	"archive":                   {"Archive"},                           // The archive folder messages are sent to when using the One_Click Archive feature in Outlook clients that support it. Note: this isn't the same as the Archive Mailbox feature of Exchange online.
	"clutter":                   nil,                                   // The clutter folder low-priority messages are moved to when using the Clutter feature.
	"conflicts":                 nil,                                   // The folder that contains conflicting items in the mailbox.
	"conversationhistory":       nil,                                   // The folder where Skype saves IM conversations (if Skype is configured to do so).
	"deleteditems":              {"Trash", "Deleted", "Deleted Items"}, // The folder items are moved to when they're deleted.
	"drafts":                    {"Drafts"},                            // The folder that contains unsent messages.
	"inbox":                     {"INBOX"},                             // The inbox folder.
	"junkemail":                 {"Spam", "Junk", "Junk Email"},        // The junk email folder.
	"localfailures":             nil,                                   // The folder that contains items that exist on the local client but couldn't be uploaded to the server.
	"msgfolderroot":             nil,                                   // "The Top of Information Store" folder. This folder is the parent folder for folders that are displayed in normal mail clients, such as the inbox.
	"outbox":                    nil,                                   // The outbox folder.
	"recoverableitemsdeletions": nil,                                   // The folder that contains soft-deleted items: deleted either from the Deleted Items folder, or by pressing shift+delete in Outlook. This folder isn't visible in any Outlook email client, but end users can interact with it through the Recover Deleted Items from Server feature in Outlook or Outlook on the web.
	"scheduled":                 nil,                                   // The folder that contains messages that are scheduled to reappear in the inbox using the Schedule feature in Outlook for iOS.
	"searchfolders":             nil,                                   // The parent folder for all search folders defined in the user's mailbox.
	"sentitems":                 {"Sent", "Sent Items"},                // The sent items folder.
	"serverfailures":            nil,                                   // The folder that contains items that exist on the server but couldn't be synchronized to the local client.
	"syncissues":                nil,                                   // The folder that contains synchronization logs created by Outlook.
}

type GraphMailClient struct {
	BaseClient msgraph.Client
}

var mailReadWriteScopes = []string{"https://graph.microsoft.com/Mail.ReadWrite", "https://graph.microsoft.com/Mail.Send", "https://graph.microsoft.com/MailboxFolder.ReadWrite"}

func NewGraphMailClient(ctx context.Context, tenantID, clientID, clientSecret, redirectURI string) (GraphMailClient, []User, error) {
	logger := zlog.SFromContext(ctx)
	env := environments.AzurePublic()
	var err error
	var authorizer auth.Authorizer
	var users []User
	if clientSecret == "" {
		var ia *interactiveAuthorizer
		if ia, err = newInteractiveAuthorizer(ctx, clientID, tenantID, redirectURI, mailReadWriteScopes, "graph-tokens.json"); err == nil {
			authorizer = ia
			if _, err = ia.Token(ctx, nil); err == nil {
				logger.Info("Token", "ia", ia, "accounts", ia.Accounts)
				a := ia.Accounts[0]
				// logger.Info("got", "Account", a, "a", fmt.Sprintf("%#v", a))
				u := User{
					DisplayName:       &a.Name,
					UserPrincipalName: &a.PreferredUsername,
				}
				u.Id = &a.LocalAccountID
				users = append(users[:0], u)
			}
		}
	} else {
		credentials := auth.Credentials{
			Environment:                           *env,
			TenantID:                              tenantID,
			ClientID:                              clientID,
			ClientSecret:                          clientSecret,
			EnableAuthenticatingUsingClientSecret: true,
		}
		authorizer, err = auth.NewAuthorizerFromCredentials(ctx, credentials, env.MicrosoftGraph)
	}
	if err != nil {
		return GraphMailClient{}, nil, err
	}
	client := msgraph.NewUsersClient()
	client.BaseClient.Authorizer = authorizer
	client.BaseClient.RetryableClient.RetryMax = 3

	if logger.Enabled(ctx, slog.LevelDebug) {
		requestLogger := func(req *http.Request) (*http.Request, error) {
			if req != nil && logger.Enabled(req.Context(), slog.LevelDebug) {
				dump, _ := httputil.DumpRequestOut(req, false)
				logger.Debug("request", "method", req.Method, "URL", req.URL.String(), "body", string(dump))
			}
			return req, nil
		}

		responseLogger := func(req *http.Request, resp *http.Response) (*http.Response, error) {
			if resp != nil && logger.Enabled(req.Context(), slog.LevelDebug) {
				dump, _ := httputil.DumpResponse(resp, false)
				logger.Debug("response", "URL", resp.Request.URL.String(), "body", string(dump))
			}
			return resp, nil
		}

		client.BaseClient.RequestMiddlewares = &[]msgraph.RequestMiddleware{requestLogger}
		client.BaseClient.ResponseMiddlewares = &[]msgraph.ResponseMiddleware{responseLogger}
	}

	cl := GraphMailClient{BaseClient: client.BaseClient}
	if len(users) == 0 {
		if _, err := cl.Users(ctx); err != nil {
			return GraphMailClient{}, users, fmt.Errorf("%w", err)
		}
	}

	return cl, users, nil
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
		DisablePaging:          query.Top != 0,
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
	var buf strings.Builder
	if err := json.NewDecoder(io.TeeReader(resp.Body, &buf)).Decode(dest); err != nil {
		return fmt.Errorf("json.Unmarshal(%q): %w", buf.String(), err)
	}
	if logger := zlog.SFromContext(ctx); logger.Enabled(ctx, slog.LevelDebug) {
		logger.Debug("get", "URL", resp.Request.URL, "response", buf.String())
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

func (g GraphMailClient) GetMIMEMessage(ctx context.Context, w io.Writer, userID, messageID string) (int64, error) {
	entity := "/users/" + url.PathEscape(userID) + "/messages/" + url.PathEscape(messageID) + "/$value"
	resp, status, _, err := g.BaseClient.Get(ctx, msgraph.GetHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		DisablePaging:          true,
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

func (g GraphMailClient) GetMessage(ctx context.Context, userID, messageID string, query odata.Query) (Message, error) {
	var data Message
	// "{\"@odata.context\":\"https://graph.microsoft.com/beta/$metadata#users('ff61c637-79fc-4e94-9d85-13c161b85a93')/messages(flag,isRead,id,importance)/$entity\",\"@odata.etag\":\"W/\\\"CQAAABYAAACo4yIhuSqFRaYgFOcu6OmPAAj5GmpC\\\"\",\"id\":\"AAMkAGJiZjViMTczLTM3Y2MtNDY4ZS1hZWUyLTg3YThiODcwM2IzYQBGAAAAAABiKbJsEoSxRopuDrKLuGHjBwCo4yIhuSqFRaYgFOcu6OmPAAAAAAEMAACo4yIhuSqFRaYgFOcu6OmPAAj7nIpyAAA=\",\"importance\":\"normal\",\"isRead\":true,\"flag\":{\"flagStatus\":\"notFlagged\"}}"
	err := g.get(ctx, &data, "/users/"+url.PathEscape(userID)+"/messages/"+url.PathEscape(messageID), query)
	return data, err
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

func (g GraphMailClient) CreateFolder(ctx context.Context, userID, displayName string) (Folder, error) {
	entity := "/users/" + url.PathEscape(userID) + "/mailFolders"
	resp, status, _, err := g.BaseClient.Post(ctx, msgraph.PostHttpRequestInput{
		Body:                   []byte(`{"displayName":` + strconv.Quote(displayName) + "}"),
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK, http.StatusCreated},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return Folder{}, fmt.Errorf("BaseClient.Get(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Folder{}, fmt.Errorf("io.ReadAll(): %w", err)
	}
	var data Folder
	err = json.Unmarshal(respBody, &data)
	return data, err
}
func (g GraphMailClient) CreateChildFolder(ctx context.Context, userID, parentID, displayName string) (Folder, error) {
	entity := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(parentID) + "/childFolders"
	resp, status, _, err := g.BaseClient.Post(ctx, msgraph.PostHttpRequestInput{
		Body:                   []byte(`{"displayName":` + strconv.Quote(displayName) + "}"),
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK, http.StatusCreated},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return Folder{}, fmt.Errorf("BaseClient.Get(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Folder{}, fmt.Errorf("io.ReadAll(): %w", err)
	}
	var data Folder
	err = json.Unmarshal(respBody, &data)
	return data, err
}

func (g GraphMailClient) CreateMessage(ctx context.Context, userID, folderID string, msg Message) (Message, error) {
	entity := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(folderID) + "/messages"
	b, err := json.Marshal(msg)
	if err != nil {
		return Message{}, err
	}
	resp, status, _, err := g.BaseClient.Post(ctx, msgraph.PostHttpRequestInput{
		Body:                   b,
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
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

func (g GraphMailClient) CopyMessage(ctx context.Context, userID, srcFolderID, msgID, destFolderID string) (Message, error) {
	return g.copyOrMoveMessage(ctx, userID, srcFolderID, msgID, destFolderID, false)
}
func (g GraphMailClient) MoveMessage(ctx context.Context, userID, srcFolderID, msgID, destFolderID string) (Message, error) {
	return g.copyOrMoveMessage(ctx, userID, srcFolderID, msgID, destFolderID, true)
}
func (g GraphMailClient) copyOrMoveMessage(ctx context.Context, userID, srcFolderID, msgID, destFolderID string, move bool) (Message, error) {
	entity := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(srcFolderID) + "/messages/" + url.PathEscape(msgID)
	if move {
		entity += "/move"
	} else {
		entity += "/copy"
	}
	resp, status, _, err := g.BaseClient.Post(ctx, msgraph.PostHttpRequestInput{
		Body:                   []byte(`{"destinationId":` + strconv.Quote(destFolderID) + "}"),
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK, http.StatusCreated},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return Message{}, fmt.Errorf("copyOrMoveMessage(%q): [%d] - %v", entity, status, err)
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
func (g GraphMailClient) RenameFolder(ctx context.Context, userID, folderID, displayName string) error {
	entity := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(folderID)
	var buf bytes.Buffer
	fmt.Fprintf(&buf, `{"displayName":%q}`, displayName)
	resp, status, _, err := g.BaseClient.Patch(ctx, msgraph.PatchHttpRequestInput{
		Body:                   buf.Bytes(),
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK, http.StatusCreated},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return fmt.Errorf("BaseClient.Patch(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	return nil
}

func (g GraphMailClient) DeleteFolder(ctx context.Context, userID, folderID string) error {
	entity := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(folderID)
	resp, status, _, err := g.BaseClient.Delete(ctx, msgraph.DeleteHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return fmt.Errorf("BaseClient.Delete(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	return nil
}

func (g GraphMailClient) DeleteChildFolder(ctx context.Context, userID, parentID, folderID string) error {
	entity := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(parentID) + "/childFolders/" + url.PathEscape(folderID)
	resp, status, _, err := g.BaseClient.Delete(ctx, msgraph.DeleteHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK, http.StatusCreated},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return fmt.Errorf("BaseClient.Delete(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	return nil
}

func (g GraphMailClient) DeleteMessage(ctx context.Context, userID, folderID, msgID string) error {
	entity := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(folderID) + "/messages/" + url.PathEscape(msgID)
	resp, status, _, err := g.BaseClient.Delete(ctx, msgraph.DeleteHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent},
		Uri: msgraph.Uri{
			Entity: entity,
			// HasTenantId: true,
		},
	})
	if err != nil {
		return fmt.Errorf("BaseClient.Delete(%q): [%d] - %v", entity, status, err)
	}
	defer resp.Body.Close()
	return nil
}

type Message struct {
	Created        time.Time      `json:"createdDateTime,omitempty"`
	Modified       time.Time      `json:"lastModifiedDateTime,omitempty"`
	Received       time.Time      `json:"receivedDateTime,omitempty"`
	Sent           time.Time      `json:"sentDateTime,omitempty"`
	Body           Content        `json:"body,omitempty"`
	Sender         EmailAddress   `json:"sender,omitempty"`
	From           EmailAddress   `json:"from,omitempty"`
	UniqueBody     Content        `json:"uniqueBody,omitempty"`
	ReplyTo        []EmailAddress `json:"replyTo,omitempty"`
	ID             string         `json:"id,omitempty"`
	Subject        string         `json:"subject,omitempty"`
	BodyPreview    string         `json:"bodyPreview,omitempty"`
	ChangeKey      string         `json:"changeKey,omitempty"`
	ConversationID string         `json:"conversationId,omitempty"`
	Flag           struct {
		Status string `json:"flagStatus,omitempty"`
	} `json:"flag,omitempty"`
	Importance string         `json:"importance,omitempty"`
	MessageID  string         `json:"internetMessageId,omitempty"`
	FolderID   string         `json:"parentFolderId,omitempty"`
	WebLink    string         `json:"webLink,omitempty"`
	To         []EmailAddress `json:"toRecipients,omitempty"`
	Cc         []EmailAddress `json:"bccRecipients,omitempty"`
	Bcc        []EmailAddress `json:"ccRecipients,omitempty"`
	Headers    []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"internetMessageHeaders,omitempty"`
	HasAttachments bool `json:"hasAttachments,omitempty"`
	Draft          bool `json:"isDraft",omitempty`
	Read           bool `json:"isRead,omitempty"`
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
	logger := zlog.SFromContext(ctx)
	logger.Debug("ListChildFolders", "got", data.Folders)
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
	for len(toList) != 0 {
		logger.Debug("toList", "toList", len(toList))
		nextList = nextList[:0]
		for _, f := range toList {
			if _, ok := seen[f.ID]; ok {
				continue
			}
			seen[f.ID] = struct{}{}
			logger.Debug("get", "name", f.DisplayName, "path", path+"/"+url.PathEscape(f.ID)+"/childFolders")
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
	if logger := zlog.SFromContext(ctx); logger.Enabled(ctx, slog.LevelDebug) {
		logger.Debug("ListMailFolders", "got", data.Folders, "error", err)
	}
	return data.Folders, err
}

func (g GraphMailClient) DeltaMailFolders(ctx context.Context, userID, deltaLink string) ([]Change, string, error) {
	var err error
	if deltaLink == "" {
		var data struct {
			Delta string `json:"@odata.deltaLink"`
		}
		path := "/users/" + url.PathEscape(userID) + "/mailFolders/delta"
		if err = g.get(ctx, &data, path, Query{Select: []string{"parentFolderId"}}); err == nil {
			deltaLink = data.Delta
		}
	}
	if deltaLink == "" {
		return nil, "", err
	}
	var data struct {
		Delta   string   `json:"@odata.deltaLink"`
		Changes []Change `json:"value"`
	}
	req := msgraph.GetHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK},
	}
	// set unexported rawUri
	rs := reflect.ValueOf(&req).Elem()
	rf := rs.FieldByName("rawUri")
	// rf can't be read or set.
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	// Now rf can be read and set.
	rf.SetString(deltaLink)
	logger := zlog.SFromContext(ctx)
	// logger.Warn("Delta", "req", fmt.Sprintf("%#v", req))
	resp, _, _, err := g.BaseClient.Get(ctx, req)
	if err == nil {
		err = json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
	}
	if err != nil {
		logger.Error("delta", "data", data, "error", err)
	} else {
		logger.Debug("delta", "data", data)
	}
	return data.Changes, data.Delta, err
}

func (g GraphMailClient) DeltaMails(ctx context.Context, userID, folderID, deltaLink string) ([]Change, string, error) {
	var err error
	if deltaLink == "" {
		var data struct {
			Delta string `json:"@odata.deltaLink"`
		}
		path := "/users/" + url.PathEscape(userID) + "/mailFolders/" + url.PathEscape(folderID) + "/messages/delta"
		if err = g.get(ctx, &data, path, Query{Select: []string{"parentFolderId"}}); err == nil {
			deltaLink = data.Delta
		}
	}
	if deltaLink == "" {
		return nil, "", err
	}
	var data struct {
		Delta   string   `json:"@odata.deltaLink"`
		Changes []Change `json:"value"`
	}
	req := msgraph.GetHttpRequestInput{
		ConsistencyFailureFunc: msgraph.RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusOK},
	}
	// set unexported rawUri
	rs := reflect.ValueOf(&req).Elem()
	rf := rs.FieldByName("rawUri")
	// rf can't be read or set.
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	// Now rf can be read and set.
	rf.SetString(deltaLink)
	logger := zlog.SFromContext(ctx)
	// logger.Warn("Delta", "req", fmt.Sprintf("%#v", req))
	resp, _, _, err := g.BaseClient.Get(ctx, req)
	if err == nil {
		err = json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
	}
	if err != nil {
		logger.Error("delta", "data", data, "error", err)
	} else {
		logger.Debug("delta", "data", data)
	}
	return data.Changes, data.Delta, err
}

type Change struct {
	Type           string          `json:"@odata.type"`
	ETag           string          `json:"@odata.etag"`
	ID             string          `json:"id"`
	ParentFolderID string          `json:"parentFolderId"`
	Removed        json.RawMessage `json:"removed"`
	Read           bool            `json:"isRead"`
}

type Folder struct {
	ID               string `json:"id"`
	DisplayName      string `json:"displayName"`
	ParentFolderID   string `json:"parentFolderId"`
	WellKnownName    string `json:"wellKnownName"`
	ChildFolderCount int    `json:"childFolderCount"`
	UnreadItemCount  int    `json:"unreadItemCount"`
	TotalItemCount   int    `json:"totalItemCount"`
	SizeInBytes      int    `json:"sizeInBytes"`
	Hidden           bool   `json:"isHidden"`
}

type interactiveAuthorizer struct {
	RedirectURI string
	Scopes      []string
	client      msal.Client
	Accounts    []msal.Account
	cache       cache.ExportReplace
}

var _ auth.Authorizer = (*interactiveAuthorizer)(nil)

func newInteractiveAuthorizer(ctx context.Context, clientID, tenantID, redirectURI string, scopes []string, cacheFileName string) (*interactiveAuthorizer, error) {
	ia := interactiveAuthorizer{RedirectURI: redirectURI, Scopes: scopes}
	if cacheFileName != "" {
		if strings.IndexByte(cacheFileName, filepath.Separator) < 0 {
			if cd, err := os.UserCacheDir(); err == nil {
				cacheFileName = filepath.Join(cd, cacheFileName)
			}
		}
		ia.cache = &tokenCache{FileName: cacheFileName}
	}

	opts := []msal.Option{msal.WithAuthority("https://login.microsoftonline.com/" + tenantID), nil}[:1]
	if ia.cache != nil {
		opts = append(opts, msal.WithCache(ia.cache))
	}
	// zlog.SFromContext(ctx).Info("interactiveAuthorizer", "cache", ia.cache, "cacheFileName", cacheFileName, "opts", opts)
	var err error
	if ia.client, err = msal.New(clientID, opts...); err != nil {
		return nil, fmt.Errorf("msal.New: %w", err)
	}
	if ia.Accounts, err = ia.client.Accounts(ctx); err != nil {
		return nil, fmt.Errorf("Accounts: %w", err)
	}
	return &ia, nil
}

// Token obtains a new access token for the configured tenant
func (ia *interactiveAuthorizer) Token(ctx context.Context, request *http.Request) (*oauth2.Token, error) {
	// https://github.com/MicrosoftDocs/azure-docs/issues/61446
	logger := zlog.SFromContext(ctx)
	var err error
	if ia.Accounts, err = ia.client.Accounts(ctx); err != nil {
		return nil, fmt.Errorf("Accounts: %w", err)
	}
	var result msal.AuthResult
	if len(ia.Accounts) > 0 {
		// There may be more accounts; here we assume the first one is wanted.
		// AcquireTokenSilent returns a non-nil error when it can't provide a token.
		if result, err = ia.client.AcquireTokenSilent(ctx, ia.Scopes, msal.WithSilentAccount(ia.Accounts[0])); err != nil {
			logger.Warn("AcquireTokenSilent", "error", err)
		}
	}
	if result.AccessToken == "" {
		// cache miss, authenticate a user with another AcquireToken* method
		shortCtx, shortCancel := context.WithTimeout(ctx, time.Minute)
		result, err = ia.client.AcquireTokenInteractive(shortCtx,
			ia.Scopes,
			msal.WithRedirectURI(nvl(ia.RedirectURI, "http://localhost")),
		)
		shortCancel()
		if err != nil {
			return nil, fmt.Errorf("AcquireTokenInteractive: %w", err)
		}
	}
	if result.Account.IsZero() {
		return nil, fmt.Errorf("AcquireTokenInteractive returned empty token: %+v", result)
	}
	ia.Accounts = append(ia.Accounts[:0], result.Account)
	return &oauth2.Token{
		AccessToken:  result.AccessToken,
		RefreshToken: result.IDToken.RawToken,
	}, nil
}

// AuxiliaryTokens obtains new access tokens for the configured auxiliary tenants
func (ia *interactiveAuthorizer) AuxiliaryTokens(ctx context.Context, request *http.Request) ([]*oauth2.Token, error) {
	return nil, nil
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

type tokenCache struct {
	FileName     string
	mu           sync.Mutex
	m            map[string]json.RawMessage
	lastModified time.Time
	hasher       hash.Hash
	hsh          [sha512.Size224]byte
}

var _ cache.ExportReplace = (*tokenCache)(nil)

// Replace replaces the cache with what is in external storage. Implementors should honor
// Context cancellations and return context.Canceled or context.DeadlineExceeded in those cases.
func (c *tokenCache) Replace(ctx context.Context, um cache.Unmarshaler, hints cache.ReplaceHints) error {
	logger := zlog.SFromContext(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m != nil && !c.lastModified.IsZero() {
		if fi, err := os.Stat(c.FileName); err == nil && !c.lastModified.Before(fi.ModTime()) {
			if err = um.Unmarshal(c.m[hints.PartitionKey]); err != nil {
				logger.Error("Replace", "error", err)
				return fmt.Errorf("unmarshal %q: %w", c.m[hints.PartitionKey], err)
			}
		}
	}
	if err := c.readFile(ctx); err != nil {
		logger.Error("readFile", "error", err)
		return err
	}
	b := c.m[hints.PartitionKey]
	if len(b) == 0 {
		b = c.m[""]
	}
	if len(b) != 0 {
		return um.Unmarshal(b)
	}
	return nil
}

func (c *tokenCache) readFile(ctx context.Context) error {
	logger := zlog.SFromContext(ctx)
	c.lastModified = time.Now()
	var mm map[string]json.RawMessage
	if b, err := os.ReadFile(c.FileName); err != nil {
		logger.Warn("read", "file", c.FileName, "error", err)
		os.Remove(c.FileName)
	} else if err = json.Unmarshal(b, &mm); err != nil {
		logger.Warn("unmarshal", "b", string(b), "error", err)
		os.Remove(c.FileName)
	} else {
		if c.hasher == nil {
			c.hasher = sha512.New512_224()
		}
		c.hasher.Reset()
		c.hasher.Write(b)
		c.hasher.Sum(c.hsh[:0])
		logger.Debug("successfully read", "file", c.FileName, "mtime", c.lastModified, "hash", c.hsh[:])
		c.m = mm
	}
	return nil
}

// Export writes the binary representation of the cache (cache.Marshal()) to external storage.
// This is considered opaque. Context cancellations should be honored as in Replace.
func (c *tokenCache) Export(ctx context.Context, m cache.Marshaler, hints cache.ExportHints) error {
	logger := zlog.SFromContext(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(c.FileName)
	if err != nil {
		logger.Warn("stat", "file", c.FileName, "error", err)
		os.Remove(c.FileName)
	} else if c.m == nil || c.lastModified.Before(fi.ModTime()) {
		if err = c.readFile(ctx); err != nil {
			logger.Error("readFile", "error", err)
			return err
		}
	}
	if b, err := m.Marshal(); err != nil {
		logger.Error("marshal", "error", err)
		return fmt.Errorf("marshal: %w", err)
	} else if len(b) != 0 {
		if c.m == nil {
			c.m = make(map[string]json.RawMessage)
		}
		if logger.Enabled(ctx, slog.LevelDebug) {
			logger.Debug("save", "key", hints.PartitionKey, "value", string(b))
		}
		c.m[hints.PartitionKey] = b
	}
	b, err := json.Marshal(c.m)
	if err != nil {
		logger.Error("marshal", "error", err)
		return fmt.Errorf("marshal map: %w", err)
	} else if true || c.hasher != nil {
		c.hasher.Reset()
		c.hasher.Write(b)
		old := c.hsh
		c.hasher.Sum(c.hsh[:0])
		if old == c.hsh {
			logger.Info("SKIP same hash")
			return nil
		}
		if logger.Enabled(ctx, slog.LevelDebug) {
			logger.Debug("changed", "b", string(b), "old", old, "new", c.hsh)
		}
	}
	if err = renameio.WriteFile(c.FileName, b, 0600); err != nil {
		logger.Error("write", "file", c.FileName, "error", err)
		return fmt.Errorf("write file %q: %w", c.FileName, err)
	}
	c.lastModified = time.Now()
	// logger.Info("saved", "lastModified", c.lastModified)
	return nil
}
