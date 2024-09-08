// Copyright 2022, 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/UNO-SOFT/zlog/v2"
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

func NewGraphMailClient(ctx context.Context, tenantID, clientID, clientSecret string) (GraphMailClient, error) {
	logger := zlog.SFromContext(ctx)
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

	if logger.Enabled(ctx, slog.LevelDebug) {
		requestLogger := func(req *http.Request) (*http.Request, error) {
			if req != nil {
				dump, _ := httputil.DumpRequestOut(req, false)
				logger.Debug("request", "method", req.Method, "URL", req.URL.String(), "body", string(dump))
			}
			return req, nil
		}

		responseLogger := func(req *http.Request, resp *http.Response) (*http.Response, error) {
			if resp != nil {
				dump, _ := httputil.DumpResponse(resp, false)
				logger.Debug("response", "URL", resp.Request.URL.String(), "body", string(dump))
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
	Created        time.Time    `json:"createdDateTime,omitempty"`
	Modified       time.Time    `json:"lastModifiedDateTime,omitempty"`
	Received       time.Time    `json:"receivedDateTime,omitempty"`
	Sent           time.Time    `json:"sentDateTime,omitempty"`
	Body           Content      `json:"body,omitempty"`
	Sender         EmailAddress `json:"sender,omitempty"`
	From           EmailAddress `json:"from,omitempty"`
	UniqueBody     Content      `json:"uniqueBody,omitempty"`
	ReplyTo        EmailAddress `json:"replyTo,omitempty"`
	ID             string       `json:"id,omitempty"`
	Subject        string       `json:"subject,omitempty"`
	BodyPreview    string       `json:"bodyPreview,omitempty"`
	ChangeKey      string       `json:"changeKey,omitempty"`
	ConversationID string       `json:"conversationId,omitempty"`
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
