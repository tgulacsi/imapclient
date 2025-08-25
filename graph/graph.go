// Copyright 2022, 2025 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/UNO-SOFT/zlog/v2"
	"github.com/microsoft/kiota-abstractions-go/serialization"
	"golang.org/x/time/rate"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
)

type (
	User      = models.Userable
	Recipient = models.Recipientable
	Message   = models.Messageable
	Folder    = models.MailFolderable
)

// type (
// 	// Query is a re-export of odata.Query to save the users of importing that package, too.
// 	Query   = odata.Query
// 	OrderBy = odata.OrderBy
// 	User    = msgraph.User
// )

// const (
// 	Ascending  = odata.Ascending
// 	Descending = odata.Descending
// )

// EscapeSingleQuote replaces all occurrences of single quote, with 2 single quotes.
// For requests that use single quotes, if any parameter values also contain single quotes,
// those must be double escaped; otherwise, the request will fail due to invalid syntax.
// https://docs.microsoft.com/en-us/graph/query-parameters#escaping-single-quotes
func EscapeSingleQuote(qparam string) string {
	return strings.ReplaceAll(qparam, `'`, `''`)
}

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
	client      *msgraph.GraphServiceClient
	limiter     *rate.Limiter
	isDelegated bool
}

var (
	applicationScopes = []string{
		"https://graph.microsoft.com/.default",
	}
	delegatedScopes = []string{
		"https://graph.microsoft.com/Mail.ReadWrite",
		// "https://graph.microsoft.com/Mail.Send",
		"https://graph.microsoft.com/MailboxFolder.ReadWrite",
		"https://graph.microsoft.com/User.ReadBasic.all",
	}
)

func NewGraphMailClient(
	ctx context.Context,
	tenantID, clientID, clientSecret, redirectURI string,
) (GraphMailClient, []User, error) {
	logger := zlog.SFromContext(ctx)
	cache, err := cache.New(nil)
	if err != nil {
		return GraphMailClient{}, nil, err
	}

	var cred azcore.TokenCredential
	var scopes []string
	var isDelegated bool
	var users []User
	if isDelegated = clientSecret == ""; isDelegated {
		cred, err = azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
			ClientID: clientID, TenantID: tenantID, Cache: cache,
		})
		scopes = delegatedScopes
	} else {
		cred, err = azidentity.NewClientSecretCredential(
			tenantID, clientID, clientSecret,
			&azidentity.ClientSecretCredentialOptions{Cache: cache},
		)
		scopes = applicationScopes
	}
	if err != nil {
		return GraphMailClient{}, nil, fmt.Errorf("azidentity: %w", err)
	}

	client, err := msgraph.NewGraphServiceClientWithCredentials(
		cred, scopes)
	if err != nil {
		return GraphMailClient{}, nil, fmt.Errorf("NewGraphServiceClientWithCredentials: %w", err)
	}

	if isDelegated {
		me, err := client.Me().Get(ctx, nil)
		if err != nil {
			return GraphMailClient{}, nil, fmt.Errorf("Me: %w", err)
		}
		logger.Info("got", "me", JSON{me})
		if len(users) == 0 {
			users = []User{me}
		}
	}
	cl := GraphMailClient{
		client:      client,
		limiter:     rate.NewLimiter(24, 1),
		isDelegated: isDelegated,
	}
	if len(users) == 0 {
		if _, err := cl.Users(ctx); err != nil {
			return GraphMailClient{}, users, fmt.Errorf("Users: %w", err)
		}
	}

	return cl, users, nil
}
func (g GraphMailClient) SetLimit(limit rate.Limit) { g.limiter.SetLimit(limit) }

func (g GraphMailClient) Users(ctx context.Context) ([]User, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	coll, err := g.client.Users().Get(ctx, nil)
	if err != nil {
		logger := zlog.SFromContext(ctx)
		logger.Error("get users", "error", err)
		panic(err)
		if !g.isDelegated {
			return nil, err
		}
		if u, meErr := g.client.Me().Get(ctx, nil); meErr != nil {
			logger.Error("users.Me", "error", err)
			return nil, fmt.Errorf("Users.Get: %w (me: %w)", err, meErr)
		} else {
			return []User{u}, nil
		}
	}
	users := make([]User, 0, 10)
	it, err := msgraphcore.NewPageIterator[User](coll, g.client.GetAdapter(),
		models.CreateUserCollectionResponseFromDiscriminatorValue)
	err = it.Iterate(ctx, func(u User) bool {
		users = append(users, u)
		return true
	})
	return users, err
}

func (g GraphMailClient) UpdateMessage(ctx context.Context, userID, messageID string, update Message) (Message, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	msg, err := g.user(userID).
		Messages().ByMessageId(messageID).
		Patch(ctx, update, nil)
	if err != nil {
		return nil, fmt.Errorf("UpdateMessage(%q): [%d] - %w", update, err)
	}
	return msg, err
}

func (g GraphMailClient) GetMIMEMessage(ctx context.Context, userID, messageID string) ([]byte, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	// https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0&tabs=go#example-4-get-mime-content
	msg, err := g.user(userID).
		Messages().ByMessageId(messageID).
		Content().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("GetMIMEMessage(%q): [%d] - %w", err)
	}
	return msg, nil
}

func (g GraphMailClient) GetMessage(ctx context.Context, userID, messageID string, query Query) (models.Messageable, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	var conf *users.ItemMessagesMessageItemRequestBuilderGetRequestConfiguration
	if !query.IsZero() {
		conf = &users.ItemMessagesMessageItemRequestBuilderGetRequestConfiguration{
			QueryParameters: &users.ItemMessagesMessageItemRequestBuilderGetQueryParameters{Select: query.Select},
		}
	}
	return g.user(userID).Messages().ByMessageId(messageID).Get(ctx, conf)
}

func (g GraphMailClient) GetMessageHeaders(ctx context.Context, userID, messageID string) (map[string][]string, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	msg, err := g.user(userID).Messages().ByMessageId(messageID).Get(ctx,
		&users.ItemMessagesMessageItemRequestBuilderGetRequestConfiguration{
			QueryParameters: &users.ItemMessagesMessageItemRequestBuilderGetQueryParameters{
				Select: []string{"internetMessageHeaders"},
			},
		})
	if err != nil {
		return nil, err
	}
	hdrs := msg.GetInternetMessageHeaders()
	m := make(map[string][]string, len(hdrs))
	for _, kv := range hdrs {
		if k, v := kv.GetName(), kv.GetValue(); k != nil && v != nil {
			m[*k] = append(m[*k], *v)
		}
	}
	return m, nil
}

type Query struct {
	Select, OrderBy []string
	Filter, Search  string
}

func (q Query) IsZero() bool { return len(q.Select) == 0 && q.Search == "" && q.Filter == "" }

var requestTop = int32(64)

func (g GraphMailClient) ListMessages(ctx context.Context, userID, folderID string, query Query) ([]Message, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	qp := users.ItemMailFoldersItemMessagesRequestBuilderGetQueryParameters{
		Top: &requestTop,
	}
	if !query.IsZero() {
		qp.Select = query.Select
		qp.Orderby = query.OrderBy
		if query.Filter != "" {
			qp.Filter = &query.Filter
		}
		if query.Search != "" {
			qp.Search = &query.Search
		}
	}
	resp, err := g.user(userID).
		MailFolders().ByMailFolderId(folderID).
		Messages().Get(ctx,
		&users.ItemMailFoldersItemMessagesRequestBuilderGetRequestConfiguration{
			QueryParameters: &qp,
		})
	if err != nil {
		return nil, err
	}
	msgs := make([]Message, 0, requestTop)
	it, err := msgraphcore.NewPageIterator[Message](resp, g.client.GetAdapter(),
		models.CreateMessageCollectionResponseFromDiscriminatorValue)
	err = it.Iterate(ctx, func(m Message) bool {
		msgs = append(msgs, m)
		return true
	})
	return msgs, err
}

func (g GraphMailClient) CreateFolder(ctx context.Context, userID, displayName string) (Folder, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	f := models.NewMailFolder()
	f.SetDisplayName(&displayName)
	return g.user(userID).MailFolders().Post(ctx, f, nil)
}

func (g GraphMailClient) CreateChildFolder(ctx context.Context, userID, parentID, displayName string) (Folder, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	f := models.NewMailFolder()
	f.SetParentFolderId(&parentID)
	f.SetDisplayName(&displayName)
	return g.user(userID).MailFolders().Post(ctx, f, nil)
}

func (g GraphMailClient) CreateMessage(ctx context.Context, userID, folderID string, msg Message) (Message, error) {
	msg.SetParentFolderId(&folderID)
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	return g.user(userID).Messages().Post(ctx, msg, nil)
}

func (g GraphMailClient) CopyMessage(ctx context.Context, userID, srcFolderID, msgID, destFolderID string) (Message, error) {
	return g.copyOrMoveMessage(ctx, userID, srcFolderID, msgID, destFolderID, false)
}
func (g GraphMailClient) MoveMessage(ctx context.Context, userID, srcFolderID, msgID, destFolderID string) (Message, error) {
	return g.copyOrMoveMessage(ctx, userID, srcFolderID, msgID, destFolderID, true)
}
func (g GraphMailClient) copyOrMoveMessage(ctx context.Context, userID, srcFolderID, msgID, destFolderID string, move bool) (Message, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if move {
		body := users.NewItemMessagesItemMovePostRequestBody()
		body.SetDestinationId(&destFolderID)
		return g.user(userID).Messages().ByMessageId(msgID).Move().Post(ctx, body, nil)
	}
	body := users.NewItemMessagesItemCopyPostRequestBody()
	body.SetDestinationId(&destFolderID)
	return g.user(userID).Messages().ByMessageId(msgID).Copy().Post(ctx, body, nil)
}

func (g GraphMailClient) RenameFolder(ctx context.Context, userID, folderID, displayName string) error {
	return errors.ErrUnsupported
}

func (g GraphMailClient) DeleteFolder(ctx context.Context, userID, folderID string) error {
	if err := g.limiter.Wait(ctx); err != nil {
		return err
	}
	return g.user(userID).MailFolders().ByMailFolderId(folderID).Delete(ctx, nil)
}

func (g GraphMailClient) DeleteChildFolder(ctx context.Context, userID, parentID, folderID string) error {
	if err := g.limiter.Wait(ctx); err != nil {
		return err
	}
	return g.user(userID).MailFolders().ByMailFolderId(parentID).ChildFolders().ByMailFolderId1(folderID).Delete(ctx, nil)
}

func (g GraphMailClient) DeleteMessage(ctx context.Context, userID, folderID, msgID string) error {
	if err := g.limiter.Wait(ctx); err != nil {
		return err
	}
	return g.user(userID).MailFolders().ByMailFolderId(folderID).Messages().ByMessageId(msgID).Delete(ctx, nil)
}

func NewFlag(flagged bool) models.FollowupFlagable {
	f := models.NewFollowupFlag()
	if flagged {
		i := models.FLAGGED_FOLLOWUPFLAGSTATUS
		f.SetFlagStatus(&i)
	}
	return f
}
func NewRecipient(name, email string) Recipient {
	r := models.NewRecipient()
	var a models.EmailAddressable
	if name != "" {
		if a == nil {
			a = models.NewEmailAddress()
		}
		a.SetName(&name)
	}
	if email != "" {
		if a == nil {
			a = models.NewEmailAddress()
		}
		a.SetAddress(&email)
	}
	if a != nil {
		r.SetEmailAddress(a)
	}
	return r
}

func NewMessage() Message { return models.NewMessage() }

var ErrNotFound = errors.New("not found")

func (g GraphMailClient) GetFolder(ctx context.Context, displayName string) (Folder, error) {
	if _, ok := WellKnownFolders[displayName]; ok {
		f, err := g.user("").MailFolders().ByMailFolderId(displayName).Get(ctx, nil)
		if err != nil {
			err = fmt.Errorf("%w: byMailFolderId(%s): %w", ErrNotFound, displayName, err)
		} else if f.GetId() == nil {
			f.SetId(&displayName)
		}
		return f, err
	}
	f := models.NewMailFolder()
	if displayName != "" {
		f.SetDisplayName(&displayName)
	}
	return f, nil
}
func NewBody(contentType string, content string) models.ItemBodyable {
	body := models.NewItemBody()
	var bt models.BodyType
	if strings.HasPrefix(contentType, "text/html") {
		bt = models.HTML_BODYTYPE
	} else {
		bt = models.TEXT_BODYTYPE
	}
	body.SetContentType(&bt)
	body.SetContent(&content)
	return body
}

// type imh struct {
// 	Name  string `json:"name"`
// 	Value string `json:"value"`
// }

// type Message struct {
// 	Created        time.Time      `json:"createdDateTime,omitempty"`
// 	Modified       time.Time      `json:"lastModifiedDateTime,omitempty"`
// 	Received       time.Time      `json:"receivedDateTime,omitempty"`
// 	Sent           time.Time      `json:"sentDateTime,omitempty"`
// 	Body           Content        `json:"body,omitempty"`
// 	Sender         EmailAddress   `json:"sender,omitempty"`
// 	From           EmailAddress   `json:"from,omitempty"`
// 	UniqueBody     Content        `json:"uniqueBody,omitempty"`
// 	ReplyTo        []EmailAddress `json:"replyTo,omitempty"`
// 	ID             string         `json:"id,omitempty"`
// 	Subject        string         `json:"subject,omitempty"`
// 	BodyPreview    string         `json:"bodyPreview,omitempty"`
// 	ChangeKey      string         `json:"changeKey,omitempty"`
// 	ConversationID string         `json:"conversationId,omitempty"`
// 	Flag           struct {
// 		Status string `json:"flagStatus,omitempty"`
// 	} `json:"flag,omitempty"`
// 	Importance     string         `json:"importance,omitempty"`
// 	MessageID      string         `json:"internetMessageId,omitempty"`
// 	FolderID       string         `json:"parentFolderId,omitempty"`
// 	WebLink        string         `json:"webLink,omitempty"`
// 	To             []EmailAddress `json:"toRecipients,omitempty"`
// 	Cc             []EmailAddress `json:"bccRecipients,omitempty"`
// 	Bcc            []EmailAddress `json:"ccRecipients,omitempty"`
// 	Headers        []imh          `json:"internetMessageHeaders,omitempty"`
// 	HasAttachments bool           `json:"hasAttachments,omitempty"`
// 	Draft          bool           `json:"isDraft",omitempty`
// 	Read           bool           `json:"isRead,omitempty"`
// }
// type Content struct {
// 	ContentType string `json:"contentType"`
// 	Content     string `json:"content"`
// }
// type EmailAddress struct {
// 	Name    string `json:"name"`
// 	Address string `json:"address"`
// }

func (g GraphMailClient) ListChildFolders(ctx context.Context, userID, folderID string, recursive bool, query Query) ([]Folder, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	conf := users.ItemMailFoldersItemChildFoldersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.ItemMailFoldersItemChildFoldersRequestBuilderGetQueryParameters{
			Top: &requestTop,
		},
	}
	resp, err := g.user(userID).MailFolders().ByMailFolderId(folderID).ChildFolders().Get(ctx, &conf)
	if err != nil {
		return nil, err
	}
	folders := make([]Folder, 0, requestTop)
	it, err := msgraphcore.NewPageIterator[Folder](resp, g.client.GetAdapter(),
		models.CreateMailFolderCollectionResponseFromDiscriminatorValue)
	err = it.Iterate(ctx, func(f Folder) bool {
		folders = append(folders, f)
		return true
	})

	return folders, err
}

func (g GraphMailClient) ListMailFolders(ctx context.Context, userID string, query Query) ([]Folder, error) {
	if err := g.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	conf := users.ItemMailFoldersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.ItemMailFoldersRequestBuilderGetQueryParameters{
			Top: &requestTop,
		},
	}
	if !query.IsZero() {
		conf.QueryParameters.Select = query.Select
		if query.Filter != "" {
			conf.QueryParameters.Filter = &query.Filter
		}
	}
	resp, err := g.user(userID).MailFolders().Get(ctx, &conf)
	if err != nil {
		return nil, fmt.Errorf("ListMailFolders(%s, %v): %w", userID, query, err)
	}
	folders := make([]Folder, 0, requestTop)
	it, err := msgraphcore.NewPageIterator[Folder](resp, g.client.GetAdapter(),
		models.CreateMailFolderCollectionResponseFromDiscriminatorValue)
	err = it.Iterate(ctx, func(f Folder) bool {
		folders = append(folders, f)
		return true
	})
	return folders, err
}

func (g GraphMailClient) user(userID string) *users.UserItemRequestBuilder {
	if userID == "" || g.isDelegated {
		return g.client.Me()
	}
	return g.client.Users().ByUserId(userID)
}

type JSON struct {
	serialization.Parsable
}

func (j JSON) String() string               { v, _ := serialization.SerializeToJson(j.Parsable); return string(v) }
func (j JSON) MarshalJSON() ([]byte, error) { return serialization.SerializeToJson(j.Parsable) }
