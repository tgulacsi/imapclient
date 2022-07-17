// Copyright 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package o365 implements an imap client, using Office 365 Mail REST API.
package o365

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/tgulacsi/oauth2client"
)

var Log = func(keyvals ...interface{}) error {
	log.Println(keyvals...)
	return nil
}

const baseURL = "https://outlook.office.com/api/v2.0"

type client struct {
	*oauth2.Config
	oauth2.TokenSource
	Me string
}

type clientOptions struct {
	TokensFile              string
	TLSCertFile, TLSKeyFile string
	Impersonate             string
	ReadOnly                bool
}
type ClientOption func(*clientOptions)

func ReadOnly(readOnly bool) ClientOption { return func(o *clientOptions) { o.ReadOnly = readOnly } }
func TokensFile(file string) ClientOption { return func(o *clientOptions) { o.TokensFile = file } }
func TLS(certFile, keyFile string) ClientOption {
	return func(o *clientOptions) { o.TLSCertFile, o.TLSKeyFile = certFile, keyFile }
}
func Impersonate(email string) ClientOption { return func(o *clientOptions) { o.Impersonate = email } }

func NewClient(clientID, clientSecret, redirectURL string, options ...ClientOption) *client {
	if clientID == "" || clientSecret == "" {
		panic("clientID and clientSecret is a must!")
	}
	if redirectURL == "" {
		redirectURL = "http://localhost:8123"
	}
	var opts clientOptions
	for _, f := range options {
		f(&opts)
	}
	var sWrite string
	if !opts.ReadOnly {
		sWrite = "write"
	}
	if opts.TLSCertFile != "" && opts.TLSKeyFile != "" && strings.HasPrefix(redirectURL, "http://") {
		redirectURL = "https" + redirectURL[4:]
	}

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://outlook.office.com/mail.read" + sWrite,
			"offline_access",
		},
		Endpoint: oauth2client.AzureV2Endpoint,
	}

	tokensFile := opts.TokensFile
	if tokensFile == "" {
		tokensFile = filepath.Join(os.Getenv("HOME"), ".config", "o365.conf")
	}
	if opts.Impersonate == "" {
		opts.Impersonate = "me"
	}
	return &client{
		Config:      conf,
		Me:          opts.Impersonate,
		TokenSource: oauth2client.NewTokenSource(conf, tokensFile, opts.TLSCertFile, opts.TLSKeyFile),
	}
}

type Attachment struct {
	// The date and time when the attachment was last modified. The date and time use ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'
	LastModifiedDateTime time.Time `json:",omitempty"`
	// The MIME type of the attachment.
	ContentType string `json:",omitempty"`
	// The display name of the attachment. This does not need to be the actual file name.
	Name string `json:",omitempty"`
	// The length of the attachment in bytes.
	Size int32 `json:",omitempty"`
	// true if the attachment is an inline attachment; otherwise, false.
	IsInline bool `json:",omitempty"`
}

type Recipient struct {
	EmailAddress EmailAddress `json:",omitempty"`
}

type EmailAddress struct {
	Name, Address string `json:",omitempty"`
}

type ItemBody struct {
	// The content type: Text = 0, HTML = 1.
	ContentType string `json:",omitempty"`
	// The text or HTML content.
	Content string `json:",omitempty"`
}

type Importance string
type InferenceClassificationType string
type SingleValueLegacyExtendedProperty struct {
	// The property ID. This is used to identify the property.
	PropertyID string `json:"PropertyId,omitempty"`
	// A property values.
	Value string `json:",omitempty"`
}
type MultiValueLegacyExtendedProperty struct {
	// The property ID. This is used to identify the property.
	PropertyID string `json:"PropertyId,omitempty"`
	// A collection of property values.
	Value []string `json:",omitempty"`
}

// https://msdn.microsoft.com/en-us/office/office365/api/complex-types-for-mail-contacts-calendar#MessageResource
// The fields last word designates the Writable/Filterable/Searchable property of the field.
type Message struct {
	// The date and time the message was created.
	// -F-
	Created *time.Time `json:"CreatedDateTime,omitempty"`
	// The date and time the message was last changed.
	// -F-
	LastModified *time.Time `json:"LastModifiedDateTime,omitempty"`
	// The date and time the message was sent.
	// -F-
	Sent *time.Time `json:"SentDateTime,omitempty"`
	// The date and time the message was received.
	// -FS
	Received *time.Time `json:"ReceivedDateTime,omitempty"`
	// A collection of multi-value extended properties of type MultiValueLegacyExtendedProperty. This is a navigation property. Find more information about extended properties.
	// WF-
	MultiValueExtendedProperties *MultiValueLegacyExtendedProperty `json:",omitempty"`
	// A collection of single-value extended properties of type SingleValueLegacyExtendedProperty. This is a navigation property. Find more information about extended properties.
	// WF-
	SingleValueExtendedProperties *SingleValueLegacyExtendedProperty `json:",omitempty"`
	// The mailbox owner and sender of the message.
	// WFS
	From *Recipient `json:",omitempty"`
	// The account that is actually used to generate the message.
	// WF-
	Sender *Recipient `json:",omitempty"`
	// The body of the message that is unique to the conversation.
	// ---
	UniqueBody *ItemBody `json:",omitempty"`
	// The body of the message.
	// W--
	Body ItemBody `json:",omitempty"`
	// The importance of the message: Low = 0, Normal = 1, High = 2.
	// WFS
	Importance Importance `json:",omitempty"`

	// The classification of this message for the user, based on inferred relevance or importance, or on an explicit override.
	// WFS
	InferenceClassification InferenceClassificationType `json:",omitempty"`
	// The version of the message.
	// ---
	ChangeKey string `json:",omitempty"`
	// The ID of the conversation the email belongs to.
	// -F-
	ConversationID string `json:"ConversationId,omitempty"`
	// The unique identifier of the message.
	// ---
	ID string `json:"Id,omitempty"`
	// The unique identifier for the message's parent folder.
	// ---
	ParentFolderID string `json:"ParentFolderId,omitempty"`
	// The subject of the message.
	// WF-
	Subject string `json:",omitempty"`
	// The URL to open the message in Outlook Web App.
	// You can append an ispopout argument to the end of the URL to change how the message is displayed. If ispopout is not present or if it is set to 1, then the message is shown in a popout window. If ispopout is set to 0, then the browser will show the message in the Outlook Web App review pane.
	// The message will open in the browser if you are logged in to your mailbox via Outlook Web App. You will be prompted to login if you are not already logged in with the browser.
	// This URL can be accessed from within an iFrame.
	// -F-
	WebLink string `json:",omitempty"`
	// The first 255 characters of the message body content.
	// --S
	BodyPreview string `json:",omitempty"`

	// The Bcc recipients for the message.
	// W-S
	Bcc []Recipient `json:"BccRecipients,omitempty"`
	// The email addresses to use when replying.
	// ---
	ReplyTo []Recipient `json:",omitempty"`
	// The To recipients for the message.
	// W-S
	To []Recipient `json:"ToRecipients,omitempty"`
	// The Cc recipients for the message.
	// W-S
	Cc []Recipient `json:"CcRecipients,omitempty"`

	// The FileAttachment and ItemAttachment attachments for the message. Navigation property.
	// W-S
	Attachments []Attachment `json:",omitempty"`

	// The categories associated with the message.
	// WFS
	Categories []string `json:",omitempty"`
	// The collection of open type data extensions defined for the message. Navigation property.
	// -F-
	Extensions []string `json:",omitempty"`

	// Indicates whether the message has attachments.
	// -FS
	HasAttachments bool `json:",omitempty"`
	// Indicates whether a read receipt is requested for the message.
	// WF-
	IsDeliveryReceiptRequested bool `json:",omitempty"`
	// Indicates whether the message is a draft. A message is a draft if it hasn't been sent yet.
	// -F-
	IsDraft bool `json:",omitempty"`
	// Indicates whether the message has been read.
	// WF-
	IsRead bool `json:",omitempty"`
	// Indicates whether a read receipt is requested for the message.
	// WF-
	IsReadReceiptRequested bool `json:",omitempty"`
}

func (c *client) List(ctx context.Context, mbox, pattern string, all bool) ([]Message, error) {
	path := "/messages"
	if mbox != "" {
		path = "/MailFolders/" + mbox + "/messages"
	}

	values := url.Values{
		"$select": {"Sender,Subject"},
	}
	if pattern != "" {
		values.Set("$search", `"subject:`+pattern+`"`)
	}
	if !all {
		values.Set("$filter", "IsRead eq false")
	}

	body, err := c.get(ctx, path+"?"+values.Encode())
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(io.Discard, body)
		body.Close()
	}()

	type listResponse struct {
		Value []Message `json:"value"`
	}
	var resp listResponse
	err = json.NewDecoder(body).Decode(&resp)
	return resp.Value, err
}

func (c *client) Get(ctx context.Context, msgID string) (Message, error) {
	path := "/messages/" + msgID
	var msg Message
	body, err := c.get(ctx, path)
	if err != nil {
		return msg, err
	}
	defer func() {
		io.Copy(io.Discard, body)
		body.Close()
	}()
	err = json.NewDecoder(body).Decode(&msg)
	return msg, err
}

func (c *client) Send(ctx context.Context, msg Message) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(struct {
		Message Message
	}{Message: msg}); err != nil {
		return fmt.Errorf("encode %#v: %w", msg, err)
	}
	path := "/sendmail"
	return c.post(ctx, path, bytes.NewReader(buf.Bytes()))
}

func (c *client) post(ctx context.Context, path string, body io.Reader) error {
	rc, err := c.p(ctx, "POST", path, body)
	if rc != nil {
		rc.Close()
	}
	return err
}
func (c *client) p(ctx context.Context, method, path string, body io.Reader) (io.ReadCloser, error) {
	if method == "" {
		method = "POST"
	}
	var buf bytes.Buffer
	req, err := http.NewRequest(method, c.URLFor(path), io.TeeReader(body, &buf))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	resp, err := oauth2.NewClient(ctx, c.TokenSource).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", buf.String(), err)
	}
	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		io.Copy(&buf, body)
		io.WriteString(&buf, "\n\n")
		io.Copy(&buf, resp.Body)
		return nil, fmt.Errorf("POST %q: %s\n%s", path, resp.Status, buf.Bytes())
	}
	return resp.Body, nil
}

func (c *client) Delete(ctx context.Context, msgID string) error {
	return c.delete(ctx, "/messages/"+msgID)
}

func (c *client) Move(ctx context.Context, msgID, destinationID string) error {
	return c.post(ctx, "/messages/"+msgID+"/move", bytes.NewReader(jsonObj("DestinationId", destinationID)))
}
func (c *client) Copy(ctx context.Context, msgID, destinationID string) error {
	return c.post(ctx, "/messages/"+msgID+"/copy", bytes.NewReader(jsonObj("DestinationId", destinationID)))
}

func (c *client) Update(ctx context.Context, msgID string, upd map[string]interface{}) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(upd); err != nil {
		return fmt.Errorf("%#v: %w", upd, err)
	}
	body, err := c.p(ctx, "PATCH", "/messages/"+msgID, bytes.NewReader(buf.Bytes()))
	if body != nil {
		body.Close()
	}
	if err != nil {
		return fmt.Errorf("%#v: %w", upd, err)
	}
	return nil
}

type Folder struct {
	ID          string `json:"Id"`
	Name        string `json:"DisplayName"`
	ParentID    string `json:"ParentFolderId,omitempty"`
	ChildCount  uint32 `json:"ChildFolderCount,omitempty"`
	UnreadCount uint32 `json:"UnreadItemCount,omitempty"`
	TotalCount  uint32 `json:"TotalItemCount,omitempty"`
}

func (c *client) ListFolders(ctx context.Context, parent string) ([]Folder, error) {
	path := "/MailFolders"
	if parent != "" {
		path += "/" + parent + "/childfolders"
	}
	body, err := c.get(ctx, path)
	if body != nil {
		defer func() {
			io.Copy(io.Discard, body)
			body.Close()
		}()
	}
	if err != nil {
		return nil, err
	}

	type folderList struct {
		Value []Folder `json:"value"`
	}
	var resp folderList
	err = json.NewDecoder(body).Decode(&resp)
	return resp.Value, err
}

func (c *client) CreateFolder(ctx context.Context, parent, folder string) error {
	return c.post(ctx, "/MailFolders/"+parent+"/childfolders", bytes.NewReader(jsonObj("DisplayName", folder)))
}

func (c *client) RenameFolder(ctx context.Context, folderID, newName string) error {
	return c.post(ctx, "/MailFolders/"+folderID, bytes.NewReader(jsonObj("DisplayName", newName)))
}
func (c *client) MoveFolder(ctx context.Context, folderID, destinationID string) error {
	return c.post(ctx, "/MailFolders/"+folderID+"/move", bytes.NewReader(jsonObj("DestinationId", destinationID)))
}
func (c *client) CopyFolder(ctx context.Context, folderID, destinationID string) error {
	return c.post(ctx, "/MailFolders/"+folderID+"/copy", bytes.NewReader(jsonObj("DestinationId", destinationID)))
}

func (c *client) DeleteFolder(ctx context.Context, folderID string) error {
	return c.delete(ctx, "/MailFolders/"+folderID)
}

func (c *client) URLFor(path string) string { return baseURL + "/" + c.Me + path }
func (c *client) get(ctx context.Context, path string) (io.ReadCloser, error) {
	URL := c.URLFor(path)
	Log("get", URL)
	resp, err := oauth2.NewClient(ctx, c.TokenSource).Get(URL)
	Log("resp", resp, "error", err)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return resp.Body, nil
}

func (c *client) delete(ctx context.Context, path string) error {
	req, err := http.NewRequest("DELETE", c.URLFor(path), nil)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	resp, err := oauth2.NewClient(ctx, c.TokenSource).Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", req.URL.String(), err)
	}
	if resp.StatusCode > 299 {
		return fmt.Errorf("DELETE %q: %s", path, resp.Status)
	}
	return nil
}

func jsonObj(key, value string) []byte {
	b, err := json.Marshal(map[string]string{key: value})
	if err != nil {
		panic(err)
	}
	return b
}
