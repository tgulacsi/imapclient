// Package o365 implements an imap client, using Office 365 Mail REST API.
package o365

import (
	"encoding/json"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/pkg/errors"
	"github.com/tgulacsi/oauth2client"
)

var Log = func(keyvals ...interface{}) error {
	log.Println(keyvals...)
	return nil
}

const baseURL = "https://outlook.office.com/api/v2.0/me"

type client struct {
	*oauth2.Config
	oauth2.TokenSource
}

func NewClient(clientID, clientSecret, redirectURL string) *client {
	if redirectURL == "" {
		redirectURL = "http://localhost:8123"
	}
	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"https://outlook.office.com/mail.read"},
		Endpoint:     oauth2client.AzureV2Endpoint,
	}

	return &client{
		Config: conf,
		TokenSource: oauth2client.NewTokenSource(
			conf,
			filepath.Join(os.Getenv("HOME"), ".config", "o365.conf")),
	}
}

type Attachment struct {
	// The MIME type of the attachment.
	ContentType string
	// true if the attachment is an inline attachment; otherwise, false.
	IsInline bool
	// The date and time when the attachment was last modified. The date and time use ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'
	LastModifiedDateTime time.Time
	// The display name of the attachment. This does not need to be the actual file name.
	Name string
	// The length of the attachment in bytes.
	Size int32
}

type Recipient struct {
	EmailAddress EmailAddress
}

type EmailAddress struct {
	Name, Address string
}

type ItemBody struct {
	// The content type: Text = 0, HTML = 1.
	ContentType uint8
	// The text or HTML content.
	Content string
}

type Importance uint8
type InferenceClassificationType string
type SingleValueLegacyExtendedProperty struct {
	// A property values.
	Value string
	// The property ID. This is used to identify the property.
	PropertyID string `json:"PropertyId"`
}
type MultiValueLegacyExtendedProperty struct {
	// A collection of property values.
	Value []string
	// The property ID. This is used to identify the property.
	PropertyID string `json:"PropertyId"`
}

type Message struct {
	// The FileAttachment and ItemAttachment attachments for the message. Navigation property.
	Attachments []Attachment
	// The Bcc recipients for the message.
	BccRecipients []Recipient
	// The body of the message.
	Body ItemBody
	// The first 255 characters of the message body content.
	BodyPreview string
	// The categories associated with the message.
	Categories []string
	// The Cc recipients for the message.
	CcRecipients []Recipient
	// The version of the message.
	ChangeKey string
	// The ID of the conversation the email belongs to.
	ConversationID string `json:"ConversationId"`
	// The date and time the message was created.
	CreatedDateTime time.Time
	// The collection of open type data extensions defined for the message. Navigation property.
	Extensions []string
	// The mailbox owner and sender of the message.
	From Recipient
	// Indicates whether the message has attachments.
	HasAttachments bool
	// The unique identifier of the message.
	ID string `json:"Id"`
	// The importance of the message: Low = 0, Normal = 1, High = 2.
	Importance Importance
	// The classification of this message for the user, based on inferred relevance or importance, or on an explicit override.
	InferenceClassification InferenceClassificationType
	// Indicates whether a read receipt is requested for the message.
	IsDeliveryReceiptRequested bool
	// Indicates whether the message is a draft. A message is a draft if it hasn't been sent yet.
	IsDraft bool
	// Indicates whether the message has been read.
	IsRead bool
	// Indicates whether a read receipt is requested for the message.
	IsReadReceiptRequested bool
	// The date and time the message was last changed.
	LastModifiedDateTime time.Time
	// A collection of multi-value extended properties of type MultiValueLegacyExtendedProperty. This is a navigation property. Find more information about extended properties.
	MultiValueExtendedProperties MultiValueLegacyExtendedProperty
	// The unique identifier for the message's parent folder.
	ParentFolderID string `json:"ParentFolderId"`
	// The date and time the message was received.
	ReceivedDateTime time.Time
	// The email addresses to use when replying.
	ReplyTo []Recipient
	// The account that is actually used to generate the message.
	Sender Recipient
	// A collection of single-value extended properties of type SingleValueLegacyExtendedProperty. This is a navigation property. Find more information about extended properties.
	SingleValueExtendedProperties SingleValueLegacyExtendedProperty
	// The date and time the message was sent.
	SentDateTime time.Time
	// The subject of the message.
	Subject string
	// The To recipients for the message.
	ToRecipients []Recipient
	// The body of the message that is unique to the conversation.
	UniqueBody ItemBody
	// The URL to open the message in Outlook Web App.
	// You can append an ispopout argument to the end of the URL to change how the message is displayed. If ispopout is not present or if it is set to 1, then the message is shown in a popout window. If ispopout is set to 0, then the browser will show the message in the Outlook Web App review pane.
	// The message will open in the browser if you are logged in to your mailbox via Outlook Web App. You will be prompted to login if you are not already logged in with the browser.
	// This URL can be accessed from within an iFrame.
	WebLink string
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

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := c.get(ctx, path+"?"+values.Encode())
	if err != nil {
		return nil, err
	}
	defer body.Close()

	type listResponse struct {
		Value []Message `json:"value"`
	}
	var resp listResponse
	err = json.NewDecoder(body).Decode(&resp)
	return resp.Value, err
}

func (c *client) get(ctx context.Context, path string) (io.ReadCloser, error) {
	Log("get", baseURL+path)
	resp, err := oauth2.NewClient(ctx, c.TokenSource).Get(baseURL + path)
	if err != nil {
		return nil, errors.Wrap(err, path)
	}
	return resp.Body, nil
}
