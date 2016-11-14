package o365

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

var clientID, clientSecret = os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET")

func TestList(t *testing.T) {
	cl := NewClient(clientID, clientSecret, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	messages, err := cl.List(ctx, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for i, m := range messages {
		t.Logf("%d. %#v", i, m)
		id = m.ID
	}

	msg, err := cl.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%q: %#v", id, msg)
}

func TestSend(t *testing.T) {
	cl := NewClient(clientID, clientSecret, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cl.Send(ctx,
		Message{
			Subject: "test",
			Body:    ItemBody{ContentType: "Text", Content: "test"},
			To:      []Recipient{Recipient{EmailAddress{Address: "tgulacsi78@gmail.com"}}},
		},
	); err != nil {
		if strings.Contains(err.Error(), "Forbidden") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
}
