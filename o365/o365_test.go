package o365

import (
	"context"
	"os"
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
	for i, m := range messages {
		t.Logf("%d. %#v", i, m)
	}
}
