/*
Copyright 2017 Tamás Gulácsi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package imapclient

import (
	"crypto/sha1"
	"fmt"
	"io"
	"strconv"
	"time"

	"golang.org/x/net/context"

	"github.com/go-kit/kit/log"
	"github.com/tgulacsi/go/temp"
)

var (
	// ShortSleep is the duration which ised for sleep after successful delivery.
	ShortSleep = 1 * time.Second
	// LongSleep is the duration which used for sleep between errors and if the inbox is empty.
	LongSleep = 5 * time.Minute
)

// DeliveryLoop periodically checks the inbox for mails with the specified pattern
// in the subject (or for any unseen mail if pattern == ""), tries to parse the
// message, and call the deliver function with the parsed message.
//
// If deliver did not returned error, the message is marked as Seen, and if outbox
// is not empty, then moved to outbox.
//
// deliver is called with the message, UID and sha1.
func DeliveryLoop(c Client, inbox, pattern string, deliver DeliverFunc, outbox, errbox string, closeCh <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-closeCh
		cancel()
	}()
	_ = DeliveryLoopC(ctx, c, inbox, pattern, MkDeliverFuncC(ctx, deliver), outbox, errbox)
}

// DeliveryLoopC periodically checks the inbox for mails with the specified pattern
// in the subject (or for any unseen mail if pattern == ""), tries to parse the
// message, and call the deliver function with the parsed message.
//
// If deliver did not returned error, the message is marked as Seen, and if outbox
// is not empty, then moved to outbox.
//
// deliver is called with the message, UID and sha1.
func DeliveryLoopC(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFuncC, outbox, errbox string) error {
	if inbox == "" {
		inbox = "INBOX"
	}
	for {
		n, err := one(ctx, c, inbox, pattern, deliver, outbox, errbox)
		if err != nil {
			Log("msg", "DeliveryLoop one round", "count", n, "error", err)
		} else {
			Log("msg", "DeliveryLoop one round", "count", n)
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if err != nil {
			time.Sleep(LongSleep)
			continue
		}
		if n > 0 {
			time.Sleep(ShortSleep)
		} else {
			time.Sleep(LongSleep)
		}
		continue
	}
}

// DeliverOne does one round of message reading and delivery. Does not loop.
// Returns the number of messages delivered.
func DeliverOne(c Client, inbox, pattern string, deliver DeliverFunc, outbox, errbox string) (int, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return DeliverOneC(ctx, c, inbox, pattern, MkDeliverFuncC(ctx, deliver), outbox, errbox)
}

func MkDeliverFuncC(ctx context.Context, deliver DeliverFunc) DeliverFuncC {
	return func(ctx context.Context, r io.ReadSeeker, uid uint32, sha1 []byte) error {
		return deliver(r, uid, sha1)
	}
}

// DeliverOneC does one round of message reading and delivery. Does not loop.
// Returns the number of messages delivered.
func DeliverOneC(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFuncC, outbox, errbox string) (int, error) {
	if inbox == "" {
		inbox = "INBOX"
	}
	return one(ctx, c, inbox, pattern, deliver, outbox, errbox)
}

// DeliverFunc is the type for message delivery.
//
// r is the message data, uid is the IMAP server sent message UID, sha1 is the message's sha1 hash.
type DeliverFunc func(r io.ReadSeeker, uid uint32, sha1 []byte) error

// DeliverFuncC is the type for message delivery.
//
// r is the message data, uid is the IMAP server sent message UID, sha1 is the message's sha1 hash.
type DeliverFuncC func(ctx context.Context, r io.ReadSeeker, uid uint32, sha1 []byte) error

func one(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFuncC, outbox, errbox string) (int, error) {
	logger := log.With(log.LoggerFunc(GetLog(ctx)), "c", c, "inbox", inbox)
	if err := c.ConnectC(ctx); err != nil {
		Log("msg", "Connecting", "error", err)
		return 0, fmt.Errorf("connect to %v: %w", c, err)
	}
	defer c.Close(true)

	uids, err := c.ListC(ctx, inbox, pattern, outbox != "" && errbox != "")
	Log("msg", "List", "uids", uids, "error", err)
	if err != nil {
		return 0, fmt.Errorf("list %v/%v: %w", c, inbox, err)
	}

	var n int
	hsh := sha1.New()
	for _, uid := range uids {
		if err = ctx.Err(); err != nil {
			return n, err
		}
		Log := log.With(logger, "uid", uid).Log
		ctx := CtxWithLogFunc(context.Background(), Log)
		hsh.Reset()
		body := temp.NewMemorySlurper(strconv.FormatUint(uint64(uid), 10))
		if _, err = c.ReadToC(ctx, io.MultiWriter(body, hsh), uid); err != nil {
			body.Close()
			Log("msg", "Read", "error", err)
			continue
		}

		err = deliver(ctx, body, uid, hsh.Sum(nil))
		body.Close()
		if err != nil {
			Log("msg", "deliver", "error", err)
			if errbox != "" {
				if err = c.MoveC(ctx, uid, errbox); err != nil {
					Log("msg", "move to", "errbox", errbox, "error", err)
				}
			}
			continue
		}
		n++

		if err = c.MarkC(ctx, uid, true); err != nil {
			Log("msg", "mark seen", "error", err)
		}

		if outbox != "" {
			if err = c.MoveC(ctx, uid, outbox); err != nil {
				Log("msg", "move to", "outbox", outbox, "error", err)
				continue
			}
		}
	}

	return n, nil
}
