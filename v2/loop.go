// Copyright 2017, 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package imapclient

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/tgulacsi/go/temp"
)

var (
	// ShortSleep is the duration which ised for sleep after successful delivery.
	ShortSleep = 1 * time.Second
	// LongSleep is the duration which used for sleep between errors and if the inbox is empty.
	LongSleep = 5 * time.Minute

	// ErrSkip from DeliverFunc means leave the message as is.
	ErrSkip = errors.New("skip move")
)

// DeliveryLoop periodically checks the inbox for mails with the specified pattern
// in the subject (or for any unseen mail if pattern == ""), tries to parse the
// message, and call the deliver function with the parsed message.
//
// If deliver did not returned error, the message is marked as Seen, and if outbox
// is not empty, then moved to outbox.
// Except when the error is ErrSkip - then the message is left there as is.
//
// deliver is called with the message, UID and sha1.
func DeliveryLoop(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFunc, outbox, errbox string, logger log.Logger) error {
	if inbox == "" {
		inbox = "INBOX"
	}
	for {
		n, err := one(ctx, c, inbox, pattern, deliver, outbox, errbox, logger)
		if err != nil {
			logger.Log("msg", "DeliveryLoop one round", "count", n, "error", err)
		} else {
			logger.Log("msg", "DeliveryLoop one round", "count", n)
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		dur := ShortSleep
		if n == 0 || err != nil {
			dur = LongSleep
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(dur):
		}
	}
}

func MkDeliverFunc(ctx context.Context, deliver DeliverFunc) DeliverFunc {
	return func(ctx context.Context, r io.ReadSeeker, uid uint32, sha1 []byte) error {
		return deliver(ctx, r, uid, sha1)
	}
}

// DeliverOne does one round of message reading and delivery. Does not loop.
// Returns the number of messages delivered.
func DeliverOne(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFunc, outbox, errbox string, logger log.Logger) (int, error) {
	if inbox == "" {
		inbox = "INBOX"
	}
	return one(ctx, c, inbox, pattern, deliver, outbox, errbox, logger)
}

// DeliverFunc is the type for message delivery.
//
// r is the message data, uid is the IMAP server sent message UID, sha1 is the message's sha1 hash.
type DeliverFunc func(ctx context.Context, r io.ReadSeeker, uid uint32, sha1 []byte) error

func one(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFunc, outbox, errbox string, logger log.Logger) (int, error) {
	logger = log.With(logger, "c", c, "inbox", inbox)
	if err := c.Connect(ctx); err != nil {
		logger.Log("msg", "Connecting", "error", err)
		return 0, fmt.Errorf("connect to %v: %w", c, err)
	}
	defer c.Close(ctx, true)

	uids, err := c.List(ctx, inbox, pattern, outbox != "" && errbox != "")
	logger.Log("msg", "List", "uids", uids, "error", err)
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
		hsh.Reset()
		body := temp.NewMemorySlurper(strconv.FormatUint(uint64(uid), 10))
		if _, err = c.ReadTo(ctx, io.MultiWriter(body, hsh), uid); err != nil {
			body.Close()
			Log("msg", "Read", "error", err)
			continue
		}

		err = deliver(ctx, body, uid, hsh.Sum(nil))
		body.Close()
		if err != nil {
			Log("msg", "deliver", "error", err)
			if errbox != "" && !errors.Is(err, ErrSkip) {
				if err = c.Move(ctx, uid, errbox); err != nil {
					Log("msg", "move to", "errbox", errbox, "error", err)
				}
			}
			continue
		}
		n++

		if err = c.Mark(ctx, uid, true); err != nil {
			Log("msg", "mark seen", "error", err)
		}

		if outbox != "" {
			if err = c.Move(ctx, uid, outbox); err != nil {
				Log("msg", "move to", "outbox", outbox, "error", err)
				continue
			}
		}
	}

	return n, nil
}
