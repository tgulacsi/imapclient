// Copyright 2017, 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package imapclient

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/UNO-SOFT/zlog/v2"
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
// deliver is called with the message, UID and hsh.
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
// Except when the error is ErrSkip - then the message is left there as is.
//
// deliver is called with the message, UID and hsh.
func DeliveryLoopC(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFuncC, outbox, errbox string) error {
	if inbox == "" {
		inbox = "INBOX"
	}
	for {
		// nosemgrep: trailofbits.go.invalid-usage-of-modified-variable.invalid-usage-of-modified-variable
		n, err := one(ctx, c, inbox, pattern, deliver, outbox, errbox)
		if err != nil {
			logger.Error("DeliveryLoop one round", "count", n, "error", err)
		} else {
			logger.Info("DeliveryLoop one round", "count", n)
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

		delay := time.NewTimer(dur)
		select {
		case <-delay.C:
		case <-ctx.Done():
			if !delay.Stop() {
				<-delay.C
			}
			return nil
		}
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
	return func(ctx context.Context, r io.ReadSeeker, uid uint32, hsh []byte) error {
		return deliver(r, uid, hsh)
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
// r is the message data, uid is the IMAP server sent message UID, hsh is the message's hash.
type DeliverFunc func(r io.ReadSeeker, uid uint32, hsh []byte) error

// DeliverFuncC is the type for message delivery.
//
// r is the message data, uid is the IMAP server sent message UID, hsh is the message's hash.
type DeliverFuncC func(ctx context.Context, r io.ReadSeeker, uid uint32, hsh []byte) error

func one(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFuncC, outbox, errbox string) (int, error) {
	logger := GetLogger(ctx).With("c", c, "inbox", inbox)
	if err := c.ConnectC(ctx); err != nil {
		logger.Error("Connecting", "error", err)
		return 0, fmt.Errorf("connect to %v: %w", c, err)
	}
	defer c.Close(true)

	uids, err := c.ListC(ctx, inbox, pattern, outbox != "" && errbox != "")
	logger.Info("List", "uids", uids, "error", err)
	if err != nil {
		return 0, fmt.Errorf("list %v/%v: %w", c, inbox, err)
	}

	var n int
	hsh := sha512.New384()
	for _, uid := range uids {
		if err = ctx.Err(); err != nil {
			return n, err
		}
		logger := logger.With("uid", uid)
		ctx := zlog.NewSContext(ctx, logger)
		hsh.Reset()
		body := temp.NewMemorySlurper(strconv.FormatUint(uint64(uid), 10))
		if _, err = c.ReadToC(ctx, io.MultiWriter(body, hsh), uid); err != nil {
			body.Close()
			logger.Error("Read", "error", err)
			continue
		}

		err = deliver(ctx, body, uid, hsh.Sum(nil))
		body.Close()
		if err != nil {
			logger.Error("deliver", "error", err)
			if errbox != "" && !errors.Is(err, ErrSkip) {
				if err = c.MoveC(ctx, uid, errbox); err != nil {
					logger.Error("move to", "errbox", errbox, "error", err)
				}
			}
			continue
		}
		n++

		if err = c.MarkC(ctx, uid, true); err != nil {
			logger.Error("mark seen", "error", err)
		}

		if outbox != "" {
			if err = c.MoveC(ctx, uid, outbox); err != nil {
				logger.Error("move to", "outbox", outbox, "error", err)
				continue
			}
		}
	}

	return n, nil
}
