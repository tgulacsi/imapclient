// Copyright 2017, 2025 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package imapclient

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/tgulacsi/go/iohlp"
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
func DeliveryLoop(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFunc, outbox, errbox string, logger *slog.Logger, delete bool) error {
	if inbox == "" {
		inbox = "INBOX"
	}
	for {
		// nosemgrep: trailofbits.go.invalid-usage-of-modified-variable.invalid-usage-of-modified-variable
		n, err := one(ctx, c, inbox, pattern, deliver, outbox, errbox, logger, delete)
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

func NewHash() *Hash { return &Hash{Hash: sha512.New512_224()} }

type HashArray [sha512.Size224]byte

func (h HashArray) String() string { return base64.URLEncoding.EncodeToString(h[:]) }

type Hash struct{ hash.Hash }

func (h Hash) Array() HashArray { var a HashArray; h.Hash.Sum(a[:0]); return a }

func MkDeliverFunc(ctx context.Context, deliver DeliverFunc) DeliverFunc {
	return func(ctx context.Context, r io.ReadSeeker, uid uint32, hsh HashArray) error {
		return deliver(ctx, r, uid, hsh)
	}
}

// DeliverOne does one round of message reading and delivery. Does not loop.
// Returns the number of messages delivered.
func DeliverOne(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFunc, outbox, errbox string, logger *slog.Logger, delete bool) (int, error) {
	if inbox == "" {
		inbox = "INBOX"
	}
	return one(ctx, c, inbox, pattern, deliver, outbox, errbox, logger, delete)
}

// DeliverFunc is the type for message delivery.
//
// r is the message data, uid is the IMAP server sent message UID, hsh is the message's hash.
type DeliverFunc func(ctx context.Context, r io.ReadSeeker, uid uint32, hsh HashArray) error

func one(ctx context.Context, c Client, inbox, pattern string, deliver DeliverFunc, outbox, errbox string, logger *slog.Logger, delete bool) (int, error) {
	logger = logger.With("inbox", inbox)
	if err := c.Connect(ctx); err != nil {
		logger.Error("Connecting", "error", err)
		return 0, fmt.Errorf("connect: %w", err)
	}
	defer c.Close(ctx, true)

	uids, err := c.List(ctx, inbox, pattern, outbox != "" && errbox != "")
	logger.Info("List", "uids", uids, "error", err)
	if err != nil {
		return 0, fmt.Errorf("list %v/%v: %w", c, inbox, err)
	}

	var n int
	hsh := NewHash()
	rand.Shuffle(len(uids), func(i, j int) { uids[i], uids[j] = uids[j], uids[i] })
	for _, uid := range uids {
		if err = ctx.Err(); err != nil {
			return n, err
		}
		logger := logger.With("uid", uid)

		hsh.Reset()
		pr, pw := io.Pipe()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			_, err = c.ReadTo(ctx, io.MultiWriter(pw, hsh), uid)
			pw.CloseWithError(err)
			wg.Done()
		}()
		sr, err := iohlp.MakeSectionReader(pr, 1<<20)
		pr.CloseWithError(err)
		wg.Wait()
		if err != nil || sr.Size() == 0 {
			logger.Error("Read", "error", err)
			continue
		}

		if err = deliver(ctx, sr, uid, hsh.Array()); err != nil {
			logger.Error("deliver", "error", err)
			if errbox != "" && !errors.Is(err, ErrSkip) {
				if err = c.Move(ctx, uid, errbox); err != nil {
					logger.Error("move to", "errbox", errbox, "error", err)
				}
			}
			return n, err
		}
		n++
		logger.Info("delivered")

		if err = c.Mark(ctx, uid, true); err != nil {
			logger.Error("mark seen", "error", err)
		}

		if delete {
			if err = c.Delete(ctx, uid); err != nil {
				logger.Error("delete", "error", err)
			} else {
				continue
			}
		}
		if outbox != "" {
			if err = c.Move(ctx, uid, outbox); err != nil {
				logger.Error("move to", "outbox", outbox, "error", err)
				continue
			}
		}
	}

	return n, nil
}
