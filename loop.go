/*
Copyright 2014 Tamás Gulácsi

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
	"io"
	"strconv"
	"time"

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
// deliver is called with the message, where X-UID and X-SHA1 are set.
func DeliveryLoop(c Client, inbox, pattern string, deliver DeliverFunc, outbox string) {
	if inbox == "" {
		inbox = "INBOX"
	}
	for {
		n, err := one(c, inbox, pattern, deliver, outbox)
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

// DeliverFunc is the type for message delivery.
type DeliverFunc func(io.ReadSeeker, uint32, []byte) error

func one(c Client, inbox, pattern string, deliver DeliverFunc, outbox string) (int, error) {
	if err := c.Connect(); err != nil {
		Log.Error("Connecting", "server", c, "error", err)
		return 0, err
	}
	defer c.Close(true)

	uids, err := c.ListNew(inbox, pattern)
	if err != nil {
		Log.Error("List", "server", c, "inbox", inbox, "error", err)
		return 0, err
	}

	var n int
	hsh := sha1.New()
	for _, uid := range uids {
		hsh.Reset()
		body := temp.NewMemorySlurper(strconv.FormatUint(uint64(uid), 10))
		if _, err = c.ReadTo(io.MultiWriter(body, hsh), uid); err != nil {
			Log.Error("Read", "uid", uid, "error", err)
			continue
		}

		if err = deliver(body, uid, hsh.Sum(nil)); err != nil {
			Log.Error("deliver", "uid", uid, "error", err)
			continue
		}
		n++

		if err = c.Mark(uid, true); err != nil {
			Log.Error("mark seen", "uid", uid, "error", err)
			continue
		}

		if outbox != "" {
			if err = c.Move(uid, outbox); err != nil {
				Log.Error("move", "uid", uid, "outbox", outbox, "error", err)
				continue
			}
		}
	}

	return n, nil
}
