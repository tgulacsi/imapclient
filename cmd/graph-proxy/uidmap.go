// Copyright 2024 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/UNO-SOFT/zlog/v2"
	"github.com/emersion/go-imap/v2"
	"go.etcd.io/bbolt"
	"golang.org/x/sync/errgroup"
)

var endian = binary.BigEndian

func newUIDMap(ctx context.Context, fileName string) (*uidMap, error) {
	logger := zlog.SFromContext(ctx)
	db, err := bbolt.Open(fileName, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("open uidMap %q: %w", fileName, err)
	}
	m := uidMap{db: db}
	tx, err := db.Begin(true)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	key := []byte("V:")
	bucket, err := tx.CreateBucketIfNotExists(key)
	if err != nil {
		return nil, err
	}
	if b := bucket.Get(key); len(b) != 0 {
		m.uidValidity = endian.Uint32(b)
	} else {
		m.uidValidity = uint32(time.Now().Unix() >> 4)
		if err = bucket.Put(key, endian.AppendUint32(nil, m.uidValidity)); err != nil {
			return nil, err
		}
	}
	if logger.Enabled(ctx, slog.LevelDebug) {
		if err = tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			bName := string(name)
			logger := logger.With("bucket", bName)
			cur := b.Cursor()
			for k, v := cur.First(); len(k) != 0; k, v = cur.Next() {
				switch bName[:2] {
				case "U:":
					logger.Debug("uid2id", "uid", endian.Uint32(k), "id", string(v))
				case "M:":
					logger.Debug("id2uid", "id", string(k), "uid", endian.Uint32(v))
				case "V:":
					logger.Debug("uidValidity", "k", string(k), "uidValidity", endian.Uint32(v))
				default:
					logger.Debug("UNKNOWN", "k", string(k), "v", string(v))
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return &m, tx.Commit()
}

func (m *uidMap) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	db := m.db
	m.db = nil
	if db != nil {
		return db.Close()
	}
	return nil
}

// uidMap is a per-folder UID->msgID map
//
// The other way (msgID->UID) is the fnv1 hash of the msgID.
// So the UIDs won't change, but may collide - that's why
// we use a per-folder map, to minimize this risk.
//
// No collision for under 32k mailboxes.
type uidMap struct {
	// uid2id      map[string]map[imap.UID]string
	db          *bbolt.DB
	mu          sync.RWMutex
	uidValidity uint32
}

func (m *uidMap) uidNext(folderID string) imap.UID {
	m.mu.RLock()
	tx, err := m.db.Begin(false)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()
	var n uint32
	if U := tx.Bucket([]byte("U:" + folderID)); U != nil {
		if k, _ := U.Cursor().Last(); len(k) != 0 {
			n = endian.Uint32(k)
		}
	}
	m.mu.RUnlock()
	return imap.UID(n + 1)
}

func (m *uidMap) idOf(folderID string, uid imap.UID) string {
	m.mu.RLock()
	tx, err := m.db.Begin(false)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()
	bucket := tx.Bucket([]byte("U:" + folderID))
	if bucket == nil {
		panic("no folderID=" + folderID + "seen yet")
	}
	s := bucket.Get(endian.AppendUint32(nil, uint32(uid)))
	m.mu.RUnlock()
	return string(s)
}

func (m *uidMap) uidOf(folderID, msgID string) imap.UID {
	folderM := []byte("M:" + folderID)
	{
		m.mu.RLock()
		tx, err := m.db.Begin(false)
		if err != nil {
			panic(err)
		}
		M := tx.Bucket(folderM)
		var b []byte
		if M != nil {
			b = M.Get([]byte(msgID))
		}
		tx.Rollback()
		m.mu.RUnlock()
		if len(b) != 0 {
			return imap.UID(endian.Uint32(b))
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, err := m.db.Begin(true)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()
	M, err := tx.CreateBucketIfNotExists(folderM)
	if err != nil {
		panic(err)
	}
	if b := M.Get([]byte(msgID)); len(b) != 0 {
		return imap.UID(endian.Uint32(b))
	}
	folderU := []byte("U:" + folderID)
	U, err := tx.CreateBucketIfNotExists(folderU)
	if err != nil {
		panic(err)
	}
	var uid uint32
	if k, _ := U.Cursor().Last(); len(k) != 0 {
		uid = endian.Uint32(k)
	}
	uid++
	k := endian.AppendUint32(nil, uid)
	if err = M.Put([]byte(msgID), k); err != nil {
		panic(err)
	}
	if err = U.Put(k, []byte(msgID)); err != nil {
		panic(err)
	}
	if err = tx.Commit(); err != nil {
		panic(err)
	}
	return imap.UID(uid)
}

func (m *uidMap) forNumSet(ctx context.Context,
	folderID string, numSet imap.NumSet, full bool,
	fetchFolder func(context.Context) error,
	f func(context.Context, string) error,
) error {
	if fetchFolder != nil {
		if fetched, err := func() (bool, error) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			tx, err := m.db.Begin(false)
			if err != nil {
				return false, err
			}
			defer tx.Rollback()
			return tx.Bucket([]byte("U:"+folderID)) != nil, nil
		}(); err != nil {
			return err
		} else if !fetched {
			if err := fetchFolder(ctx); err != nil {
				return err
			}
		}
	}
	type pair struct {
		UID   uint32
		MsgID string
	}
	var ids []pair
	if err := func() error {
		m.mu.RLock()
		defer m.mu.RUnlock()
		tx, err := m.db.Begin(false)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		bucket := tx.Bucket([]byte("U:" + folderID))
		if bucket == nil {
			return nil
		}
		cur := bucket.Cursor()
		for k, v := cur.First(); len(k) != 0 && len(v) != 0; k, v = cur.Next() {
			if len(k) == 0 || len(v) == 0 {
				break
			}
			ids = append(ids, pair{
				UID: endian.Uint32(k), MsgID: string(v),
			})
		}
		return nil
	}(); err != nil {
		return err
	}

	var next func() (string, bool)
	if ids != nil {
		var Contains func(imap.UID) bool
		if ss, ok := numSet.(imap.SeqSet); ok {
			Contains = func(uid imap.UID) bool { return ss.Contains(uint32(uid)) }
		} else if us, ok := numSet.(imap.UIDSet); ok {
			Contains = us.Contains
		}
		next = func() (string, bool) {
			for len(ids) != 0 {
				p := ids[0]
				ids = ids[1:]
				if Contains(imap.UID(p.UID)) {
					return p.MsgID, len(ids) != 0
				}
			}
			return "", false
		}
	} else {
		if ss, ok := numSet.(imap.SeqSet); ok {
			nums, _ := ss.Nums()
			next = func() (string, bool) {
				for len(nums) != 0 {
					n := nums[0]
					nums = nums[1:]
					if id := m.idOf(folderID, imap.UID(n)); id != "" {
						return id, len(nums) != 0
					}
				}
				return "", false
			}
		} else if us, ok := numSet.(imap.UIDSet); ok {
			ur := us[0]
			us = us[1:]
			first := true
			var msgID imap.UID
			next = func() (string, bool) {
				cont := true
				for cont {
					if first {
						msgID = ur.Start
						first = false
					} else if msgID >= ur.Stop {
						if len(us) == 0 {
							cont = false
						} else {
							ur = us[0]
							us = us[1:]
							first = true
						}
					} else {
						msgID++
					}
					if id := m.idOf(folderID, msgID); id != "" {
						return id, cont
					}
				}
				return "", false
			}
		}

	}

	grp := new(errgroup.Group)
	if !full {
		grp, ctx = errgroup.WithContext(ctx)
	}
	grp.SetLimit(16)
	for id, cont := next(); cont; id, cont = next() {
		if id != "" {
			grp.Go(func() error {
				return f(ctx, id)
			})
		}
		if !cont {
			break
		}
	}
	return grp.Wait()
}
