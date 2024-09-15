// Copyright 2024 Tamás Gulácsi. All rights reserved.

package main_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"testing"
	"time"

	"github.com/dchest/siphash"
)

func TestHashCollision(t *testing.T) {
	hfnv := fnv.New32()
	hfnva := fnv.New32a()
	collisions := make(map[string]int64, 4)
	for i := 0; i < 10; i++ {
		datas := make([][]byte, 0, 128<<10)
		for name, f := range map[string]func([]byte) uint32{
			"FNV":  func(data []byte) uint32 { hfnv.Reset(); hfnv.Write(data); return hfnv.Sum32() },
			"FNVa": func(data []byte) uint32 { hfnva.Reset(); hfnva.Write(data); return hfnva.Sum32() },
			"SIM":  func(data []byte) uint32 { return uint32(siphash.Hash(0, 0, data)) },
		} {
			t.Run(name, func(t *testing.T) {
				datas := datas[:]
				seen := make(map[uint32]struct{})
				start := time.Now()
				var collided bool
				for _, d := range datas {
					v := f(d[:])
					if _, ok := seen[v]; ok {
						t.Logf("%q: first collision after %d hashes", name, len(seen))
						collisions[name] += int64(len(seen))
						collided = true
						break
					}
					seen[v] = struct{}{}
				}
				if !collided {
					for {
						var a [120 * 3 / 4]byte
						var d [120]byte
						n, _ := rand.Read(a[:])
						base64.URLEncoding.Encode(d[:], a[:n])
						// copy(d[:], a[:n])
						datas = append(datas, append([]byte(nil), d[:]...))
						v := f(d[:])
						if _, ok := seen[v]; ok {
							t.Logf("%q: first collision after %d hashes", name, len(seen))
							collisions[name] += int64(len(seen))
							collided = true
							break
						}
						seen[v] = struct{}{}
					}
				}
				t.Logf("speed: %f", float64(len(seen))/float64(time.Since(start)))
			})
		}
	}
	fmt.Println(collisions)
}
