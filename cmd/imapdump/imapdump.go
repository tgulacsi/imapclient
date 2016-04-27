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

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/errgo.v1"

	"golang.org/x/net/context"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"

	"github.com/rs/xlog"
	"github.com/spf13/cobra"
	"github.com/tgulacsi/imapclient"
)

// Log is the logger.
var Log xlog.Logger

func main() {
	Log = xlog.New(xlog.Config{Output: xlog.NewConsoleOutput()})
	imapclient.Log = Log

	dumpCmd := &cobra.Command{
		Use: "dump",
	}
	var (
		username, password string
		host, mbox         string
		port               int
		all                bool
	)
	P := dumpCmd.PersistentFlags()
	P.StringVarP(&username, "username", "U", "", "username")
	P.StringVarP(&password, "password", "P", "", "password")
	P.StringVarP(&host, "host", "H", "localhost", "host")
	P.IntVarP(&port, "port", "p", 143, "port")
	P.StringVarP(&mbox, "mbox", "m", "INBOX", "mail box")

	listCmd := &cobra.Command{
		Use: "list",
		Run: func(_ *cobra.Command, args []string) {
			c := imapclient.NewClient(host, port, username, password)
			if err := c.Connect(); err != nil {
				Log.Fatalf("CONNECT: %v", err)
			}
			defer c.Close(false)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			uids, err := c.ListC(ctx, mbox, "", all)
			cancel()
			if err != nil {
				Log.Fatalf("LIST: %v", err)
			}
			var buf bytes.Buffer
			for _, uid := range uids {
				buf.Reset()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err := c.Peek(ctx, &buf, uid, "")
				cancel()
				if err != nil {
					Log.Errorf("Peek(%d): %v", uid, err)
					continue
				}
				hdr, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(buf.Bytes()))).ReadMIMEHeader()
				if err != nil {
					Log.Errorf("parse(%d) %q: %v", uid, buf.String(), err)
					continue
				}
				fmt.Fprintf(os.Stdout, "%d\t%s\n", uid, HeadDecode(hdr.Get("Subject")))
			}
		},
	}
	listCmd.Flags().BoolVarP(&all, "all", "a", false, "list all, not just UNSEEN")
	dumpCmd.AddCommand(listCmd)

	var out string
	saveCmd := &cobra.Command{
		Use:     "save",
		Aliases: []string{"dump", "write"},
		Run: func(_ *cobra.Command, args []string) {
			c := imapclient.NewClient(host, port, username, password)
			if err := c.Connect(); err != nil {
				Log.Fatalf("CONNECT: %v", err)
			}
			defer c.Close(false)
			ctx := context.Background()
			ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.Select(ctx2, mbox)
			cancel()
			if err != nil {
				Log.Fatalf("SELECT(%q): %v", mbox, err)
			}

			dest := os.Stdout
			if !(out == "" || out == "-") {
				var err error
				dest, err = os.Create(out)
				if err != nil {
					Log.Fatalf("create output %q: %v", out, err)
				}
			}
			defer func() {
				if err := dest.Close(); err != nil {
					Log.Errorf("close output: %v", err)
				}
			}()

			var uids []uint32
			if len(args) == 0 || strings.ToUpper(args[0]) == "ALL" {
				ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				var err error
				uids, err = c.ListC(ctx, mbox, "", all)
				cancel()
				if err != nil {
					Log.Fatalf("list %q: %v", mbox, err)
				}
			} else {
				for _, a := range args {
					uid, err := strconv.ParseUint(a, 10, 32)
					if err != nil {
						Log.Errorf("parse %q as uid: %v", a, err)
						continue
					}
					uids = append(uids, uint32(uid))
				}
			}

			if len(uids) == 0 {
				return
			}
			if len(args) == 1 {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err = c.ReadToC(ctx, dest, uids[0])
				cancel()
				if err != nil {
					Log.Fatalf("Read(%d): %v", uids[0], err)
				}
				return
			}

			tw := tar.NewWriter(dest)
			defer tw.Close()
			var buf bytes.Buffer
			now := time.Now()
			osUid, osGid := os.Getuid(), os.Getgid()
			for _, uid := range uids {
				buf.Reset()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err = c.ReadToC(ctx, &buf, uint32(uid))
				cancel()
				if err != nil {
					Log.Fatalf("Read(%d): %v", uid, errgo.Details(err))
				}
				if err := tw.WriteHeader(&tar.Header{
					Name:     fmt.Sprintf("%d.eml", uid),
					Size:     int64(buf.Len()),
					Mode:     0640,
					Typeflag: tar.TypeReg,
					ModTime:  now,
					Uid:      osUid, Gid: osGid,
				}); err != nil {
					Log.Fatal(err)
				}
				if _, err := io.Copy(tw, bytes.NewReader(buf.Bytes())); err != nil {
					Log.Fatal(err)
				}

				if err := tw.Flush(); err != nil {
					Log.Fatal(err)
				}
			}

		},
	}
	saveCmd.Flags().StringVarP(&out, "out", "o", "-", "output mail(s) to this file")
	dumpCmd.AddCommand(saveCmd)

	dumpCmd.Execute()
}

var WordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		//enc, err := ianaindex.MIME.Get(charset)
		enc, err := htmlindex.Get(charset)
		if err != nil {
			return input, err
		}
		return transform.NewReader(input, enc.NewDecoder()), nil
	},
}

func HeadDecode(head string) string {
	res, err := WordDecoder.DecodeHeader(head)
	if err == nil {
		return res
	}
	if err != nil {
		Log.Errorf("decode %q: %v", head, err)
	}
	return head
}
