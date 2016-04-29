/*
Copyright 2016 Tamás Gulácsi

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

const fetchBatchLen = 1024

// Log is the logger.
var Log xlog.Logger

func main() {
	logCfg := xlog.Config{Output: xlog.NewConsoleOutput(), Level: xlog.LevelInfo}
	Log = xlog.New(logCfg)

	dumpCmd := &cobra.Command{
		Use: "dump",
	}

	var (
		username, password string
		verbose, all       bool
	)
	host := os.Getenv("IMAPDUMP_HOST")
	port := 143
	if s := os.Getenv("IMAPDUMP_PORT"); s != "" {
		if i, err := strconv.Atoi(s); err == nil {
			port = i
		}
	}
	P := dumpCmd.PersistentFlags()
	P.StringVarP(&username, "username", "U", os.Getenv("IMAPDUMP_USER"), "username")
	P.StringVarP(&password, "password", "P", os.Getenv("IMAPDUMP_PASS"), "password")
	P.StringVarP(&host, "host", "H", host, "host")
	P.BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	P.IntVarP(&port, "port", "p", port, "port")

	rootCtx := xlog.NewContext(context.Background(), Log)
	dumpCmd.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		if verbose {
			logCfg.Level = xlog.LevelDebug
			Log = xlog.New(logCfg)
			imapclient.Log = Log
			rootCtx = xlog.NewContext(rootCtx, Log)
		}
	}

	listCmd := &cobra.Command{
		Use: "list",
		Run: func(_ *cobra.Command, args []string) {
			c := imapclient.NewClient(host, port, username, password)
			if err := c.Connect(); err != nil {
				Log.Fatalf("CONNECT: %v", err)
			}
			defer c.Close(false)
			for _, mbox := range args {
				mails, err := listMbox(rootCtx, c, mbox, all)
				if err != nil {
					Log.Errorf("Listing %q: %v", mbox, err)
				}
				for _, m := range mails {
					fmt.Fprintf(os.Stdout, "%d\t%d\t%s\n", m.UID, m.Size, m.Subject)
				}
			}
		},
	}
	listCmd.Flags().BoolVarP(&all, "all", "a", false, "list all, not just UNSEEN")
	dumpCmd.AddCommand(listCmd)

	var du bool
	treeCmd := &cobra.Command{
		Use: "tree",
		Run: func(_ *cobra.Command, args []string) {
			c := imapclient.NewClient(host, port, username, password)
			if err := c.Connect(); err != nil {
				Log.Fatalf("CONNECT: %v", err)
			}
			defer c.Close(false)
			ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
			mbox := "INBOX"
			if len(args) > 0 {
				mbox = args[0]
			}
			boxes, err := c.Mailboxes(ctx, mbox)
			cancel()
			if err != nil {
				Log.Fatalf("LIST: %v", err)
			}
			if !du {
				for _, m := range boxes {
					fmt.Fprintln(os.Stdout, m)
				}
				return
			}
			for _, m := range boxes {
				ctx, cancel := context.WithTimeout(rootCtx, 5*time.Minute)
				mails, err := listMbox(ctx, c, m, true)
				cancel()
				if err != nil {
					Log.Errorf("list %q: %v", m, err)
				}
				var s uint64
				for _, m := range mails {
					s += uint64(m.Size)
				}
				fmt.Fprintf(os.Stdout, "%s\t%d\n", m, s)
			}
		},
	}
	treeCmd.Flags().BoolVarP(&du, "du", "l", false, "print dir sizes, too")
	dumpCmd.AddCommand(treeCmd)

	var out, mbox string
	recursive := false
	saveCmd := &cobra.Command{
		Use:     "save",
		Aliases: []string{"dump", "write"},
		Run: func(_ *cobra.Command, args []string) {
			c := imapclient.NewClient(host, port, username, password)
			if err := c.Connect(); err != nil {
				Log.Fatalf("CONNECT: %v", err)
			}
			defer c.Close(false)
			mailboxes := []string{mbox}
			if recursive {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
				var err error
				mailboxes, err = c.Mailboxes(ctx, mbox)
				cancel()
				if err != nil {
					Log.Fatalf("List mailboxes under %q: %v", mbox, err)
				}
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

			var tw *tar.Writer
			for _, mbox := range mailboxes {

				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
				err := c.Select(ctx, mbox)
				cancel()
				if err != nil {
					Log.Fatalf("SELECT(%q): %v", mbox, err)
				}

				var uids []uint32
				if len(args) == 0 || strings.ToUpper(args[0]) == "ALL" {
					ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
					var err error
					uids, err = c.ListC(ctx, mbox, "", true)
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

				switch len(uids) {
				case 0:
					if recursive {
						continue
					}
					return
				case 1:
					ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
					_, err = c.ReadToC(ctx, dest, uids[0])
					cancel()
					if err != nil {
						Log.Fatalf("Read(%d): %v", uids[0], err)
					}
					if recursive {
						continue
					}
					return
				}
				if tw == nil {
					tw = tar.NewWriter(dest)
					defer tw.Close()
				}

				now := time.Now()
				osUid, osGid := os.Getuid(), os.Getgid()
				Log.Infof("Saving %d messages from %q...", len(uids), mbox)
				var buf bytes.Buffer
				for _, uid := range uids {
					buf.Reset()
					ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
					_, err = c.ReadToC(ctx, &buf, uint32(uid))
					cancel()
					if err != nil {
						Log.Fatal(errgo.Notef(err, "read(%d)", uid))
					}
					hdr, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(buf.Bytes()))).ReadMIMEHeader()
					t := now
					if err != nil {
						Log.Errorf("parse(%d): %v", uid, err)
					} else {
						var ok bool
						if t, ok = HeadDate(hdr.Get("Date")); !ok {
							t = now
						}
					}
					if err := tw.WriteHeader(&tar.Header{
						Name:     fmt.Sprintf("%s/%d.eml", mbox, uid),
						Size:     int64(buf.Len()),
						Mode:     0640,
						Typeflag: tar.TypeReg,
						ModTime:  t,
						Uid:      osUid, Gid: osGid,
					}); err != nil {
						Log.Fatal(errgo.Notef(err, "WriteHeader"))
					}
					if _, err := io.Copy(tw, bytes.NewReader(buf.Bytes())); err != nil {
						Log.Fatal(errgo.Notef(err, "write tar"))
					}

					if err := tw.Flush(); err != nil {
						Log.Fatal(errgo.Notef(err, "flush tar"))
					}
				}
			}

		},
	}
	saveCmd.Flags().StringVarP(&out, "out", "o", "-", "output mail(s) to this file")
	saveCmd.Flags().StringVarP(&mbox, "mbox", "m", "INBOX", "mailbox to save from")
	saveCmd.Flags().BoolVarP(&recursive, "recursive", "r", recursive, "dump recursively (all subfolders)")
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

type Mail struct {
	UID     uint32
	Subject string
	Size    uint32
}

func listMbox(rootCtx context.Context, c imapclient.Client, mbox string, all bool) ([]Mail, error) {
	ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
	uids, err := c.ListC(ctx, mbox, "", all)
	cancel()
	if err != nil {
		return nil, errgo.Notef(err, "LIST %q", mbox)
	}
	if len(uids) == 0 {
		return nil, nil
	}

	result := make([]Mail, 0, len(uids))
	for len(uids) > 0 {
		n := len(uids)
		if n > fetchBatchLen {
			n = fetchBatchLen
			Log.Infof("Fetching %d of %d.", n, len(uids))
		}
		ctx, cancel = context.WithTimeout(rootCtx, 10*time.Second)
		attrs, err := c.FetchArgs(ctx, "RFC822.SIZE RFC822.HEADER", uids[:n]...)
		uids = uids[n:]
		cancel()
		if err != nil {
			Log.Errorf("FetchArgs(%d): %v", uids, err)
			return nil, err
		}
		for uid, a := range attrs {
			m := Mail{UID: uid}
			result = append(result, m)
			hdr, err := textproto.NewReader(bufio.NewReader(strings.NewReader(a["RFC822.HEADER"][0]))).ReadMIMEHeader()
			if err != nil {
				Log.Errorf("parse(%d): %v", uid, err)
				continue
			}
			m.Subject = HeadDecode(hdr.Get("Subject"))
			if s, err := strconv.ParseUint(a["RFC822.SIZE"][0], 10, 32); err != nil {
				Log.Errorf("size(%d)=%v: %v", uid, a["RFC822.SIZE"], err)
				continue
			} else {
				m.Size = uint32(s)
				result[len(result)-1] = m
			}
		}
	}
	return result, nil
}

func HeadDate(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, pat := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822} {
		if t, err := time.Parse(pat, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
