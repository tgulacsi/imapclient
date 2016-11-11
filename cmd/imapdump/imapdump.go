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
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	_ "net/http/pprof"
	"net/textproto"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go4.org/syncutil"

	"golang.org/x/net/context"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"

	"github.com/go-kit/kit/log"
	"github.com/mxk/go-imap/imap"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tgulacsi/go/loghlp/kitloghlp"
	"github.com/tgulacsi/imapclient"
)

const fetchBatchLen = 1024

// Log is the logger.
var logger = log.NewContext(kitloghlp.Stringify{log.NewLogfmtLogger(os.Stderr)}).
	With("ts", log.DefaultTimestamp)

func main() {
	dumpCmd := &cobra.Command{
		Use: "dump",
	}

	var (
		pprofListen        string
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
	P.StringVarP(&pprofListen, "pprof", "", "", "HTTP address to pprof to listen on")
	P.StringVarP(&username, "username", "U", os.Getenv("IMAPDUMP_USER"), "username")
	P.StringVarP(&password, "password", "P", os.Getenv("IMAPDUMP_PASS"), "password")
	P.StringVarP(&host, "host", "H", host, "host")
	P.BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	P.IntVarP(&port, "port", "p", port, "port")

	rootCtx := context.WithValue(context.Background(), "Log", logger.Log)
	dumpCmd.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		if verbose {
			imapclient.Log = logger.With("lib", "imapclient").Log
		}
		if pprofListen != "" {
			go func() {
				logger.Log("msg", http.ListenAndServe(pprofListen, nil))
			}()
		}
	}

	NewClient := func() (imapclient.Client, error) {
		c := imapclient.NewClient(host, port, username, password)
		c.SetLoggerC(rootCtx)
		if verbose {
			c.SetLogMask(imap.LogAll)
		}
		return c, c.Connect()
	}

	Log := logger.Log
	listCmd := &cobra.Command{
		Use: "list",
		Run: func(_ *cobra.Command, args []string) {
			c, err := NewClient()
			if err != nil {
				Log("msg", "CONNECT", "error", err)
				os.Exit(1)
			}
			defer c.Close(false)
			for _, mbox := range args {
				mails, err := listMbox(rootCtx, c, mbox, all)
				if err != nil {
					Log("msg", "Listing", "box", mbox, "error", err)
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
			c, err := NewClient()
			if err != nil {
				Log("msg", "CONNECT", "error", err)
				os.Exit(1)
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
				Log("msg", "LIST", "error", err)
				os.Exit(1)
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
					Log("msg", "list", "box", m, "error", err)
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
			c, err := NewClient()
			if err != nil {
				Log("msg", "CONNECT", "error", err)
			}
			defer c.Close(false)
			mailboxes := []string{mbox}
			if recursive {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
				var err error
				mailboxes, err = c.Mailboxes(ctx, mbox)
				cancel()
				if err != nil {
					Log("msg", "List mailboxes under", "box", mbox, "error", err)
					os.Exit(1)
				}
			}

			dest := os.Stdout
			if !(out == "" || out == "-") {
				var err error
				dest, err = os.Create(out)
				if err != nil {
					Log("msg", "create", "output", out, "error", err)
					os.Exit(1)
				}
			}
			defer func() {
				if err := dest.Close(); err != nil {
					Log("msg", "close output", "error", err)
				}
			}()

			if !recursive {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
				err := c.Select(ctx, mbox)
				cancel()
				if err != nil {
					Log("msg", "SELECT", "box", mbox, "error", err)
					os.Exit(1)
				}

				var uids []uint32
				if len(args) == 0 || strings.ToUpper(args[0]) == "ALL" {
					ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
					var err error
					uids, err = c.ListC(ctx, mbox, "", true)
					cancel()
					if err != nil {
						Log("msg", "list", "box", mbox, "error", err)
						os.Exit(1)
					}
				} else {
					for _, a := range args {
						uid, err := strconv.ParseUint(a, 10, 32)
						if err != nil {
							Log("msg", "parse as uid", "text", a, "error", err)
							continue
						}
						uids = append(uids, uint32(uid))
					}
				}

				if 1 == len(uids) {
					ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
					_, err = c.ReadToC(ctx, dest, uids[0])
					cancel()
					if err != nil {
						Log("msg", "Read", "uid", uids[0], "error", err)
						os.Exit(1)
					}
				}
				tw := &syncTW{Writer: tar.NewWriter(dest)}
				err = dumpMails(rootCtx, tw, c, mbox, uids)
				if closeErr := tw.Close(); closeErr != nil && err == nil {
					err = closeErr
				}
				if err != nil {
					Log("error", err)
					os.Exit(1)
				}
				return
			}

			tw := &syncTW{Writer: tar.NewWriter(dest)}
			defer func() {
				if err := tw.Close(); err != nil {
					Log("msg", "Close tar", "error", err)
					os.Exit(1)
				}
			}()

			var grp syncutil.Group
			for _, mbox := range mailboxes {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Minute)
				uids, err := c.ListC(ctx, mbox, "", true)
				cancel()
				if err != nil {
					Log("msg", "list", "box", mbox, "error", err)
					os.Exit(1)
				}
				if len(uids) == 0 {
					continue
				}

				mbox := mbox
				grp.Go(func() error {
					c, err := NewClient()
					if err != nil {
						return err
					}
					defer func() {
						if err := c.Close(true); err != nil {
							Log("msg", "Close", "error", err)
						}
						runtime.GC()
					}()
					return dumpMails(rootCtx, tw, c, mbox, uids)
				})
			}
			if err := grp.Err(); err != nil {
				Log("error", err)
				os.Exit(1)
			}

		},
	}
	saveCmd.Flags().StringVarP(&out, "out", "o", "-", "output mail(s) to this file")
	saveCmd.Flags().StringVarP(&mbox, "mbox", "m", "INBOX", "mailbox to save from")
	saveCmd.Flags().BoolVarP(&recursive, "recursive", "r", recursive, "dump recursively (all subfolders)")
	dumpCmd.AddCommand(saveCmd)

	dumpCmd.Execute()
}

var bufPool = sync.Pool{New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 1<<20)) }}

func dumpMails(rootCtx context.Context, tw *syncTW, c imapclient.Client, mbox string, uids []uint32) error {
	ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
	err := c.Select(ctx, mbox)
	cancel()
	Log := imapclient.GetLog(ctx)
	if err != nil {
		Log("msg", "SELECT", "box", mbox, "error", err)
		os.Exit(1)
	}

	if len(uids) == 0 {
		ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
		var err error
		uids, err = c.ListC(ctx, mbox, "", true)
		cancel()
		if err != nil {
			Log("msg", "list", "box", mbox, "error", err)
			os.Exit(1)
		}
	}

	now := time.Now()
	osUid, osGid := os.Getuid(), os.Getgid()
	Log("msg", "Saving messages", "count", len(uids), "box", mbox)
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	seen := make(map[string]struct{}, 1024)
	var hshB []byte
	for _, uid := range uids {
		buf.Reset()
		ctx, cancel := context.WithTimeout(rootCtx, 10*time.Minute)
		_, err = c.ReadToC(ctx, buf, uint32(uid))
		cancel()
		if err != nil {
			Log("error", errors.Wrapf(err, "read(%d)", uid))
		}
		hsh := sha1.New()
		io.Copy(hsh, bytes.NewReader(buf.Bytes()))
		hshB = hsh.Sum(hshB[:0])
		hshS := base64.URLEncoding.EncodeToString(hshB)
		if _, ok := seen[hshS]; ok {
			Log("msg", "Deleting already seen.", "box", mbox, "uid", uid)
			if err := c.Delete(uid); err != nil {
				Log("msg", "Delete", "box", mbox, "uid", uid, "error", err)
			}
			continue
		}
		seen[hshS] = struct{}{}

		hdr, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(buf.Bytes()))).ReadMIMEHeader()
		msgID := hdr.Get("Message-ID")
		if msgID == "" {
			msgID = fmt.Sprintf("%06d", uid)
		}
		t := now
		if err != nil {
			Log("msg", "parse", "uid", uid, "error", err)
		} else {
			var ok bool
			if t, ok = HeadDate(hdr.Get("Date")); !ok {
				t = now
			}
		}
		tw.Lock()
		if err := tw.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("%s/%s.eml", mbox, base64.URLEncoding.EncodeToString([]byte(msgID))),
			Size:     int64(buf.Len()),
			Mode:     0640,
			Typeflag: tar.TypeReg,
			ModTime:  t,
			Uid:      osUid, Gid: osGid,
		}); err != nil {
			tw.Unlock()
			return errors.Wrapf(err, "WriteHeader")
		}
		if _, err := io.Copy(tw, bytes.NewReader(buf.Bytes())); err != nil {
			tw.Unlock()
			return errors.Wrapf(err, "write tar")
		}

		if err := tw.Flush(); err != nil {
			tw.Unlock()
			return errors.Wrapf(err, "flush tar")
		}
		tw.Unlock()
	}
	return nil
}

type syncTW struct {
	*tar.Writer
	sync.Mutex
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
		logger.Log("msg", "decode", "head", head, "error", err)
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
		return nil, errors.Wrapf(err, "LIST %q", mbox)
	}
	if len(uids) == 0 {
		return nil, nil
	}

	Log := imapclient.GetLog(rootCtx)
	result := make([]Mail, 0, len(uids))
	for len(uids) > 0 {
		n := len(uids)
		if n > fetchBatchLen {
			n = fetchBatchLen
			Log("msg", "Fetching.", "n", n, "of", len(uids))
		}
		ctx, cancel = context.WithTimeout(rootCtx, 10*time.Second)
		attrs, err := c.FetchArgs(ctx, "RFC822.SIZE RFC822.HEADER", uids[:n]...)
		uids = uids[n:]
		cancel()
		if err != nil {
			Log("msg", "FetchArgs", "uids", uids, "error", err)
			return nil, err
		}
		for uid, a := range attrs {
			m := Mail{UID: uid}
			result = append(result, m)
			hdr, err := textproto.NewReader(bufio.NewReader(strings.NewReader(a["RFC822.HEADER"][0]))).ReadMIMEHeader()
			if err != nil {
				Log("msg", "parse", "uid", uid, "error", err)
				continue
			}
			m.Subject = HeadDecode(hdr.Get("Subject"))
			if s, err := strconv.ParseUint(a["RFC822.SIZE"][0], 10, 32); err != nil {
				Log("msg", "size of", "uid", uid, "text", a["RFC822.SIZE"], "error", err)
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
