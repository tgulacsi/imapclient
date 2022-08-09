// Copyright 2019, 2022 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"mime"
	_ "net/http/pprof"
	"net/textproto"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/tgulacsi/imapclient/v2"
	"github.com/tgulacsi/imapclient/v2/o365"
)

const fetchBatchLen = 1024

var zl = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger().Level(zerolog.InfoLevel)
var logger = zerologr.New(&zl)

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v", err)
	}
}

func Main() error {
	var (
		username, password          string
		recursive, verbose, all, du bool
		clientID, clientSecret      string
		impersonate                 string
	)
	host := os.Getenv("IMAPDUMP_HOST")
	port := 143
	if s := os.Getenv("IMAPDUMP_PORT"); s != "" {
		if i, err := strconv.Atoi(s); err == nil {
			port = i
		}
	}
	FS := flag.NewFlagSet("global", flag.ExitOnError)
	FS.BoolVar(&verbose, "v", false, "verbose")
	FS.StringVar(&username, "username", os.Getenv("IMAPDUMP_USER"), "username")
	FS.StringVar(&password, "password", os.Getenv("IMAPDUMP_PASS"), "password")
	FS.StringVar(&host, "host", host, "host")
	FS.IntVar(&port, "port", port, "port")
	FS.StringVar(&clientID, "client-id", os.Getenv("CLIENT_ID"), "Office 365 CLIENT_ID")
	FS.StringVar(&clientSecret, "client-secret", os.Getenv("CLIENT_SECRET"), "Office 365 CLIENT_SECRET")
	FS.StringVar(&impersonate, "impersonate", "", "Office 365 impersonate")
	flagForceTLS := FS.Bool("force-tls", false, "force use of TLS")
	flagForbidTLS := FS.Bool("forbid-tls", false, "forbid (force no TLS)")

	app := ffcli.Command{Name: "imapdump", ShortHelp: "dump/load mail through IMAP", FlagSet: FS}

	rootCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	prepare := func(ctx context.Context) (imapclient.Client, error) {
		var c imapclient.Client
		if clientID != "" && clientSecret != "" {
			c = o365.NewIMAPClient(o365.NewClient(
				clientID, clientSecret, "http://localhost:8123",
				o365.Impersonate(impersonate),
			))
		} else {
			if port == 0 {
				port = 143
				if *flagForceTLS {
					port = 993
				}
			}
			sa := imapclient.ServerAddress{
				Host: host, Port: uint32(port),
				Username:  username,
				TLSPolicy: imapclient.MaybeTLS,
			}.WithPassword(password)
			if *flagForceTLS {
				sa.TLSPolicy = imapclient.ForceTLS
			} else if *flagForbidTLS {
				sa.TLSPolicy = imapclient.NoTLS
			}
			c = imapclient.FromServerAddress(sa)
			if verbose {
				c.SetLogger(logger)
				c.SetLogMask(imapclient.LogAll)
			}
		}
		if err := c.Connect(ctx); err != nil {
			return nil, err
		}
		return c, nil
	}

	cClose := func(c imapclient.Client) {
		ctx, cancel := context.WithTimeout(rootCtx, 3*time.Second)
		defer cancel()
		c.Close(ctx, false)
	}

	//dumpCmd := app.Command("dump", "dump mail").Default()

	FS = flag.NewFlagSet("list", flag.ContinueOnError)
	FS.BoolVar(&all, "all", false, "list all, not just UNSEEN")
	listCmd := ffcli.Command{Name: "list", ShortHelp: "list mailbox", FlagSet: FS,
		Exec: func(rootCtx context.Context, args []string) error {
			c, err := prepare(rootCtx)
			if err != nil {
				return err
			}
			defer cClose(c)
			for _, mbox := range args {
				mails, err := listMbox(rootCtx, c, mbox, all)
				if err != nil {
					logger.Error(err, "Listing", "box", mbox)
				}
				for _, m := range mails {
					fmt.Fprintf(os.Stdout, "%d\t%d\t%s\n", m.UID, m.Size, m.Subject)
				}
			}
			return nil
		},
	}
	app.Subcommands = append(app.Subcommands, &listCmd)

	FS = flag.NewFlagSet("tree", flag.ContinueOnError)
	FS.BoolVar(&du, "du", false, "print dir sizes, too")
	treeCmd := ffcli.Command{Name: "tree", ShortHelp: "print the tree of mailboxes", FlagSet: FS,
		ShortUsage: "tree [opts] <root - INBOX by default",
		Exec: func(rootCtx context.Context, args []string) error {
			mbox := "INBOX"
			if len(args) != 0 {
				mbox = args[0]
			}
			c, err := prepare(rootCtx)
			if err != nil {
				return err
			}
			defer cClose(c)
			ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
			logger.Info("start Mailboxes")
			boxes, err := c.Mailboxes(ctx, mbox)
			cancel()
			logger.Info("end Mailboxes", "boxes", boxes, "du", du, "error", err)
			if err != nil {
				logger.Error(err, "LIST")
				return err
			}
			if !du {
				for _, m := range boxes {
					logger.Info("tree", "m", m)
					fmt.Fprintln(os.Stdout, m)
				}
				return nil
			}
			logger.Info("boxes")
			for _, m := range boxes {
				ctx, cancel := context.WithTimeout(rootCtx, 5*time.Minute)
				logger.Info("start listMbox", "mbox", m)
				mails, err := listMbox(ctx, c, m, true)
				cancel()
				if err != nil {
					logger.Error(err, "list", "box", m)
				}
				var s uint64
				for _, m := range mails {
					s += uint64(m.Size)
				}
				fmt.Fprintf(os.Stdout, "%s\t%d\n", m, s)
			}
			return nil
		},
	}
	app.Subcommands = append(app.Subcommands, &treeCmd)

	FS = flag.NewFlagSet("save", flag.ContinueOnError)
	saveOut := FS.String("out", "-", "output mail(s) to this file")
	saveMbox := FS.String("mbox", "INBOX", "mailbox to save from")
	FS.BoolVar(&recursive, "recursive", recursive, "dump recursively (all subfolders)")
	saveCmd := ffcli.Command{Name: "save", ShortHelp: "save the mails", FlagSet: FS,
		ShortUsage: "save [opts] [uids to save - empty for all]",
		Exec: func(rootCtx context.Context, args []string) error {
			uids := make([]uint32, 0, len(args))
			for _, s := range args {
				u, err := strconv.ParseUint(s, 10, 32)
				if err != nil {
					return fmt.Errorf("parse %q as uid: %w", s, err)
				}
				uids = append(uids, uint32(u))
			}
			c, err := prepare(rootCtx)
			if err != nil {
				return err
			}
			defer cClose(c)
			mbox := *saveMbox
			mailboxes := []string{mbox}
			if recursive {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
				var err error
				mailboxes, err = c.Mailboxes(ctx, mbox)
				cancel()
				if err != nil {
					logger.Error(err, "List mailboxes under", "box", mbox)
					//return err
					mailboxes = []string{mbox}
				}
			}

			dest := os.Stdout
			if !(*saveOut == "" || *saveOut == "-") {
				var err error
				dest, err = os.Create(*saveOut)
				if err != nil {
					logger.Error(err, "create", "output", *saveOut)
					return err
				}
			}
			defer func() {
				if err := dest.Close(); err != nil {
					logger.Error(err, "close output")
				}
			}()

			if !recursive {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
				err := c.Select(ctx, mbox)
				cancel()
				if err != nil {
					logger.Error(err, "SELECT", "box", mbox)
					return err
				}

				if len(uids) == 0 {
					ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
					var err error
					uids, err = c.List(ctx, mbox, "", true)
					cancel()
					if err != nil {
						logger.Error(err, "list", "box", mbox)
						return err
					}
				}

				if len(uids) == 1 {
					ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
					_, err = c.ReadTo(ctx, dest, uids[0])
					cancel()
					if err != nil {
						logger.Error(err, "Read", "uid", uids[0])
						return err
					}
				}
				tw := &syncTW{Writer: tar.NewWriter(dest)}
				err = dumpMails(rootCtx, tw, c, mbox, uids)
				if closeErr := tw.Close(); closeErr != nil && err == nil {
					err = closeErr
				}
				if err != nil {
					logger.Error(err, "dumpMails")
				}
				return err
			}

			tw := &syncTW{Writer: tar.NewWriter(dest)}
			defer func() {
				if err := tw.Close(); err != nil {
					logger.Error(err, "Close tar")
					os.Exit(1)
				}
			}()

			for _, mbox := range mailboxes {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Minute)
				uids, err := c.List(ctx, mbox, "", true)
				cancel()
				if err != nil {
					logger.Error(err, "list", "box", mbox)
					return err
				}
				if len(uids) == 0 {
					continue
				}

				if err = dumpMails(rootCtx, tw, c, mbox, uids); err != nil {
					return err
				}
			}
			return nil
		},
	}
	app.Subcommands = append(app.Subcommands, &saveCmd)

	loadCmd := ffcli.Command{Name: "load", ShortHelp: "load the mails",
		Exec: func(rootCtx context.Context, args []string) error {
			mbox := args[0]
			files := args[1:]
			c, err := prepare(rootCtx)
			if err != nil {
				return err
			}
			defer cClose(c)
			ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
			err = c.Select(ctx, mbox)
			cancel()
			if err != nil {
				return err
			}
			for _, inpFn := range files {
				var date time.Time
				var inpFh io.ReadCloser
				if inpFn == "" || inpFn == "-" {
					inpFh = os.Stdin
					date = time.Now()
				} else {
					if fh, err := os.Open(inpFn); err != nil {
						return fmt.Errorf("%s: %w", inpFn, err)
					} else if fi, err := fh.Stat(); err != nil {
						fh.Close()
						return err
					} else {
						inpFh = fh
						date = fi.ModTime()
					}
				}
				L := func(r io.Reader, date time.Time) error {
					b, err := io.ReadAll(r)
					if err != nil {
						inpFh.Close()
						return err
					}
					ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
					err = c.WriteTo(ctx, mbox, b, date)
					cancel()
					if err != nil {
						inpFh.Close()
						return err
					}
					return nil
				}
				br := bufio.NewReader(inpFh)
				b, err := br.Peek(8)
				if err != nil {
					inpFh.Close()
					return fmt.Errorf("%s: %w", inpFn, err)
				}
				if bytes.Equal(b[:2], []byte{0x1F, 0x8B}) { // GZIP
					gr, err := gzip.NewReader(br)
					if err != nil {
						inpFh.Close()
						return fmt.Errorf("%s: %w", inpFn, err)
					}
					br = bufio.NewReader(gr)
				}
				if bytes.Equal(b, []byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00}) ||
					bytes.Equal(b, []byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30}) { // TAR
					tr := tar.NewReader(br)
					for {
						th, err := tr.Next()
						if err != nil {
							if err == io.EOF {
								break
							}
							inpFh.Close()
							return err
						}
						if err = L(tr, th.ModTime); err != nil {
							return err
						}
					}
				}
				err = L(br, date)
				inpFh.Close()
				if err != nil {
					return err
				}
			}
			return nil
		},
	}
	app.Subcommands = append(app.Subcommands, &loadCmd)

	syncCmd := ffcli.Command{Name: "sync", ShortHelp: "synchronize (push missing message)",
		ShortUsage: "sync <source mailbox in 'imaps://host:port/mbox?user=a@b&passw=xxx' format> <destination mailbox in 'imaps://host:port/mbox?user=a@b&passw=xxx' format>",
		Exec: func(rootCtx context.Context, args []string) error {
			syncSrc, syncDst := args[0], args[1]
			srcM, err := imapclient.ParseMailbox(syncSrc)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
			src, err := srcM.Connect(ctx)
			cancel()
			if err != nil {
				return err
			}
			if verbose {
				src.SetLogger(logger)
				src.SetLogMask(imapclient.LogAll)
			}
			dstM, err := imapclient.ParseMailbox(syncDst)
			if err != nil {
				return err
			}
			ctx, cancel = context.WithTimeout(rootCtx, 10*time.Second)
			dst, err := dstM.Connect(ctx)
			cancel()
			if err != nil {
				return err
			}
			if verbose {
				dst.SetLogMask(imapclient.LogAll)
			}

			var wg sync.WaitGroup
			var destMails []Mail
			var destListErr error
			go func() {
				ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
				destMails, destListErr = listMbox(ctx, dst, dstM.Mailbox, true)
				cancel()
			}()

			ctx, cancel = context.WithTimeout(rootCtx, 30*time.Second)
			sourceMails, err := listMbox(ctx, src, srcM.Mailbox, true)
			cancel()
			if err != nil {
				return err
			}
			wg.Wait()
			if destListErr != nil {
				return destListErr
			}
			there := make(map[string]*Mail, len(destMails))
			for i, m := range destMails {
				there[m.MessageID] = &destMails[i]
			}

			var buf bytes.Buffer
			for _, m := range sourceMails {
				if _, ok := there[m.MessageID]; ok {
					continue
				}
				fmt.Printf("%s\t\t%q\n", m.MessageID, m.Subject)
				if err = rootCtx.Err(); err != nil {
					return err
				}
				buf.Reset()
				ctx, cancel = context.WithTimeout(rootCtx, 30*time.Second)
				_, err = src.ReadTo(ctx, &buf, m.UID)
				cancel()
				if err != nil {
					return fmt.Errorf("%s: %w", m.Subject, err)
				}
				if err = rootCtx.Err(); err != nil {
					return err
				}
				ctx, cancel = context.WithTimeout(rootCtx, 30*time.Second)
				err = dst.WriteTo(ctx, dstM.Mailbox, buf.Bytes(), m.Date)
				cancel()
				if err != nil {
					return err
				}
			}
			//fmt.Println("have: ", there)

			return nil
		},
	}
	app.Subcommands = append(app.Subcommands, &syncCmd)

	return app.ParseAndRun(rootCtx, os.Args[1:])
}

var bufPool = sync.Pool{New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 1<<20)) }}

func dumpMails(rootCtx context.Context, tw *syncTW, c imapclient.Client, mbox string, uids []uint32) error {
	ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
	err := c.Select(ctx, mbox)
	cancel()
	if err != nil {
		logger.Error(err, "SELECT", "box", mbox)
		return err
	}

	if len(uids) == 0 {
		var err error
		ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
		uids, err = c.List(ctx, mbox, "", true)
		cancel()
		if err != nil {
			logger.Error(err, "list", "box", mbox)
			return err
		}
	}

	now := time.Now()
	osUID, osGID := os.Getuid(), os.Getgid()
	logger.Info("Saving messages", "count", len(uids), "box", mbox)
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	seen := make(map[string]struct{}, 1024)
	var hshB []byte
	for _, uid := range uids {
		buf.Reset()
		ctx, cancel := context.WithTimeout(rootCtx, 10*time.Minute)
		_, err = c.ReadTo(ctx, buf, uint32(uid))
		cancel()
		if err != nil {
			logger.Error(err, "read", "uid", uid)
		}
		hsh := sha1.New()
		hsh.Write(buf.Bytes())
		hshB = hsh.Sum(hshB[:0])
		hshS := base64.URLEncoding.EncodeToString(hshB)
		if _, ok := seen[hshS]; ok {
			logger.Info("Deleting already seen.", "box", mbox, "uid", uid)
			if err := c.Delete(ctx, uid); err != nil {
				logger.Error(err, "Delete", "box", mbox, "uid", uid)
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
			logger.Error(err, "parse", "uid", uid, "bytes", buf.Bytes())
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
			Uid:      osUID, Gid: osGID,
		}); err != nil {
			tw.Unlock()
			return fmt.Errorf("WriteHeader: %w", err)
		}
		if _, err := tw.Write(buf.Bytes()); err != nil {
			tw.Unlock()
			return fmt.Errorf("write tar: %w", err)
		}

		if err := tw.Flush(); err != nil {
			tw.Unlock()
			return fmt.Errorf("flush tar: %w", err)
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
	logger.Error(err, "decode", "head", head)
	return head
}

type Mail struct {
	Date      time.Time
	MessageID string
	Subject   string
	Size      uint32
	UID       uint32
}

func listMbox(rootCtx context.Context, c imapclient.Client, mbox string, all bool) ([]Mail, error) {
	ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
	uids, err := c.List(ctx, mbox, "", all)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("LIST %q: %w", mbox, err)
	}
	if len(uids) == 0 {
		logger.Info("empty", "mbox", mbox)
		return nil, nil
	}

	result := make([]Mail, 0, len(uids))
	for len(uids) > 0 {
		if err = rootCtx.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", "listMbox", err)
		}
		n := len(uids)
		if n > fetchBatchLen {
			n = fetchBatchLen
			logger.Info("Fetching.", "n", n, "of", len(uids))
		}
		ctx, cancel = context.WithTimeout(rootCtx, 30*time.Second)
		attrs, err := c.FetchArgs(ctx, "RFC822.SIZE RFC822.HEADER", uids[:n]...)
		cancel()
		if err != nil {
			logger.Error(err, "FetchArgs", "uids", uids)
			return nil, fmt.Errorf("FetchArgs %v: %w", uids, err)
		}
		uids = uids[n:]
		for uid, a := range attrs {
			m := Mail{UID: uid}
			result = append(result, m)
			if h := a["RFC822.HEADER"]; len(h) == 0 || h[0] == "" || h[0] == "<nil>" {
				continue
			}
			hdr, err := textproto.NewReader(bufio.NewReader(strings.NewReader(a["RFC822.HEADER"][0]))).ReadMIMEHeader()
			if err != nil {
				logger.Error(err, "parse", "uid", uid, "bytes", a["RFC822.HEADER"])
				continue
			}
			m.Subject = HeadDecode(hdr.Get("Subject"))
			m.MessageID = HeadDecode(hdr.Get("Message-ID"))
			s := HeadDecode(hdr.Get("Date"))
			for _, pat := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, time.RFC850} {
				if m.Date, err = time.Parse(pat, s); err == nil {
					break
				}
			}
			if s, err := strconv.ParseUint(a["RFC822.SIZE"][0], 10, 32); err != nil {
				logger.Error(err, "size of", "uid", uid, "text", a["RFC822.SIZE"])
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
