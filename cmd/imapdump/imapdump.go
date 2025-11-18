// Copyright 2019, 2025 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
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

	"golang.org/x/oauth2"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"

	"github.com/UNO-SOFT/zlog/v2"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/tgulacsi/imapclient/graph"
	"github.com/tgulacsi/imapclient/v2"
	"github.com/tgulacsi/imapclient/v2/o365"
)

const fetchBatchLen = 1024

var verbose zlog.VerboseVar
var logger = zlog.NewLogger(zlog.MaybeConsoleHandler(&verbose, os.Stderr)).SLog()

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v", err)
	}
}

func Main() error {
	var (
		username, password     string
		recursive, all, du     bool
		clientID, clientSecret string
		tenantID, userID       string
		impersonate            string
	)
	host := os.Getenv("IMAPDUMP_HOST")
	port := 143
	if s := os.Getenv("IMAPDUMP_PORT"); s != "" {
		if i, err := strconv.Atoi(s); err == nil {
			port = i
		}
	}
	FS := ff.NewFlagSet("global")
	FS.Value('v', "verbose", &verbose, "log verbose")
	FS.StringVar(&username, 'u', "username", os.Getenv("IMAPDUMP_USER"), "username")
	FS.StringVar(&password, 'p', "password", os.Getenv("IMAPDUMP_PASS"), "password")
	FS.StringVar(&host, 'H', "host", host, "host")
	FS.IntVar(&port, 'P', "port", port, "port")
	FS.StringVar(&clientID, 0, "client-id", os.Getenv("CLIENT_ID"), "Office 365 CLIENT_ID")
	FS.StringVar(&clientSecret, 0, "client-secret", os.Getenv("CLIENT_SECRET"), "Office 365 CLIENT_SECRET")
	flagClientCertsFile := FS.StringLong("client-certs", "", "client certificates file")
	FS.StringVar(&tenantID, 'T', "tenant-id", os.Getenv("TENANT_ID"), "Office 365 tenant ID")
	FS.StringVar(&impersonate, 0, "impersonate", "", "Office 365 impersonate")
	FS.StringVar(&userID, 'U', "user-id", os.Getenv("USER_ID"), "Office 365 user ID. Implies Graph API")
	flagForceTLS := FS.BoolLong("force-tls", "force use of TLS")
	flagForbidTLS := FS.BoolLong("forbid-tls", "forbid (force no TLS)")

	app := ff.Command{Name: "imapdump", ShortHelp: "dump/load mail through IMAP", Flags: FS}

	rootCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	rootCtx = zlog.NewSContext(rootCtx, logger)

	prepare := func(ctx context.Context) (imapclient.Client, error) {
		var c imapclient.Client
		if clientID != "" {
			if userID != "" {
				credOpts := graph.CredentialOptions{Secret: clientSecret}
				if *flagClientCertsFile != "" {
					fh, err := os.Open(*flagClientCertsFile)
					if err != nil {
						return nil, err
					}
					if credOpts.Certs, credOpts.Key, err = graph.ParseCertificates(fh); err != nil {
						return nil, err
					}
				}
				var err error
				c, err = o365.NewGraphMailClient(ctx, clientID, tenantID, userID,
					credOpts)
				if err != nil {
					return nil, err
				}
			} else {
				if false {
					conf := &oauth2.Config{
						ClientID:     clientID,
						ClientSecret: clientSecret,
						Scopes:       []string{"https://outlook.office365.com/.default"},
					}
					ts := o365.NewConfidentialTokenSource(conf, tenantID)
					token, err := ts.Token()
					if err != nil {
						return nil, err
					}
					sa := imapclient.ServerAddress{
						Host: host, Port: 993,
						Username:  username,
						TLSPolicy: imapclient.ForceTLS,
					}.WithPassword(token.AccessToken)
					c = imapclient.FromServerAddress(sa)
					if verbose > 1 {
						c.SetLogger(logger)
						c.SetLogMask(imapclient.LogAll)
					}
				} else {
					c = o365.NewIMAPClient(o365.NewClient(
						clientID, clientSecret, "http://localhost:8123",
						o365.Impersonate(impersonate),
						o365.TenantID(tenantID),
					))
				}
			}
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
			if verbose > 1 {
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

	FS = ff.NewFlagSet("list")
	FS.BoolVar(&all, 'a', "all", "list all, not just UNSEEN")
	listCmd := ff.Command{Name: "list", ShortHelp: "list mailbox", Flags: FS,
		Exec: func(rootCtx context.Context, args []string) error {
			c, err := prepare(rootCtx)
			if err != nil {
				return err
			}
			defer cClose(c)
			if len(args) == 0 {
				args = []string{"INBOX"}
			}
			for _, mbox := range args {
				mails, err := listMbox(rootCtx, c, mbox, all)
				if err != nil {
					logger.Error("Listing", "box", mbox, "error", err)
				}
				fmt.Fprintln(os.Stdout, "UID\tSIZE\tSUBJECT")
				for _, m := range mails {
					fmt.Fprintf(os.Stdout, "%d\t%d\t%s\n", m.UID, m.Size, m.Subject)
				}
			}
			return nil
		},
	}
	app.Subcommands = append(app.Subcommands, &listCmd)

	FS = ff.NewFlagSet("tree")
	FS.BoolVar(&du, 0, "du", "print dir sizes, too")
	treeCmd := ff.Command{Name: "tree", ShortHelp: "print the tree of mailboxes", Flags: FS,
		Usage: "tree [opts] <root - INBOX by default",
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
			ctx, cancel := context.WithTimeout(rootCtx, 10*time.Minute)
			logger.Info("start Mailboxes")
			boxes, err := c.Mailboxes(ctx, mbox)
			cancel()
			logger.Info("end Mailboxes", "boxes", boxes, "du", du, "error", err)
			if err != nil {
				logger.Error("LIST", "error", err)
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
					logger.Error("list", "box", m, "error", err)
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

	FS = ff.NewFlagSet("save")
	saveOut := FS.String('o', "out", "-", "output mail(s) to this file")
	saveMbox := FS.StringLong("mbox", "INBOX", "mailbox to save from")
	FS.BoolVar(&recursive, 'r', "recursive", "dump recursively (all subfolders)")
	saveCmd := ff.Command{Name: "save", ShortHelp: "save the mails", Flags: FS,
		Usage: "save [opts] [uids to save - empty for all]",
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
				ctx, cancel := context.WithTimeout(rootCtx, 1*time.Minute)
				var err error
				mailboxes, err = c.Mailboxes(ctx, mbox)
				cancel()
				if err != nil {
					logger.Error("List mailboxes under", "box", mbox, "error", err)
					//return err
					mailboxes = []string{mbox}
				}
			}

			dest := os.Stdout
			if !(*saveOut == "" || *saveOut == "-") {
				var err error
				dest, err = os.Create(*saveOut)
				if err != nil {
					logger.Error("create", "output", *saveOut, "error", err)
					return err
				}
			}
			defer func() {
				if err := dest.Close(); err != nil {
					logger.Error("close output", "error", err)
				}
			}()

			if !recursive {
				ctx, cancel := context.WithTimeout(rootCtx, 1*time.Minute)
				err := c.Select(ctx, mbox)
				cancel()
				if err != nil {
					logger.Error("SELECT", "box", mbox, "error", err)
					return err
				}

				if len(uids) == 0 {
					ctx, cancel := context.WithTimeout(rootCtx, 1*time.Minute)
					var err error
					uids, err = c.List(ctx, mbox, "", true)
					cancel()
					if err != nil {
						logger.Error("list", "box", mbox, "error", err)
						return err
					}
				}

				if len(uids) == 1 {
					ctx, cancel := context.WithTimeout(rootCtx, 1*time.Minute)
					_, err = c.ReadTo(ctx, dest, uids[0])
					cancel()
					if err != nil {
						logger.Error("Read", "uid", uids[0], "error", err)
						return err
					}
				}
				tw := &syncTW{Writer: tar.NewWriter(dest)}
				err = dumpMails(rootCtx, tw, c, mbox, uids)
				if closeErr := tw.Close(); closeErr != nil && err == nil {
					err = closeErr
				}
				if err != nil {
					logger.Error("dumpMails", "error", err)
				}
				return err
			}

			tw := &syncTW{Writer: tar.NewWriter(dest)}
			defer func() {
				if err := tw.Close(); err != nil {
					logger.Error("Close tar", "error", err)
					os.Exit(1)
				}
			}()

			for _, mbox := range mailboxes {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Minute)
				uids, err := c.List(ctx, mbox, "", true)
				cancel()
				if err != nil {
					logger.Error("list", "box", mbox, "error", err)
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

	loadCmd := ff.Command{Name: "load", ShortHelp: "load the mails",
		Exec: func(rootCtx context.Context, args []string) error {
			mbox := args[0]
			files := args[1:]
			c, err := prepare(rootCtx)
			if err != nil {
				return err
			}
			defer cClose(c)
			ctx, cancel := context.WithTimeout(rootCtx, 1*time.Minute)
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
					ctx, cancel := context.WithTimeout(rootCtx, 3*time.Minute)
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

	syncCmd := ff.Command{Name: "sync", ShortHelp: "synchronize (push missing message)",
		Usage: "sync <source mailbox in 'imaps://host:port/mbox?user=a@b&passw=xxx' format> <destination mailbox in 'imaps://host:port/mbox?user=a@b&passw=xxx' format>",
		Exec: func(rootCtx context.Context, args []string) error {
			syncSrc, syncDst := args[0], args[1]
			srcM, err := imapclient.ParseMailbox(syncSrc)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(rootCtx, 1*time.Minute)
			src, err := srcM.Connect(ctx)
			cancel()
			if err != nil {
				return err
			}
			if verbose > 1 {
				src.SetLogger(logger)
				src.SetLogMask(imapclient.LogAll)
			}
			dstM, err := imapclient.ParseMailbox(syncDst)
			if err != nil {
				return err
			}
			ctx, cancel = context.WithTimeout(rootCtx, 1*time.Minute)
			dst, err := dstM.Connect(ctx)
			cancel()
			if err != nil {
				return err
			}
			if verbose > 1 {
				dst.SetLogMask(imapclient.LogAll)
			}

			var wg sync.WaitGroup
			var destMails []Mail
			var destListErr error
			go func() {
				ctx, cancel := context.WithTimeout(rootCtx, 3*time.Minute)
				destMails, destListErr = listMbox(ctx, dst, dstM.Mailbox, true)
				cancel()
			}()

			ctx, cancel = context.WithTimeout(rootCtx, 3*time.Minute)
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
				ctx, cancel = context.WithTimeout(rootCtx, 3*time.Minute)
				_, err = src.ReadTo(ctx, &buf, m.UID)
				cancel()
				if err != nil {
					return fmt.Errorf("%s: %w", m.Subject, err)
				}
				if err = rootCtx.Err(); err != nil {
					return err
				}
				ctx, cancel = context.WithTimeout(rootCtx, 3*time.Minute)
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
	if err := app.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, ff.ErrHelp) {
			ffhelp.Command(&app).WriteTo(os.Stderr)
			return nil
		}
		return err
	}

	return app.Run(rootCtx)
}

var bufPool = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 1<<20)) }}

func dumpMails(rootCtx context.Context, tw *syncTW, c imapclient.Client, mbox string, uids []uint32) error {
	ctx, cancel := context.WithTimeout(rootCtx, 1*time.Minute)
	err := c.Select(ctx, mbox)
	cancel()
	if err != nil {
		logger.Error("SELECT", "box", mbox, "error", err)
		return err
	}

	if len(uids) == 0 {
		var err error
		ctx, cancel := context.WithTimeout(rootCtx, 1*time.Minute)
		uids, err = c.List(ctx, mbox, "", true)
		cancel()
		if err != nil {
			logger.Error("list", "box", mbox, "error", err)
			return err
		}
	}

	now := time.Now()
	osUID, osGID := os.Getuid(), os.Getgid()
	logger.Info("Saving messages", "count", len(uids), "box", mbox)
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	seen := make(map[string]struct{}, 1024)
	hsh := imapclient.NewHash()
	for _, uid := range uids {
		buf.Reset()
		ctx, cancel := context.WithTimeout(rootCtx, 10*time.Minute)
		_, err = c.ReadTo(ctx, buf, uint32(uid))
		cancel()
		if err != nil {
			logger.Error("read", "uid", uid, "error", err)
		}
		hsh.Reset()
		hsh.Write(buf.Bytes())
		hshS := hsh.Array().String()
		if _, ok := seen[hshS]; ok {
			logger.Info("Deleting already seen.", "box", mbox, "uid", uid)
			if err := c.Delete(ctx, uid); err != nil {
				logger.Error("Delete", "box", mbox, "uid", uid, "error", err)
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
			logger.Error("parse", "uid", uid, "bytes", buf.Bytes(), "error", err)
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
	logger.Error("decode", "head", head, "error", err)
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
	ctx, cancel := context.WithTimeout(rootCtx, 3*time.Minute)
	uids, err := c.List(ctx, mbox, "", all)
	cancel()
	// logger.Info("listMbox", "uids", uids, "error", err)
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
		ctx, cancel = context.WithTimeout(rootCtx, 3*time.Minute)
		attrs, err := c.FetchArgs(ctx, "RFC822.SIZE RFC822.HEADER", uids[:n]...)
		cancel()
		if err != nil {
			logger.Error("FetchArgs", "uids", uids, "error", err)
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
				logger.Error("parse", "uid", uid, "bytes", a["RFC822.HEADER"], "error", err)
				continue
			}
			m.Subject = HeadDecode(hdr.Get("Subject"))
			m.MessageID = HeadDecode(hdr.Get("Message-ID"))
			s := HeadDecode(hdr.Get("Date"))
			for _, pat := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, time.RFC850} {
				if d, err := time.Parse(pat, s); err == nil {
					m.Date = d
					break
				}
			}
			if s, err := strconv.ParseUint(a["RFC822.SIZE"][0], 10, 32); err != nil {
				logger.Error("size of", "uid", uid, "text", a["RFC822.SIZE"], "error", err)
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
