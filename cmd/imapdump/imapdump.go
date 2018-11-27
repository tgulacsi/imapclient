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
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	_ "net/http/pprof"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
	"github.com/tgulacsi/go/loghlp/kitloghlp"
	"github.com/tgulacsi/imapclient"
	"github.com/tgulacsi/imapclient/o365"
	"gopkg.in/alecthomas/kingpin.v2"
)

const fetchBatchLen = 1024

// Log is the logger.
var logger = log.With(
	kitloghlp.Stringify{Logger: log.NewLogfmtLogger(os.Stderr)},
	"ts", log.DefaultTimestamp)

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

	app := kingpin.New("imapdump", "dump/load mail through IMAP")
	app.HelpFlag.Short('h')
	app.Flag("verbose", "verbose").Short('v').BoolVar(&verbose)

	app.Flag("username", "username").Short('U').Default(os.Getenv("IMAPDUMP_USER")).StringVar(&username)
	app.Flag("password", "password").Short('P').Default(os.Getenv("IMAPDUMP_PASS")).StringVar(&password)
	app.Flag("host", "host").Short('H').Default(host).StringVar(&host)
	app.Flag("port", "port").Short('p').Default(strconv.Itoa(port)).IntVar(&port)
	app.Flag("client-id", "Office 365 CLIENT_ID").Default(os.Getenv("CLIENT_ID")).StringVar(&clientID)
	app.Flag("client-secret", "Office 365 CLIENT_SECRET").Default(os.Getenv("CLIENT_SECRET")).StringVar(&clientSecret)
	app.Flag("impersonate", "Office 365 impersonate").StringVar(&impersonate)

	//dumpCmd := app.Command("dump", "dump mail").Default()

	listCmd := app.Command("list", "list mailbox")
	listCmd.Flag("all", "list all, not just UNSEEN").Short('a').BoolVar(&all)
	listMboxes := listCmd.Arg("mboxes", "mailboxes to list").Strings()

	treeCmd := app.Command("tree", "print the tree of mailboxes")
	treeCmd.Flag("du", "print dir sizes, too").Short('l').BoolVar(&du)
	treeMbox := treeCmd.Arg("mbox", "root mailbox").Default("INBOX").String()

	saveCmd := app.Command("save", "save the mails").Alias("dump").Alias("write")
	saveOut := saveCmd.Flag("out", "output mail(s) to this file").Short('o').Default("-").String()
	saveMbox := saveCmd.Flag("mbox", "mailbox to save from").Short('m').Default("INBOX").String()
	saveCmd.Flag("recursive", "dump recursively (all subfolders)").Short('r').BoolVar(&recursive)
	saveUIDs := saveCmd.Arg("uids", "uids to save - empty for all").Uints()

	loadCmd := app.Command("load", "load the mails").Alias("push").Alias("read")
	loadMbox := loadCmd.Arg("mbox", "mailbox to push to").String()
	loadFiles := loadCmd.Arg("files", "files to load (or a .tar)").Strings()

	syncCmd := app.Command("sync", "synchronize (push missing message)")
	syncSrc := syncCmd.Arg("source", "source mailbox in 'imaps://host:port/mbox?user=a@b&passw=xxx' format").String()
	syncDst := syncCmd.Arg("dest", "destination mailbox in 'imaps://host:port/mbox?user=a@b&passw=xxx' format").String()

	rootCtx := imapclient.CtxWithLogFunc(context.Background(), logger.Log)

	todo, err := app.Parse(os.Args[1:])
	if err != nil {
		return err
	}
	if verbose {
		imapclient.Log = log.With(logger, "lib", "imapclient").Log
	}

	var c imapclient.Client
	if todo != syncCmd.FullCommand() {
		if clientID != "" && clientSecret != "" {
			c = o365.NewIMAPClient(o365.NewClient(
				clientID, clientSecret, "http://localhost:8123",
				o365.Impersonate(impersonate),
			))
		} else {
			c = imapclient.NewClient(host, port, username, password)
			c.SetLoggerC(rootCtx)
			if verbose {
				c.SetLogMask(imapclient.LogAll)
			}
		}
		if err = c.Connect(); err != nil {
			return err
		}
		defer c.Close(false)
	}

	Log := logger.Log

	switch todo {
	//case dumpCmd.FullCommand():

	case listCmd.FullCommand():
		for _, mbox := range *listMboxes {
			mails, err := listMbox(rootCtx, c, mbox, all)
			if err != nil {
				Log("msg", "Listing", "box", mbox, "error", err)
			}
			for _, m := range mails {
				fmt.Fprintf(os.Stdout, "%d\t%d\t%s\n", m.UID, m.Size, m.Subject)
			}
		}

	case treeCmd.FullCommand():
		ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
		boxes, err := c.Mailboxes(ctx, *treeMbox)
		cancel()
		if err != nil {
			Log("msg", "LIST", "error", err)
			return err
		}
		if !du {
			for _, m := range boxes {
				fmt.Fprintln(os.Stdout, m)
			}
			return nil
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

	case saveCmd.FullCommand():
		mbox := *saveMbox
		mailboxes := []string{mbox}
		if recursive {
			ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
			var err error
			mailboxes, err = c.Mailboxes(ctx, mbox)
			cancel()
			if err != nil {
				Log("msg", "List mailboxes under", "box", mbox, "error", err)
				//return err
				mailboxes = []string{mbox}
			}
		}

		dest := os.Stdout
		if !(*saveOut == "" || *saveOut == "-") {
			var err error
			dest, err = os.Create(*saveOut)
			if err != nil {
				Log("msg", "create", "output", *saveOut, "error", err)
				return err
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
				return err
			}

			var uids []uint32
			if len(*saveUIDs) == 0 {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
				var err error
				uids, err = c.ListC(ctx, mbox, "", true)
				cancel()
				if err != nil {
					Log("msg", "list", "box", mbox, "error", err)
					return err
				}
			} else {
				uids = make([]uint32, len(*saveUIDs))
				for i, u := range *saveUIDs {
					uids[i] = uint32(u)
				}
			}

			if 1 == len(uids) {
				ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
				_, err = c.ReadToC(ctx, dest, uids[0])
				cancel()
				if err != nil {
					Log("msg", "Read", "uid", uids[0], "error", err)
					return err
				}
			}
			tw := &syncTW{Writer: tar.NewWriter(dest)}
			err = dumpMails(rootCtx, tw, c, mbox, uids)
			if closeErr := tw.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				Log("error", err)
			}
			return err
		}

		tw := &syncTW{Writer: tar.NewWriter(dest)}
		defer func() {
			if err := tw.Close(); err != nil {
				Log("msg", "Close tar", "error", err)
				os.Exit(1)
			}
		}()

		for _, mbox := range mailboxes {
			ctx, cancel := context.WithTimeout(rootCtx, 10*time.Minute)
			uids, err := c.ListC(ctx, mbox, "", true)
			cancel()
			if err != nil {
				Log("msg", "list", "box", mbox, "error", err)
				return err
			}
			if len(uids) == 0 {
				continue
			}

			if err = dumpMails(rootCtx, tw, c, mbox, uids); err != nil {
				return err
			}
		}

	case loadCmd.FullCommand():
		ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
		err = c.Select(ctx, *loadMbox)
		cancel()
		if err != nil {
			return err
		}
		for _, inpFn := range *loadFiles {
			var date time.Time
			var inpFh io.ReadCloser
			if inpFn == "" || inpFn == "-" {
				inpFh = os.Stdin
				date = time.Now()
			} else {
				if fh, err := os.Open(inpFn); err != nil {
					return errors.Wrap(err, inpFn)
				} else if fi, err := fh.Stat(); err != nil {
					fh.Close()
					return err
				} else {
					inpFh = fh
					date = fi.ModTime()
				}
			}
			L := func(r io.Reader, date time.Time) error {
				b, err := ioutil.ReadAll(r)
				if err != nil {
					inpFh.Close()
					return err
				}
				ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
				err = c.WriteTo(ctx, *loadMbox, b, date)
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
				return errors.Wrap(err, inpFn)
			}
			if bytes.Equal(b[:2], []byte{0x1F, 0x8B}) { // GZIP
				gr, err := gzip.NewReader(br)
				if err != nil {
					inpFh.Close()
					return errors.Wrap(err, inpFn)
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

	case syncCmd.FullCommand():
		srcM, err := imapclient.ParseMailbox(*syncSrc)
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
			src.SetLogMask(imapclient.LogAll)
		}
		dstM, err := imapclient.ParseMailbox(*syncDst)
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
			_, err = src.ReadToC(ctx, &buf, m.UID)
			cancel()
			if err != nil {
				return errors.Wrap(err, m.Subject)
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
	}
	return nil
}

var bufPool = sync.Pool{New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 1<<20)) }}

func dumpMails(rootCtx context.Context, tw *syncTW, c imapclient.Client, mbox string, uids []uint32) error {
	ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
	err := c.Select(ctx, mbox)
	cancel()
	Log := imapclient.GetLog(ctx)
	if err != nil {
		Log("msg", "SELECT", "box", mbox, "error", err)
		return err
	}

	if len(uids) == 0 {
		var err error
		ctx, cancel := context.WithTimeout(rootCtx, 10*time.Second)
		uids, err = c.ListC(ctx, mbox, "", true)
		cancel()
		if err != nil {
			Log("msg", "list", "box", mbox, "error", err)
			return err
		}
	}

	now := time.Now()
	osUID, osGID := os.Getuid(), os.Getgid()
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
		hsh.Write(buf.Bytes())
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
			Uid:      osUID, Gid: osGID,
		}); err != nil {
			tw.Unlock()
			return errors.Wrapf(err, "WriteHeader")
		}
		if _, err := tw.Write(buf.Bytes()); err != nil {
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
	UID       uint32
	MessageID string
	Subject   string
	Size      uint32
	Date      time.Time
}

func listMbox(rootCtx context.Context, c imapclient.Client, mbox string, all bool) ([]Mail, error) {
	ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
	uids, err := c.ListC(ctx, mbox, "", all)
	cancel()
	if err != nil {
		return nil, errors.Wrapf(err, "LIST %q", mbox)
	}
	Log := imapclient.GetLog(rootCtx)
	if len(uids) == 0 {
		Log("msg", "empty", "mbox", mbox)
		return nil, nil
	}

	result := make([]Mail, 0, len(uids))
	for len(uids) > 0 {
		if err = rootCtx.Err(); err != nil {
			return nil, errors.Wrap(err, "listMbox")
		}
		n := len(uids)
		if n > fetchBatchLen {
			n = fetchBatchLen
			Log("msg", "Fetching.", "n", n, "of", len(uids))
		}
		ctx, cancel = context.WithTimeout(rootCtx, 30*time.Second)
		attrs, err := c.FetchArgs(ctx, "RFC822.SIZE RFC822.HEADER", uids[:n]...)
		cancel()
		if err != nil {
			Log("msg", "FetchArgs", "uids", uids, "error", err)
			return nil, errors.Wrapf(err, "FetchArgs %v", uids)
		}
		uids = uids[n:]
		for uid, a := range attrs {
			m := Mail{UID: uid}
			result = append(result, m)
			hdr, err := textproto.NewReader(bufio.NewReader(strings.NewReader(a["RFC822.HEADER"][0]))).ReadMIMEHeader()
			if err != nil {
				Log("msg", "parse", "uid", uid, "error", err)
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
