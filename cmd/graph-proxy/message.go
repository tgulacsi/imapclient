/*
The MIT License (MIT)

Copyright (c) 2013 The Go-IMAP Authors
Copyright (c) 2016 Proton Technologies AG
Copyright (c) 2023 Simon Ser

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/UNO-SOFT/zlog/v2"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	gomessage "github.com/emersion/go-message"
	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
	"github.com/tgulacsi/go/iohlp"
	"golang.org/x/text/encoding/charmap"
)

func init() {
	charset.RegisterEncoding("iso-8859-2", charmap.ISO8859_2)
	charset.RegisterEncoding("iso8859-2", charmap.ISO8859_2)
}

type message struct {
	t time.Time

	GetBuf func() ([]byte, error)
	Header gomessage.Header
	Flags  map[imap.Flag]struct{}
	Buf    []byte
	UID    imap.UID
}

func (msg *message) getBuf() ([]byte, error) {
	var err error
	if len(msg.Buf) == 0 && msg.GetBuf != nil {
		msg.Buf, err = msg.GetBuf()
		msg.GetBuf = nil
	}
	return msg.Buf, err
}

func (msg *message) getHeader() (gomessage.Header, error) {
	if msg.Header.Len() == 0 {
		buf, err := msg.getBuf()
		if err != nil {
			return msg.Header, err
		}
		ent, err := gomessage.Read(bytes.NewReader(buf))
		if err != nil {
			return msg.Header, err
		}
		msg.Header = ent.Header
		fixReferences(&msg.Header)
	}
	return msg.Header, nil
}

func (msg *message) fetch(ctx context.Context, w *imapserver.FetchResponseWriter, options *imap.FetchOptions) error {
	header, err := msg.getHeader()
	if err != nil {
		return err
	}

	w.WriteUID(msg.UID)
	defer w.Close()

	if options.Flags {
		w.WriteFlags(msg.flagList())
	}
	if options.InternalDate {
		if msg.t.IsZero() {
			msg.t = parseDate(header.Get("Date"))
		}
		w.WriteInternalDate(msg.t)
	}
	if options.RFC822Size {
		buf, err := msg.getBuf()
		if err != nil {
			return err
		}
		w.WriteRFC822Size(int64(len(buf)))
	}
	if options.Envelope {
		hdr, err := msg.getHeader()
		if err != nil {
			return err
		}
		env, err := getEnvelope(ctx, hdr)
		if err != nil {
			return err
		}
		w.WriteEnvelope(env)
	}
	if bs := options.BodyStructure; bs != nil {
		bs, err := msg.bodyStructure(ctx, bs.Extended)
		if err != nil {
			return err
		}
		w.WriteBodyStructure(bs)
	}

	var buf bytes.Buffer
	W := func(g func(w io.Writer) error, f func(int64) io.WriteCloser) error {
		buf.Reset()
		if err := g(&buf); err != nil {
			return err
		}
		wc := f(int64(buf.Len()))
		_, writeErr := wc.Write(buf.Bytes())
		closeErr := wc.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	}
	for _, bs := range options.BodySection {
		if err := W(
			func(w io.Writer) error { return msg.writeBodySection(ctx, w, bs) },
			func(length int64) io.WriteCloser { return w.WriteBodySection(bs, length) },
		); err != nil {
			return err
		}
	}

	for _, bs := range options.BinarySection {
		if err := W(
			func(w io.Writer) error { return msg.writeBinarySection(ctx, w, bs) },
			func(length int64) io.WriteCloser { return w.WriteBinarySection(bs, length) },
		); err != nil {
			return err
		}
	}

	for _, bs := range options.BinarySectionSize {
		size, err := msg.getBinarySectionSize(ctx, bs)
		if err != nil {
			return err
		}
		w.WriteBinarySectionSize(bs, size)
	}
	// TODO: BinarySectionSize

	return w.Close()
}

func (msg *message) bodyStructure(ctx context.Context, extended bool) (imap.BodyStructure, error) {
	buf, err := msg.getBuf()
	if err != nil {
		return nil, err
	}
	return getBodyStructure(ctx, bytes.NewReader(buf), extended)
}

var errFound = errors.New("already found")

func (msg *message) findPart(ctx context.Context, part []int, text bool) (*gomessage.Entity, error) {
	b, err := msg.getBuf()
	if err != nil {
		return nil, err
	}
	ent, err := gomessage.Read(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	logger := zlog.SFromContext(ctx)

	// https://www.rfc-editor.org/rfc/rfc3501#page-54
	// An empty section specification refers to the entire message, including the header.
	if part == nil {
		return ent, nil
	}

	var found *gomessage.Entity
	// for i := range part {
	// 	part[i]--
	// }
	want := fmt.Sprintf("%v", part)
	if err := ent.Walk(gomessage.WalkFunc(func(path []int, ent *gomessage.Entity, err error) error {
		logger.Debug("Walk", "path", path, "want", want, "error", err)
		if found != nil {
			return errFound
		}
		if len(part) == 0 {
			if text {
				if ct, _, _ := ent.Header.ContentType(); strings.HasPrefix(ct, "text/") {
					found = ent
					return errFound
				}
			}
			found = ent
			return errFound
		}
		if err != nil {
			return err
		}
		for i := range path {
			path[i]++
		}
		got := fmt.Sprintf("%v", path)
		if got == want {
			if logger.Enabled(ctx, slog.LevelDebug) {
				logger.Debug("found", "path", got, "hdr", ent.Header.Header.Map())
			}
			found = ent
			return errFound
		}
		logger.Debug("miss", "have", got, "want", want)
		return nil
	})); err != nil && !errors.Is(err, errFound) {
		return nil, err
	}
	if found == nil {
		logger.Warn("no found")
		if len(part) == 0 {
			logger.Warn("no Part, use root")
			found = ent
		} else {
			return found, fmt.Errorf("path %v not found", part)
		}
	}
	return found, nil
}
func (msg *message) getBinarySectionSize(ctx context.Context, item *imap.FetchItemBinarySectionSize) (uint32, error) {
	found, err := msg.findPart(ctx, item.Part, false)
	if err != nil {
		return 0, err
	}
	// logger := zlog.SFromContext(ctx)
	n, err := io.Copy(io.Discard, found.Body)
	return uint32(n), err
}

func (msg *message) writeBinarySection(ctx context.Context, w io.Writer, item *imap.FetchItemBinarySection) error {
	found, err := msg.findPart(ctx, item.Part, false)
	if err != nil {
		return err
	}
	// logger := zlog.SFromContext(ctx)
	body := found.Body
	if partial := item.Partial; partial != nil {
		if partial.Offset > 0 {
			io.CopyN(io.Discard, body, partial.Offset)
		}
		body = io.LimitReader(body, partial.Size)
	}
	_, err = io.Copy(w, body)
	return err
}

func (msg *message) writeBodySection(ctx context.Context, w io.Writer, item *imap.FetchItemBodySection) error {
	found, err := msg.findPart(ctx, item.Part, item.Specifier == imap.PartSpecifierText)
	if err != nil {
		return err
	}
	header := found.Header.Copy()

	// gomessage already decoded the transfer and the text
	header.Del("Content-Transfer-Encoding")
	if ct := header.Get("Content-Type"); strings.HasPrefix(ct, "text/") {
		if pre, _, ok := strings.Cut(ct, "charset="); ok {
			header.Set("Content-Type", pre)
		}
	}

	// Filter header fields
	if len(item.HeaderFields) > 0 {
		keep := make(map[string]struct{})
		for _, k := range item.HeaderFields {
			keep[strings.ToLower(k)] = struct{}{}
		}
		for field := header.Fields(); field.Next(); {
			if _, ok := keep[strings.ToLower(field.Key())]; !ok {
				field.Del()
			}
		}
	}
	for _, k := range item.HeaderFieldsNot {
		header.Del(k)
	}

	logger := zlog.SFromContext(ctx)
	if logger.Enabled(ctx, slog.LevelDebug) {
		logger.Debug("writeBodySection", "item", item, "found", found.Header.Header.Map())
	}
	writeHeader := true
	switch item.Specifier {
	case imap.PartSpecifierNone:
		writeHeader = len(item.Part) == 0
	case imap.PartSpecifierText:
		writeHeader = false
	}
	if writeHeader {
		if err := textproto.WriteHeader(w, header.Header); err != nil {
			return err
		}
	}

	body := found.Body
	if partial := item.Partial; partial != nil {
		if partial.Offset > 0 {
			io.CopyN(io.Discard, body, partial.Offset)
		}
		body = io.LimitReader(body, partial.Size)
	}

	switch item.Specifier {
	case imap.PartSpecifierNone, imap.PartSpecifierText:
		// var buf strings.Builder
		// if _, err := io.Copy(w, io.TeeReader(body, &buf)); err != nil {
		if _, err := io.Copy(w, body); err != nil {
			return err
		}
		// logger.Info("written", "buf", buf.String())
	}

	return nil
}

func (msg *message) flagList() []imap.Flag {
	var flags []imap.Flag
	for flag := range msg.Flags {
		flags = append(flags, flag)
	}
	return flags
}

func getEnvelope(ctx context.Context, hdr gomessage.Header) (*imap.Envelope, error) {
	mh := mail.Header{Header: gomessage.Header{Header: hdr.Header}}
	date, _ := mh.Date()
	inReplyTo, _ := mh.MsgIDList("In-Reply-To")
	messageID, err := mh.MessageID()
	if err != nil {
		logger := zlog.SFromContext(ctx)
		logger.Warn("MessageID", "msgID", messageID, "error", err, "headers", mh)
		messageID, _, _ = strings.Cut(messageID, " ")
		err = nil
	}
	// messageID, _, _ = strings.Cut(messageID, " ")
	P := func(k string) []imap.Address { return parseAddressList(ctx, mh, k) }
	return &imap.Envelope{
		Date:      date,
		Subject:   hdr.Get("Subject"),
		From:      P("From"),
		Sender:    P("Sender"),
		ReplyTo:   P("Reply-To"),
		To:        P("To"),
		Cc:        P("Cc"),
		Bcc:       P("Bcc"),
		InReplyTo: inReplyTo,
		MessageID: messageID,
	}, err
}

var (
	rSpaceInAnglesMu sync.Mutex
	rSpaceInAngles   *regexp.Regexp
)

func parseAddressList(ctx context.Context, mh mail.Header, k string) []imap.Address {
	// TODO: leave the quoted words unchanged
	// TODO: handle groups
	addrs, err := mh.AddressList(k)
	if err != nil {
		raw, _ := mh.Header.Header.Raw(k)
		logger := zlog.SFromContext(ctx)
		if logger.Enabled(ctx, slog.LevelDebug) {
			logger.Debug("parseAddressList", "k", k, "raw", string(raw), "error", err)
		}
		rSpaceInAnglesMu.Lock()
		if rSpaceInAngles == nil {
			rSpaceInAngles = regexp.MustCompile("<[^>]* [^>]*>")
		}
		raw = rSpaceInAngles.ReplaceAllFunc(raw, func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte{' '}, nil)
		})
		rSpaceInAnglesMu.Unlock()
		// raw = bytes.ReplaceAll(raw, []byte("\r\n"), nil)
		mh2 := mail.Header{}
		mh2.AddRaw(raw)
		raw, _ = mh2.Header.Header.Raw(k)
		if addrs, err = mh2.AddressList(k); err != nil {
			logger.Error("parseAddressList2", "k", k, "raw", string(raw), "error", err)
		}
	}
	var l []imap.Address
	for _, addr := range addrs {
		mailbox, host, ok := strings.Cut(addr.Address, "@")
		if !ok {
			continue
		}
		l = append(l, imap.Address{
			Name:    mime.QEncoding.Encode("utf-8", addr.Name),
			Mailbox: mailbox,
			Host:    host,
		})
	}
	return l
}

func getBodyStructure(ctx context.Context, r io.Reader, extended bool) (imap.BodyStructure, error) {
	logger := zlog.SFromContext(ctx)

	P := func(ent *gomessage.Entity) (imap.BodyStructure, error) {
		header := ent.Header
		mediaType, typeParams, err := header.ContentType()
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(mediaType, "multipart/") {
			bs := imap.BodyStructureMultiPart{
				Subtype: strings.TrimPrefix(mediaType, "multipart/"),
			}
			if extended {
				bs.Extended = &imap.BodyStructureMultiPartExt{
					Params:      typeParams,
					Disposition: getContentDisposition(header),
					Language:    getContentLanguage(header),
					Location:    header.Get("Content-Location"),
				}
			}
			return &bs, nil
		}

		primaryType, subType, _ := strings.Cut(mediaType, "/")
		sr, err := iohlp.MakeSectionReader(ent.Body, 1<<20)
		if err != nil {
			return nil, err
		}
		bs := imap.BodyStructureSinglePart{
			Type:        primaryType,
			Subtype:     subType,
			Params:      typeParams,
			ID:          header.Get("Content-Id"),
			Description: header.Get("Content-Description"),
			// Encoding:    header.Get("Content-Transfer-Encoding"),
			Size: uint32(sr.Size()),
		}
		// logger.Info("singlePart", "bs", bs)
		if mediaType == "message/rfc822" || mediaType == "message/global" {
			ent, err := gomessage.Read(io.NewSectionReader(sr, 0, sr.Size()))
			if err != nil {
				return nil, err
			}
			br, err := iohlp.MakeSectionReader(ent.Body, 1<<20)
			if err != nil {
				return nil, err
			}
			bs.MessageRFC822 = &imap.BodyStructureMessageRFC822{
				NumLines: countLines(io.NewSectionReader(br, 0, br.Size())),
			}
			if bs.MessageRFC822.Envelope, err = getEnvelope(ctx, ent.Header); err != nil {
				return &bs, err
			}
			if bs.MessageRFC822.BodyStructure, err = getBodyStructure(ctx,
				br, extended,
			); err != nil {
				return &bs, err
			}
		}
		if primaryType == "text" {
			bs.Text = &imap.BodyStructureText{
				NumLines: countLines(io.NewSectionReader(sr, 0, sr.Size())),
			}
		}
		if extended {
			bs.Extended = &imap.BodyStructureSinglePartExt{
				Disposition: getContentDisposition(header),
				Language:    getContentLanguage(header),
				Location:    header.Get("Content-Location"),
			}
		}
		return &bs, nil
	}

	ent, err := gomessage.Read(r)
	if err != nil {
		return nil, err
	}
	mediaType, _, err := ent.Header.ContentType()
	if err != nil {
		return nil, fmt.Errorf("Content-Type of %+v: %w", ent.Header, err)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		m := make(map[string]*imap.BodyStructureMultiPart)
		if err = ent.Walk(gomessage.WalkFunc(func(
			path []int, ent *gomessage.Entity, err error,
		) error {
			if err != nil {
				logger.Error("Walk", "path", path, "error", err)
				return nil
			}
			part, err := P(ent)
			if err != nil {
				return err
			}
			if mp, ok := part.(*imap.BodyStructureMultiPart); ok {
				m[fmt.Sprintf("%v", path)] = mp
			}
			logger.Debug("Walk", "path", path, "m", m)
			if len(path) != 0 {
				bs := m[fmt.Sprintf("%v", path[:len(path)-1])]
				bs.Children = append(bs.Children, part)
			}

			return nil
		})); err != nil {
			return nil, err
		}

		var surr imap.BodyStructureSinglePart
		for path, bs := range m {
			if len(bs.Children) != 0 {
				continue
			}
			var pk string
			if i := strings.LastIndexByte(path, ','); i >= 0 {
				pk = path[:i] + "]"
			}
			logger.Error("multipart no children", "path", path, "bs", bs, "pk", pk, "parent", m[pk])

			if surr.Type == "" {
				surr = imap.BodyStructureSinglePart{
					Type: "text", Subtype: "plain",
					Text: &imap.BodyStructureText{NumLines: 1},
				}
				if extended {
					surr.Extended = &imap.BodyStructureSinglePartExt{
						Language: []string{"en-US"},
					}
				}
			}
			surr := surr
			surr.ID = path
			bs.Children = append(bs.Children, &surr)
			m[path] = bs
		}
		bs := m["[]"]
		logger.Debug("BodyStructureMultipart", "bs", bs)
		var check func(mp *imap.BodyStructureMultiPart)
		check = func(mp *imap.BodyStructureMultiPart) {
			if len(mp.Children) == 0 {
				panic("no children")
			}
			for _, c := range mp.Children {
				if mp, ok := c.(*imap.BodyStructureMultiPart); ok {
					check(mp)
				}
			}
		}
		check(bs)
		return bs, nil
	}

	return P(ent)
}

func countLines(sr *io.SectionReader) int64 {
	var count int64
	for off := int64(0); off < sr.Size(); {
		var a [4096]byte
		n, err := sr.ReadAt(a[:], off)
		off += int64(n)
		count += int64(bytes.Count(a[:n], []byte("\n")))
		if err != nil {
			break
		}
	}
	return count
}

func getContentDisposition(header gomessage.Header) *imap.BodyStructureDisposition {
	disp, dispParams, _ := header.ContentDisposition()
	if disp == "" {
		return nil
	}
	return &imap.BodyStructureDisposition{
		Value:  disp,
		Params: dispParams,
	}
}

func getContentLanguage(header gomessage.Header) []string {
	v := header.Get("Content-Language")
	if v == "" {
		return nil
	}
	// TODO: handle CFWS
	l := strings.Split(v, ",")
	for i, lang := range l {
		l[i] = strings.TrimSpace(lang)
	}
	return l
}

func parseDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, pat := range []string{time.RFC1123Z, time.RFC1123, time.RFC850, time.RFC822Z, time.RFC822, time.RFC3339} {
		if t, err := time.Parse(pat, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func fixReferences(hdr *gomessage.Header) {
	ok := true
	const key, from, to = "References", ">,<", "> <"
	ff := hdr.FieldsByKey(key)
	for ff.Next() {
		s, _ := ff.Text()
		if ok = !strings.Contains(s, from); !ok {
			break
		}
	}
	if ok {
		return
	}
	hdr2 := hdr.Copy()
	ff = hdr2.FieldsByKey(key)
	hdr.Del(key)
	for ff.Next() {
		hdr.Add(key, strings.ReplaceAll(ff.Value(), from, to))
	}
	slog.Info("replace Reference", "from", hdr2.Get(key), "to", hdr.Get(key))
}
