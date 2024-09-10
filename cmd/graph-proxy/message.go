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
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"mime"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
)

type message struct {
	t time.Time

	// mutable, protected by Mailbox.mutex
	flags map[imap.Flag]struct{}
	buf   []byte
	// immutable
	uid imap.UID
}

func (msg *message) fetch(w *imapserver.FetchResponseWriter, options *imap.FetchOptions) error {
	br := bufio.NewReader(bytes.NewReader(msg.buf))
	header, err := textproto.ReadHeader(br)
	if err != nil {
		return nil
	}

	w.WriteUID(msg.uid)

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
		w.WriteRFC822Size(int64(len(msg.buf)))
	}
	if options.Envelope {
		w.WriteEnvelope(msg.envelope(header))
	}
	if bs := options.BodyStructure; bs != nil {
		w.WriteBodyStructure(msg.bodyStructure(bs.Extended))
	}

	for _, bs := range options.BodySection {
		buf := msg.bodySection(bs)
		wc := w.WriteBodySection(bs, int64(len(buf)))
		_, writeErr := wc.Write(buf)
		closeErr := wc.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}

	// TODO: BinarySection, BinarySectionSize

	return w.Close()
}

func (msg *message) envelope(header textproto.Header) *imap.Envelope {
	if header.Len() == 0 {
		br := bufio.NewReader(bytes.NewReader(msg.buf))
		var err error
		if header, err = textproto.ReadHeader(br); err != nil {
			return nil
		}
	}
	return getEnvelope(header)
}

func (msg *message) bodyStructure(extended bool) imap.BodyStructure {
	br := bufio.NewReader(bytes.NewReader(msg.buf))
	header, _ := textproto.ReadHeader(br)
	return getBodyStructure(header, br, extended)
}

func openMessagePart(header textproto.Header, body io.Reader, parentMediaType string) (textproto.Header, io.Reader) {
	msgHeader := gomessage.Header{Header: header}
	mediaType, _, _ := msgHeader.ContentType()
	if !msgHeader.Has("Content-Type") && parentMediaType == "multipart/digest" {
		mediaType = "message/rfc822"
	}
	if mediaType == "message/rfc822" || mediaType == "message/global" {
		br := bufio.NewReader(body)
		header, _ = textproto.ReadHeader(br)
		return header, br
	}
	return header, body
}

func (msg *message) bodySection(item *imap.FetchItemBodySection) []byte {
	var (
		header textproto.Header
		body   io.Reader
	)

	br := bufio.NewReader(bytes.NewReader(msg.buf))
	header, err := textproto.ReadHeader(br)
	if err != nil {
		return nil
	}
	body = br

	// First part of non-multipart message refers to the message itself
	msgHeader := gomessage.Header{Header: header}
	mediaType, _, _ := msgHeader.ContentType()
	partPath := item.Part
	if !strings.HasPrefix(mediaType, "multipart/") && len(partPath) > 0 && partPath[0] == 1 {
		partPath = partPath[1:]
	}

	// Find the requested part using the provided path
	var parentMediaType string
	for i := 0; i < len(partPath); i++ {
		partNum := partPath[i]

		header, body = openMessagePart(header, body, parentMediaType)

		msgHeader := gomessage.Header{Header: header}
		mediaType, typeParams, _ := msgHeader.ContentType()
		if !strings.HasPrefix(mediaType, "multipart/") {
			if partNum != 1 {
				return nil
			}
			continue
		}

		mr := textproto.NewMultipartReader(body, typeParams["boundary"])
		found := false
		for j := 1; j <= partNum; j++ {
			p, err := mr.NextPart()
			if err != nil {
				return nil
			}

			if j == partNum {
				parentMediaType = mediaType
				header = p.Header
				body = p
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}

	if len(item.Part) > 0 {
		switch item.Specifier {
		case imap.PartSpecifierHeader, imap.PartSpecifierText:
			header, body = openMessagePart(header, body, parentMediaType)
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

	// Write the requested data to a buffer
	var buf bytes.Buffer

	writeHeader := true
	switch item.Specifier {
	case imap.PartSpecifierNone:
		writeHeader = len(item.Part) == 0
	case imap.PartSpecifierText:
		writeHeader = false
	}
	if writeHeader {
		if err := textproto.WriteHeader(&buf, header); err != nil {
			return nil
		}
	}

	switch item.Specifier {
	case imap.PartSpecifierNone, imap.PartSpecifierText:
		if _, err := io.Copy(&buf, body); err != nil {
			return nil
		}
	}

	// Extract partial if any
	b := buf.Bytes()
	if partial := item.Partial; partial != nil {
		end := partial.Offset + partial.Size
		if partial.Offset > int64(len(b)) {
			return nil
		}
		if end > int64(len(b)) {
			end = int64(len(b))
		}
		b = b[partial.Offset:end]
	}
	return b
}

func (msg *message) flagList() []imap.Flag {
	var flags []imap.Flag
	for flag := range msg.flags {
		flags = append(flags, flag)
	}
	return flags
}

func getEnvelope(h textproto.Header) *imap.Envelope {
	mh := mail.Header{Header: gomessage.Header{Header: h}}
	date, _ := mh.Date()
	inReplyTo, _ := mh.MsgIDList("In-Reply-To")
	messageID, _ := mh.MessageID()
	return &imap.Envelope{
		Date:      date,
		Subject:   h.Get("Subject"),
		From:      parseAddressList(mh, "From"),
		Sender:    parseAddressList(mh, "Sender"),
		ReplyTo:   parseAddressList(mh, "Reply-To"),
		To:        parseAddressList(mh, "To"),
		Cc:        parseAddressList(mh, "Cc"),
		Bcc:       parseAddressList(mh, "Bcc"),
		InReplyTo: inReplyTo,
		MessageID: messageID,
	}
}

func parseAddressList(mh mail.Header, k string) []imap.Address {
	// TODO: leave the quoted words unchanged
	// TODO: handle groups
	addrs, err := mh.AddressList(k)
	if err != nil {
		raw, _ := mh.Header.Header.Raw(k)
		slog.Warn("parseAddressList", "k", k, "raw", string(raw), "error", err)
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

func getBodyStructure(rawHeader textproto.Header, r io.Reader, extended bool) imap.BodyStructure {
	header := gomessage.Header{Header: rawHeader}

	mediaType, typeParams, _ := header.ContentType()
	primaryType, subType, _ := strings.Cut(mediaType, "/")

	if primaryType == "multipart" {
		bs := &imap.BodyStructureMultiPart{Subtype: subType}
		mr := textproto.NewMultipartReader(r, typeParams["boundary"])
		for {
			part, _ := mr.NextPart()
			if part == nil {
				break
			}
			bs.Children = append(bs.Children, getBodyStructure(part.Header, part, extended))
		}
		if extended {
			bs.Extended = &imap.BodyStructureMultiPartExt{
				Params:      typeParams,
				Disposition: getContentDisposition(header),
				Language:    getContentLanguage(header),
				Location:    header.Get("Content-Location"),
			}
		}
		return bs
	} else {
		body, _ := io.ReadAll(r) // TODO: optimize
		bs := &imap.BodyStructureSinglePart{
			Type:        primaryType,
			Subtype:     subType,
			Params:      typeParams,
			ID:          header.Get("Content-Id"),
			Description: header.Get("Content-Description"),
			Encoding:    header.Get("Content-Transfer-Encoding"),
			Size:        uint32(len(body)),
		}
		if mediaType == "message/rfc822" || mediaType == "message/global" {
			br := bufio.NewReader(bytes.NewReader(body))
			childHeader, _ := textproto.ReadHeader(br)
			bs.MessageRFC822 = &imap.BodyStructureMessageRFC822{
				Envelope:      getEnvelope(childHeader),
				BodyStructure: getBodyStructure(childHeader, br, extended),
				NumLines:      int64(bytes.Count(body, []byte("\n"))),
			}
		}
		if primaryType == "text" {
			bs.Text = &imap.BodyStructureText{
				NumLines: int64(bytes.Count(body, []byte("\n"))),
			}
		}
		if extended {
			bs.Extended = &imap.BodyStructureSinglePartExt{
				Disposition: getContentDisposition(header),
				Language:    getContentLanguage(header),
				Location:    header.Get("Content-Location"),
			}
		}
		return bs
	}
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
