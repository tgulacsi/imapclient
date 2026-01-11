// Copyright 2025, 2026 Tamás Gulácsi.
//
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message/mail"
)

func TestParseAddressList(t *testing.T) {
	for nm, elt := range map[string]struct {
		In   string
		Want []imap.Address
	}{
		"missing@": {
			In:   `"a.k@g.h" <a.k@g.h>, "P A" <a.p@a.h>, "N B" <b.n@i.h>, "B.G@a.h" <B.G@a.h>, "B P" <b.p@k.h>, "B D" <B.D@m.h>, "B.Z@a.h" <B.Z@a.h>, "B.Z@a.h" <B.Z@a.h>, "C K" <C.K@k.h>, "C A" <c.a@c.e>, "H-C E" <C.E@s.h>, "C S" <C.S@u.h>, "E J" <e.j@u.h>, "F G" <F.G@u.h>, "F G" <F.G@s.h>, "H G" <G.H@g.c>, "T G" <g.t@a.h>, "V G" <g.v@a.h>, "g.t@a.h" <g.t@a.h>, "V G" <g.v@i.h>, "H.I@a.h" <H.I@a.h>, "I H" <i.h@u.h>, "d. P I" <I.P@i.h>, "j.m@g.h" <j.m@g.h>, "C J" <j.c@g.c>, "j.s@m.h" <j.s@m.h>, "S-H J" <J.S-H@i.h>, "K.A@a.h" <K.A@a.h>, "S K" <k.s@g.h>, "V L" <l.2.v@a.h>, "l.c@g.h" <l.c@g.h>, "L K" <L.K@s.h>, "L.S@g.h" <L.S@g.h>, "M Z" <M.Z@u.h>, "M J" <m@k.h>, "O M" <m.o@i.h>, "R M" <m.r@i.h>, "D. S M" <m.s@m.h>, "M.G@a.h" <M.G@a.h>, "M.P@a.h" <M e.P@a.h>, "S N" <n.s@a.h>, "E N S" <N.S@k.h>, "P-T.L@a.h" <P-T.L@a.h>, "V P" <P.V@q.c>, "P Z" <P.Z@m.h>, "R M" <r.m@c.e>, "S G" <S.G@u.h>, "S.A@a.h" <S.A@a.h>, "S G" <s.g@w.h>, "S.T@a.h" <S.T@a.h>, "G T" <T.G@u.h>, "T T" <t.t@k.h>, "V F" <v.f@u.h>, "Z B" <z.b@u.h>, "H Z" <Z.H@g.c>, "Z Z" <Z.Z@s.h>`,
			Want: []imap.Address{},
		},
	} {
		t.Run(nm, func(t *testing.T) {
			const k = "To"
			mh := mail.HeaderFromMap(map[string][]string{
				k: []string{elt.In},
			})
			// t.Log(mh.Header.Header.Raw(k))
			aa := parseAddressList(t.Context(), mh, k)
			if len(aa) == 0 {
				t.Error("parse fail")
			}
		})
	}
}

func TestMailSplit(t *testing.T) {
	dis, err := os.ReadDir("testdata")
	if err != nil && len(dis) == 0 {
		t.Fatal(err)
	}
	for _, di := range dis {
		if !strings.HasSuffix(di.Name(), ".eml") && !strings.HasSuffix(di.Name(), ".eml.gz") {
			continue
		}
		t.Run(di.Name(), func(t *testing.T) {
			fh, err := os.Open(filepath.Join("testdata", di.Name()))
			if err != nil {
				t.Fatal(err)
			}
			defer fh.Close()
			r := io.Reader(fh)
			if strings.HasSuffix(fh.Name(), ".gz") {
				gr, err := gzip.NewReader(r)
				if err != nil {
					t.Fatal(err)
				}
				defer gr.Close()
				r = gr
			}

			b, err := io.ReadAll(r)
			m := message{GetBuf: func() ([]byte, error) { return b, err }}
			var buf bytes.Buffer
			if err = m.writeBodySection(t.Context(), &buf, &imap.FetchItemBodySection{}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b, buf.Bytes()) {
				t.Error("buf:", buf.String())
			}
			buf.Reset()
			if err = m.writeBodySection(t.Context(), &buf, &imap.FetchItemBodySection{Part: []int{0}}); err != nil {
				t.Fatal(err)
			}
			t.Log("buf:", buf.String())
		})
	}
}
