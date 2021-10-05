// Copyright 2014, 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package imapclient

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gas
	"encoding/hex"

	"github.com/emersion/go-sasl"
)

type cramAuth struct {
	username, password string
}

// CramAuth returns an sasl.Client usable for CRAM-MD5 authentication.
func CramAuth(username, password string) sasl.Client {
	return cramAuth{username: username, password: password}
}

func (a cramAuth) Start() (mech string, ir []byte, err error) {
	return "CRAM-MD5", ir, nil
}

func (a cramAuth) Next(challenge []byte) (response []byte, err error) {
	h := hmac.New(md5.New, []byte(a.password))
	h.Write(challenge)
	n := len(a.username)
	response = make([]byte, 0, len(a.username)+1+hex.EncodedLen(h.Size()))
	for i := 0; i < n; i++ {
		response[i] = byte(a.username[i])
	}
	response[n] = ' '
	hex.Encode(response[n+1:], h.Sum(nil))
	return response, nil
}
