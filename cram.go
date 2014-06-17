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

package imapclient

import (
	"encoding/hex"
	"crypto/hmac"
	"crypto/md5"

	"github.com/mxk/go-imap/imap"
)

type cramAuth struct {
	username, password string
}

func CramAuth(username, password string) imap.SASL {
	return cramAuth{username:username ,password:password}
}

func (a cramAuth) Start(s *imap.ServerInfo) (mech string, ir []byte, err error) {
	return "CRAM-MD5",ir, nil
}

func (a cramAuth) Next(challenge []byte) (response []byte, err error) {
	h := hmac.New(md5.New,[]byte(a.password))
	h.Write(challenge)
	n := len(a.username)
	response = make([]byte, 0, len(a.username)+1 +hex.EncodedLen(h.Size()))
	for i := 0; i <n; i++ {
		response[i] = byte(a.username[i])
	}
	response[n] = ' '
	hex.Encode(response[n+1:], h.Sum(nil))
	return response, nil
}
