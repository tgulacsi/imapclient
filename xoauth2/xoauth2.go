// Copyright (c) 2012, Quinn Slack
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package xoauth2 is Go library for generating XOAuth2 strings (for use in XOAUTH2 SASL auth schemes for IMAP/SMTP)
//
// Copied from https://github.com/sqs/go-xoauth2
//
package xoauth2

import (
	"encoding/base64"
)

// OAuth2String generates an unencoded XOAuth2 string of the form
//   "user=" {User} "^Aauth=Bearer " {Access Token} "^A^A"
// as defined at https://developers.google.com/google-apps/gmail/xoauth2_protocol#the_sasl_xoauth2_mechanism
// (^A represents a Control+A (\001)).
//
// The function XOAuth2String in this package returns the base64 encoding of this string.
func OAuth2String(user, accessToken string) string {
	return "user=" + user + "\001auth=Bearer " + accessToken + "\001\001"
}

// XOAuth2String generates a base64-encoded XOAuth2 string suitable for use in SASL XOAUTH2, as
// defined at https://developers.google.com/google-apps/gmail/xoauth2_protocol#the_sasl_xoauth2_mechanism.
//
// (Use the base64 encoding mechanism defined in RFC 4648.)
func XOAuth2String(user, accessToken string) string {
	return base64.StdEncoding.EncodeToString([]byte(
		OAuth2String(user, accessToken),
	))
}
