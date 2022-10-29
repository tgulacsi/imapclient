// Copyright 2022 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package xoauth2

import (
	"encoding/json"
	"fmt"
)

// The XOAUTH2 mechanism name.
const XOAuth2 = "XOAUTH2"

type XOAuth2Error struct {
	Status  string `json:"status"`
	Schemes string `json:"schemes"`
	Scope   string `json:"scope"`
}

type XOAuth2Options struct {
	Username     string
	AccessToken  string
	RefreshToken string
}

// Implements error
func (err *XOAuth2Error) Error() string {
	return fmt.Sprintf(XOAuth2+" authentication error (%v)", err.Status)
}

type xoauth2Client struct {
	XOAuth2Options
}

func (a *xoauth2Client) Start() (mech string, ir []byte, err error) {
	mech = XOAuth2
	ir = []byte(XOAuth2String(a.Username, a.AccessToken))
	return mech, ir, nil
}

func (a *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	authBearerErr := &XOAuth2Error{}
	if err := json.Unmarshal(challenge, authBearerErr); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", challenge, err)
	}
	return nil, fmt.Errorf("%s: %w", challenge, authBearerErr)
}

// An implementation of the OAUTHBEARER authentication mechanism, as
// described in RFC 7628.
func NewXOAuth2Client(opt *XOAuth2Options) *xoauth2Client {
	return &xoauth2Client{*opt}
}
