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

package main

import (
	"bytes"
	"flag"
	"os"

	"github.com/tgulacsi/imapclient"
	"gopkg.in/inconshreveable/log15.v2"
)

// Log is the logger.
var Log = log15.New()

func main() {
	imapclient.Log.SetHandler(log15.StderrHandler)
	flagUsername := flag.String("u", "", "username")
	flagPassword := flag.String("p", "", "password")
	flagHost := flag.String("H", "localhost", "host")
	flagPort := flag.Int("P", 143, "port")
	flag.Parse()

	c := imapclient.NewClient(*flagHost, *flagPort, *flagUsername, *flagPassword)
	if err := c.Connect(); err != nil {
		Log.Crit("CONNECT", "error", err)
		os.Exit(1)
	}
	defer c.Close(false)

	uids, err := c.ListNew("INBOX", "")
	if err != nil {
		Log.Error("LIST", "error", err)
		os.Exit(2)
	}

	Log.Info("LIST", "uids", uids)
	var body bytes.Buffer
	for _, uid := range uids {
		body.Reset()
		n, err := c.ReadTo(&body, uid)
		if err != nil {
			Log.Error("Read", "uid", uid, "error", err)
			continue
		}
		if n > 1024 {
			n = 1024
		}
		body.WriteTo(os.Stdout)
	}
}
