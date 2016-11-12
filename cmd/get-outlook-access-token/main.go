package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/tgulacsi/oauth2client"
	"golang.org/x/oauth2"
)

func main() {
	flagID := flag.String("id", os.Getenv("CLIENT_ID"), "CLIENT_ID")
	flagSecret := flag.String("secret", os.Getenv("CLIENT_SECRET"), "CLIENT_SECRET")
	flagRedirURL := flag.String("redirect", os.Getenv("REDIRECT_URL"), "REDIRECT_URL")
	flagScopes := flag.String("scopes", "https://outlook.office.com/mail.read", "scopes to apply for, space separated")
	if *flagRedirURL == "" {
		*flagRedirURL = "http://localhost:8123"
	}
	flag.Parse()

	toks := oauth2client.NewTokenSource(&oauth2.Config{
		ClientID:     *flagID,
		ClientSecret: *flagSecret,
		RedirectURL:  *flagRedirURL,
		Scopes:       strings.Split(*flagScopes, " "),
		Endpoint:     oauth2client.AzureV2Endpoint,
	},
		"o365.conf",
	)
	tok, err := toks.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(tok)
}
