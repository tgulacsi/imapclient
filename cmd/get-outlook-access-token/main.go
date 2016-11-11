package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

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

	if err := GetClient(&oauth2.Config{
		ClientID:     *flagID,
		ClientSecret: *flagSecret,
		RedirectURL:  *flagRedirURL,
		Scopes:       strings.Split(*flagScopes, " "),
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		},
	}); err != nil {
		log.Fatal(err)
	}
}

func GetClient(conf *oauth2.Config) error {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	state := base64.URLEncoding.EncodeToString(b[:])
	// Redirect user to Google's consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	fmt.Printf("Visit the URL for the auth dialog:\n\n\t%v\n\n", url)

	c := make(chan maybeCode, 1)
	if conf.RedirectURL != "" {
		go func() {
			http.ListenAndServe(
				strings.TrimPrefix(conf.RedirectURL, "http://"),
				handleRedirect(c, state),
			)
		}()
	}

	go func() {
		var code string
		_, err := fmt.Scan(&code)
		c <- maybeCode{Code: code, Err: err}
	}()

	ce := <-c
	if ce.Code == "" {
		log.Fatal(ce.Err)
	}
	// Handle the exchange code to initiate a transport.
	tok, err := conf.Exchange(oauth2.NoContext, ce.Code)
	if err != nil {
		log.Fatal(err)
	}

	return json.NewEncoder(os.Stdout).Encode(struct {
		Config *oauth2.Config
		Token  *oauth2.Token
	}{conf, tok})
}

type maybeCode struct {
	Code string
	Err  error
}

func handleRedirect(c chan<- maybeCode, state string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()
		if gotState := vals.Get("state"); gotState != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := vals.Get("code")
		if code == "" {
			log.Printf("got %s (%q)", r.URL, vals)
			http.Error(w, "empty code", http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, `Please copy the following code into the prompt of the waiting program:

%s`, code)
		c <- maybeCode{Code: code}
	})
}
