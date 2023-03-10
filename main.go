// Extremely barebones server to demonstrate OAuth 2.0 flow with Discord
// Uses native net/http to be dependency-less and easy to run.
// No sessions logic implemented, re-login needed each visit.
// Edit the config lines a little bit then go build/run it as normal.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gorilla/sessions"
	"github.com/ravener/discord-oauth2"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type Guild struct {
	Id          string
	Name        string
	Icon        string
	Owner       bool
	Permissions string
	Features    []string
}

var (
	listenAddr           = flag.String("listen.addr", "0.0.0.0", "HTTP listen address")
	listenPort           = flag.Int("listen.port", 3000, "HTTP listen port")
	discordClientId      = flag.String("discord.clientId", "", "Discord client ID")
	discordClientSecret  = flag.String("discord.clientSecret", "", "Discord client secret")
	discordRequiredGuild = flag.String("discord.requiredGuild", "", "Discord guild that user must be in")
	cookieStoreKey       = flag.String("cookieStore.key", "", "key for the cookie store")
	proxyTarget          = flag.String("proxy.target", "", "target URL to proxy to")
	oauthRedirectUrl     = flag.String("oauth.redirectUrl", "", "OAuth redirect URL")
)

// This is the state key used for security, sent in login, validated in callback.
// For this example we keep it simple and hardcode a string
// but in real apps you must provide a proper function that generates a state.
var state = "random"

var log *logrus.Logger

func main() {
	flag.Parse()

	log = logrus.New()

	if *discordClientId == "" || *discordClientSecret == "" || *discordRequiredGuild == "" ||
		*cookieStoreKey == "" || *proxyTarget == "" || *oauthRedirectUrl == "" {
		log.Fatal("Must specify arguments")
	}

	// Create a config.
	// Ensure you add the redirect url in the application's oauth2 settings
	// in the discord devs page.
	conf := &oauth2.Config{
		RedirectURL:  *oauthRedirectUrl,
		ClientID:     *discordClientId,
		ClientSecret: *discordClientSecret,
		Scopes:       []string{discord.ScopeGuilds},
		Endpoint:     discord.Endpoint,
	}

	// where we are reverse-proxying to
	u, _ := url.Parse(*proxyTarget)

	// set up the cookie store
	key := []byte(*cookieStoreKey)
	store := sessions.NewCookieStore(key)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "login")

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			// Step 1: Redirect to the OAuth 2.0 Authorization page.
			http.Redirect(w, r, conf.AuthCodeURL(state), http.StatusTemporaryRedirect)
		} else {
			httputil.NewSingleHostReverseProxy(u).ServeHTTP(w, r)
		}
	})

	http.HandleFunc("/.proxy/logout", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "login")

		session.Values["authenticated"] = false
		session.Save(r, w)
		w.Write([]byte("logged out"))
	})

	// Step 2: After user authenticates their accounts this callback is fired.
	// the state we sent in login is also sent back to us here
	// we have to verify it as necessary before continuing.
	http.HandleFunc("/.proxy/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "login")
		if r.FormValue("state") != state {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("State does not match."))
			session.Values["authenticated"] = false
			return
		}
		// Step 3: We exchange the code we got for an access token
		// Then we can use the access token to do actions, limited to scopes we requested
		token, err := conf.Exchange(context.Background(), r.FormValue("code"))

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			session.Values["authenticated"] = false
			return
		}

		// Step 4: Use the access token. Here we use it to get the logged in user's guilds.
		res, err := conf.Client(context.Background(), token).Get("https://discordapp.com/api/v6/users/@me/guilds")

		if err != nil || res.StatusCode != 200 {
			w.WriteHeader(http.StatusInternalServerError)
			session.Values["authenticated"] = false
			if err != nil {
				w.Write([]byte(err.Error()))
			} else {
				w.Write([]byte(res.Status))
			}
			return
		}

		guildJson, err := ioutil.ReadAll(res.Body)
		res.Body.Close()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		// Step 5: Check if the user is a member of the guild we care about
		var guilds []Guild

		json.Unmarshal([]byte(guildJson), &guilds)

		session.Values["authenticated"] = false
		for _, guild := range guilds {
			if guild.Id == *discordRequiredGuild {
				// user is authenticated
				session.Values["authenticated"] = true
				break
			}
		}

		session.Save(r, w)

		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			w.Write([]byte("not authorized"))
		} else {
			// redirect to "/"
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		}
	})

	log.Infof("Listening on %s:%d", *listenAddr, *listenPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *listenAddr, *listenPort), nil))

}
