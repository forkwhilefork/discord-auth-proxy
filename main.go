// Extremely barebones server to demonstrate OAuth 2.0 flow with Discord
// Uses native net/http to be dependency-less and easy to run.
// No sessions logic implemented, re-login needed each visit.
// Edit the config lines a little bit then go build/run it as normal.
package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gorilla/sessions"
	"github.com/ravener/discord-oauth2"
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

// This is the state key used for security, sent in login, validated in callback.
// For this example we keep it simple and hardcode a string
// but in real apps you must provide a proper function that generates a state.
var state = "random"

func main() {
	// Create a config.
	// Ensure you add the redirect url in the application's oauth2 settings
	// in the discord devs page.
	conf := &oauth2.Config{
		RedirectURL: "https://alpha.booktags.app/.proxy/auth/callback",
		// This next 2 lines must be edited before running this.
		ClientID:     "825495973349687336",
		ClientSecret: "SSGWwWas0laGExnPZlWRiFEWqPvthDtq",
		Scopes:       []string{discord.ScopeGuilds},
		Endpoint:     discord.Endpoint,
	}

	// where we are reverse-proxying to
	u, _ := url.Parse("http://127.0.0.1:8080/")

	// setting up the cookie store
	key := []byte("Xp2s5u8x/A?D(G+KbPeShVmYq3t6w9y$")
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
		token, err := conf.Exchange(oauth2.NoContext, r.FormValue("code"))

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			session.Values["authenticated"] = false
			return
		}

		// Step 4: Use the access token, here we use it to get the logged in user's guilds.
		res, err := conf.Client(oauth2.NoContext, token).Get("https://discordapp.com/api/v6/users/@me/guilds")

		// tagcat: 546465182344413185

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

		// check if the user is a member of the guild we care about
		requiredGuild := "546465182344413185"

		var guilds []Guild

		json.Unmarshal([]byte(guildJson), &guilds)

		session.Values["authenticated"] = false
		for _, guild := range guilds {
			if guild.Id == requiredGuild {
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

	log.Println("Listening on :3000")
	log.Fatal(http.ListenAndServe("0.0.0.0:3000", nil))
}
