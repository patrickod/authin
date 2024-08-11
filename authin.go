package main

import (
	"bytes"
	"io"
	"net"
	"path"

	crand "crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	_ "modernc.org/sqlite"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
)

var (
	tsDir    = flag.String("ts-dir", "", "directory to store tailscaled state")
	stateDir = flag.String("state-dir", "", "directory to store state")
	rpOrigin = flag.String("origin", "authin.fly.dev", "origin for the webauthn config")

	//go:embed static/*
	staticFS embed.FS
	//go:embed templates/*
	templateFS    embed.FS
	indexTemplate = template.Must(
		template.New("root").
			ParseFS(templateFS, "templates/layout.html", "templates/index.html"))

	// keys for session storage for auth stages
	passkeyRegistrationKey = "passkey_registration"
	passkeyLoginKey        = "passkey_login"
	userKey                = "user"
)

func initDB(path string) *sql.DB {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL,
		webauthn_credentials TEXT,
		created TIMESTAMP DEFAULT CURRENT_TIMESTAMP	)`); err != nil {
		log.Fatalf("failed to create table: %v", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id BLOB PRIMARY KEY,
		user_id INTEGER NOT NULL,
		credential TEXT NOT NULL,
		created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		log.Fatalf("failed to create table: %v", err)
	}
	return db
}

type server struct {
	db           *sql.DB
	webAuthn     *webauthn.WebAuthn
	sessionStore *sessions.CookieStore
}

func (s *server) ServeMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/register", s.handleBeginRegistration)
	mux.HandleFunc("/register/finish", s.handleFinishRegistration)
	mux.HandleFunc("/login", s.handleBeginLogin)
	mux.HandleFunc("/login/finish", s.handleFinishLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.Handle("/whoami", s.auth(http.HandlerFunc(s.handleWhoami)))

	// read out the `static` subtree to prevent double /static/ prefix
	fsys, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("failed to create `static` sub-FS: %v", err)
	}
	fs := http.FileServer(http.FS(fsys))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	tsweb.Debugger(mux)
	return mux
}

func (s *server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store, err := s.sessionStore.Get(r, userKey)
		if err != nil {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}

		_, ok := store.Values["user_id"]
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	store, err := s.sessionStore.Get(r, userKey)
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}

	userID, ok := store.Values["user_id"]
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	user, err := s.getUserByID(userID.(int64))
	if err != nil {
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, "Failed to encode user", http.StatusInternalServerError)
		return
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	store, err := s.sessionStore.Get(r, userKey)
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		return
	}

	var user *User
	userID, ok := store.Values["user_id"]
	if ok {
		var err error
		user, err = s.getUserByID(userID.(int64))
		if err != nil {
			http.Error(w, "Failed to get user", http.StatusInternalServerError)
			return
		}
	}

	b := new(bytes.Buffer)
	if err := indexTemplate.ExecuteTemplate(b, "layout.html", struct{ User *User }{User: user}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(b.Bytes()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *server) handleBeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	username := r.FormValue("username")

	// create session store for credential data & user id
	store, err := s.sessionStore.Get(r, passkeyRegistrationKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error getting session: %v", err), http.StatusInternalServerError)
		return
	}

	// create a local user record w/ that username & new unique ID
	user, err := s.registerUser(username)
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating user: %v", err), http.StatusInternalServerError)
		return
	}
	store.Values["user_id"] = user.ID

	// begin the webauthn registration process
	options, session, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("error beginning webauthn registnration: %v", err), http.StatusInternalServerError)
		return
	}

	store.Values["session"] = session
	if err := store.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		return
	}

	// encode the response to JSON
	type response struct {
		Options *protocol.CredentialCreation `json:"options"`
		UserID  string                       `json:"user_id"`
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response{
		Options: options,
		UserID:  base64.URLEncoding.EncodeToString(user.WebAuthnID()),
	}); err != nil {
		http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) handleFinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	registrationStore, err := s.sessionStore.Get(r, passkeyRegistrationKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving session: %v", err), http.StatusInternalServerError)
		return
	}
	if registrationStore.IsNew {
		http.Error(w, "no session found - please restart registration", http.StatusInternalServerError)
		return
	}

	session := registrationStore.Values["session"].(*webauthn.SessionData)
	if session == nil {
		http.Error(w, "no session found - please restart registration", http.StatusInternalServerError)
		return
	}
	user, err := s.getUserByID(registrationStore.Values["user_id"].(int64))
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving user: %v", err), http.StatusInternalServerError)
		return
	}

	credential, err := s.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("error finishing webauthn registration: %v", err), http.StatusInternalServerError)
		return
	}

	if err := s.addCredentialToUser(user, credential); err != nil {
		http.Error(w, fmt.Sprintf("error adding credential to user: %v", err), http.StatusInternalServerError)
		return
	}

	// clear the registrationStore now that we're finished
	registrationStore.Options.MaxAge = -1
	if ers := registrationStore.Save(r, w); ers != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", ers), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, "Registration complete! You may now close this page.")
}

func (s *server) handleBeginLogin(w http.ResponseWriter, r *http.Request) {
	store, err := s.sessionStore.Get(r, passkeyLoginKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error getting session: %v", err), http.StatusInternalServerError)
		return
	}

	options, session, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, fmt.Sprintf("error beginning webauthn login: %v", err), http.StatusInternalServerError)
		return
	}

	store.Values["session"] = session
	if err := store.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if ers := json.NewEncoder(w).Encode(options); ers != nil {
		http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) handleFinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	loginStore, err := s.sessionStore.Get(r, passkeyLoginKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving session: %v", err), http.StatusInternalServerError)
		return
	}

	session := loginStore.Values["session"].(*webauthn.SessionData)
	if session == nil {
		http.Error(w, "no session found - please restart login", http.StatusInternalServerError)
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("error parsing response: %v", err), http.StatusInternalServerError)
		return
	}

	user, _, err := s.webAuthn.ValidatePasskeyLogin(s.getUserByWebauthnID, *session, parsedResponse)
	if err != nil {
		http.Error(w, fmt.Sprintf("error finishing webauthn login: %v", err), http.StatusInternalServerError)
		return
	}

	// set the user session
	userTyped := user.(*User)
	userStore, err := s.sessionStore.Get(r, userKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving session: %v", err), http.StatusInternalServerError)
		return
	}
	userStore.Values["user_id"] = userTyped.ID
	if err := userStore.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		return
	}

	// clear the login session
	loginStore.Options.MaxAge = -1
	if ers := loginStore.Save(r, w); ers != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", ers), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, fmt.Sprintf("Welcome %q", userTyped.Username))
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	deleteKey := func(k string) error {
		s, err := s.sessionStore.New(r, k)
		if err != nil {
			return err
		}

		s.Options.MaxAge = -1
		return s.Save(r, w)
	}

	for _, k := range []string{passkeyRegistrationKey, passkeyLoginKey, userKey} {
		if err := deleteKey(k); err != nil {
			http.Error(w, fmt.Sprintf("error deleting session: %v", err), http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		var remoteAddr string
		flyIP := r.Header.Get("Fly-Client-IP")
		if flyIP != "" {
			remoteAddr = flyIP
		} else {
			remoteAddr = r.RemoteAddr
		}

		duration := time.Since(start)
		log.Printf("%s - - [%s] \"%s %s %s\" %.3f\n",
			remoteAddr,
			start.Format("02/Jan/2006:15:04:05 -0700"),
			r.Method,
			r.URL.Path,
			r.Proto,
			duration.Seconds(),
		)
	})
}

func main() {
	flag.Parse()

	// db init
	var db *sql.DB
	if *stateDir == "" {
		db = initDB("file::memory:?mode=memory&cache=shared")
	} else {
		db = initDB(path.Join(*stateDir, "authin.sqlite"))
	}
	defer db.Close()

	// webauthn init
	wconfig := &webauthn.Config{
		RPDisplayName: "authin",
		RPID:          *rpOrigin,
		RPOrigins:     []string{fmt.Sprintf("https://%s", *rpOrigin)},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce: true,
				Timeout: time.Second * 60,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce: true,
				Timeout: time.Second * 60,
			},
		},
	}
	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		log.Fatalf("failed to create webauthn: %v", err)
	}

	// session store init
	k := make([]byte, 32)
	e := os.Getenv("SECRET_KEY")
	if e == "" {
		if _, err := crand.Read(k); err != nil {
			log.Fatalf("failed to generate random key: %v", err)
		}
	} else {
		var err error
		k, err = hex.DecodeString(e)
		if err != nil {
			log.Fatalf("failed to decode secret key: %v", err)
		}
	}
	if len(k) < 32 {
		log.Fatalf("failed to decode secret key: %v", err)
	}

	// register session data type with gob for serializing in cookies
	gob.Register(&webauthn.SessionData{})

	cstore := sessions.NewCookieStore(k)
	// the need to set these instead of having secure defaults is a sad state of affairs
	cstore.Options.Secure = true
	cstore.Options.HttpOnly = true
	cstore.Options.SameSite = http.SameSiteStrictMode
	cstore.Options.MaxAge = int(24 * time.Hour.Seconds())

	h := &server{db: db, webAuthn: webAuthn, sessionStore: cstore}

	var ln net.Listener
	if *tsDir != "" {
		ts := tsnet.Server{
			Dir:      *tsDir,
			Hostname: "passkey-demo",
		}
		defer ts.Close()

		var err error
		ln, err = ts.ListenTLS("tcp", ":443")
		if err != nil {
			log.Fatalf("failed to listen on :443: %v", err)
		}
		defer ln.Close()
	} else {
		var err error
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		ln, err = net.Listen("tcp", fmt.Sprintf(":%s", port))
		if err != nil {
			log.Fatalf("failed to listen on :443: %v", err)
		}
		defer ln.Close()
	}

	if err := http.Serve(ln, LoggingMiddleware(h.ServeMux())); err != nil && err != http.ErrServerClosed {
		log.Fatalf("failed to serve: %v", err)
	}
}
