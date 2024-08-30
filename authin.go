package main

import (
	"bytes"
	"context"
	"net"
	"path"

	crand "crypto/rand"
	"database/sql"
	"embed"
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

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	_ "modernc.org/sqlite"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
)

var (
	dev      = flag.Bool("dev", false, "use tailscale in local development mode")
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
	homeTemplate = template.Must(
		template.New("root").
			ParseFS(templateFS, "templates/layout.html", "templates/home.html"))

	// keys for session storage for auth stages
	passkeyRegistrationKey = "passkey_registration"
	passkeyLoginKey        = "passkey_login"
	userKey                = "user"
)

type ContextKey string

const UserContextKey ContextKey = "user"

func initDB(path string) *sql.DB {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL,
		created TIMESTAMP DEFAULT CURRENT_TIMESTAMP	)`); err != nil {
		log.Fatalf("failed to create table: %v", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id BLOB PRIMARY KEY,
		user_id INTEGER NOT NULL,
		name TEXT,
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

	// v1 webauthn implementation using go-webauthn library
	v := v1{
		webAuthn: s.webAuthn,
		s:        s,
	}
	mux.Handle("/v1/", http.StripPrefix("/v1", v.serveMux()))

	mux.HandleFunc("/logout", s.handleLogout)
	mux.Handle("/whoami", s.auth(s.handleWhoami))
	mux.Handle("/home", s.auth(s.handleHome))
	mux.HandleFunc("/", s.handleIndex)

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

func (s *server) auth(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
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

		user, err := s.getUserByID(store.Values["user_id"].(int64))
		if err != nil {
			http.Error(w, "Failed to get user", http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next(w, r.WithContext(ctx))
	})
}

func (s *server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserContextKey).(*User)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, "Failed to encode user", http.StatusInternalServerError)
		return
	}
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserContextKey).(*User)
	b := new(bytes.Buffer)
	if err := homeTemplate.ExecuteTemplate(b, "layout.html", struct{ User *User }{User: user}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(b.Bytes()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

func ptr(s string) *string { return &s }

func main() {
	flag.Parse()

	if *dev && *tsDir == "" {
		log.Fatalf("ts-dev requires ts-dir to be set")
	}

	if *dev {
		rpOrigin = ptr("passkey-demo.bear-justice.ts.net")
	}

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

	// run over tailscale in dev for TLS
	if *dev {
		ts := tsnet.Server{
			Dir:      path.Join(*tsDir, "tailscale"),
			Hostname: "passkey-demo",
		}
		defer ts.Close()

		httpLn, err := ts.ListenTLS("tcp", ":443")
		if err != nil {
			log.Fatalf("failed to listen on :443: %v", err)
		}
		defer httpLn.Close()

		if err := http.Serve(httpLn, LoggingMiddleware(h.ServeMux())); err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to serve: %v", err)
		}
	} else {
		// run /debug on tsnet
		dbg := tsnet.Server{
			Dir:      path.Join(*tsDir, "debug"),
			Hostname: "authin-debug",
		}
		defer dbg.Close()
		dbgLn, err := dbg.Listen("tcp", ":80")
		if err != nil {
			log.Fatalf("failed to listen on tsnet :80: %v", err)
		}
		mux := http.NewServeMux()
		tsweb.Debugger(mux)
		go func() {
			if err := http.Serve(dbgLn, mux); err != nil {
				log.Fatalf("failed to serve debug: %v", err)
			}
		}()

		// run main on :8080 for fly
		ln, err := net.Listen("tcp", ":8080")
		if err != nil {
			log.Fatalf("failed to listen on :8080: %v", err)
		}
		if err := http.Serve(ln, LoggingMiddleware(h.ServeMux())); err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to serve: %v", err)
		}
	}

}
