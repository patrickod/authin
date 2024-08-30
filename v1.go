package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/prometheus/client_golang/prometheus"
)

type v1 struct {
	webAuthn *webauthn.WebAuthn
	s        *server
}

var (
	loginSuccessCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "v1_login_success_count",
		Help: "The total number of successful v1 logins",
	})
	loginFailureCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "v1_login_failure_count",
		Help: "The total number of failed v1 logins",
	})
	registrationSuccessCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "v1_registration_success_count",
		Help: "The total number of successful v1 registrations",
	})
	registrationFailureCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "v1_registration_failure_count",
		Help: "The total number of failed v1 registrations",
	})
)

func init() {
	prometheus.MustRegister(loginSuccessCount)
	prometheus.MustRegister(loginFailureCount)
	prometheus.MustRegister(registrationSuccessCount)
	prometheus.MustRegister(registrationFailureCount)
}

func (v *v1) serveMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", v.handleBeginLogin)
	mux.HandleFunc("/login/finish", v.handleFinishLogin)
	mux.HandleFunc("/register", v.handleBeginRegistration)
	mux.HandleFunc("/register/finish", v.handleFinishRegistration)
	return mux
}

func (v *v1) handleBeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		registrationFailureCount.Inc()
		return
	}
	r.ParseForm()
	username := r.FormValue("username")

	// create session store for credential data & user id
	store, err := v.s.sessionStore.Get(r, passkeyRegistrationKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error getting session: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}

	// create a local user record w/ that username & new unique ID
	user, err := v.s.registerUser(username)
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating user: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}
	store.Values["user_id"] = user.ID

	// begin the webauthn registration process
	options, session, err := v.webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("error beginning webauthn registnration: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}

	store.Values["session"] = session
	if err := store.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
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
		registrationFailureCount.Inc()
		return
	}
}

func (v *v1) handleFinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		registrationFailureCount.Inc()
		return
	}

	registrationStore, err := v.s.sessionStore.Get(r, passkeyRegistrationKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving session: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}
	if registrationStore.IsNew {
		http.Error(w, "no session found - please restart registration", http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}

	session := registrationStore.Values["session"].(*webauthn.SessionData)
	if session == nil {
		http.Error(w, "no session found - please restart registration", http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}
	user, err := v.s.getUserByID(registrationStore.Values["user_id"].(int64))
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving user: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}

	credential, err := v.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("error finishing webauthn registration: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}

	if err := v.s.addCredentialToUser(user, credential); err != nil {
		http.Error(w, fmt.Sprintf("error adding credential to user: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}

	// clear the registrationStore now that we're finished
	registrationStore.Options.MaxAge = -1
	if err := registrationStore.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		registrationFailureCount.Inc()
		return
	}

	registrationSuccessCount.Inc()
	io.WriteString(w, "Registration complete! You may now close this page.")
}

func (v *v1) handleBeginLogin(w http.ResponseWriter, r *http.Request) {
	loginStore, err := v.s.sessionStore.Get(r, passkeyLoginKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error getting session: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}

	options, session, err := v.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, fmt.Sprintf("error beginning webauthn login: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}

	loginStore.Values["session"] = session
	if err := loginStore.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(options); err != nil {
		http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}
}

func (v *v1) handleFinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		loginFailureCount.Inc()
		return
	}

	// retrieve the webauthn session data from the initial phase
	loginStore, err := v.s.sessionStore.Get(r, passkeyLoginKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving session: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}
	session := loginStore.Values["session"].(*webauthn.SessionData)
	if session == nil {
		http.Error(w, "no session found - please restart login", http.StatusInternalServerError)
		return
	}

	// validate that the necessary inputs are present in the request
	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("error parsing response: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}

	// TODO: bind the credential return value; set a LastLogin timestamp?
	user, _, err := v.webAuthn.ValidatePasskeyLogin(v.getUserByWebAuthnID, *session, parsedResponse)
	if err != nil {
		http.Error(w, fmt.Sprintf("error finishing webauthn login: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}

	// set the user session now that we have authenticated the user
	userTyped := user.(*User)
	userStore, err := v.s.sessionStore.Get(r, userKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving session: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}
	userStore.Values["user_id"] = userTyped.ID
	if err := userStore.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}

	// clear the login session
	loginStore.Options.MaxAge = -1
	if err := loginStore.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		loginFailureCount.Inc()
		return
	}

	loginSuccessCount.Inc()
	io.WriteString(w, fmt.Sprintf("Welcome %q", userTyped.Username))
}

// getUserByWebAuthnID retrieves a webauthn.User compatible User record from the
// database that belongs to the given WebAuthn credential. This hook is used by
// the WebAuthn library during its authentication routine.
func (v *v1) getUserByWebAuthnID(keyID, userID []byte) (webauthn.User, error) {
	i := int64(binary.BigEndian.Uint64(userID))
	var dbUID int64
	row := v.s.db.QueryRow("SELECT user_id FROM webauthn_credentials WHERE id = ? AND user_id = ?", keyID, i)
	if err := row.Scan(&dbUID); err != nil {
		return nil, fmt.Errorf("failed to identify user from credential: %v", err)
	}
	if err := row.Err(); err != nil {
		return nil, fmt.Errorf("failed to query user from credential: %v", err)
	}

	return v.s.getUserByID(dbUID)
}
