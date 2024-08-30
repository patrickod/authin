package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type v1 struct {
	webAuthn *webauthn.WebAuthn
	s        *server
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
		return
	}
	r.ParseForm()
	username := r.FormValue("username")

	// create session store for credential data & user id
	store, err := v.s.sessionStore.Get(r, passkeyRegistrationKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error getting session: %v", err), http.StatusInternalServerError)
		return
	}

	// create a local user record w/ that username & new unique ID
	user, err := v.s.registerUser(username)
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating user: %v", err), http.StatusInternalServerError)
		return
	}
	store.Values["user_id"] = user.ID

	// begin the webauthn registration process
	options, session, err := v.webAuthn.BeginRegistration(user)
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

func (v *v1) handleFinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	registrationStore, err := v.s.sessionStore.Get(r, passkeyRegistrationKey)
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
	user, err := v.s.getUserByID(registrationStore.Values["user_id"].(int64))
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving user: %v", err), http.StatusInternalServerError)
		return
	}

	credential, err := v.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("error finishing webauthn registration: %v", err), http.StatusInternalServerError)
		return
	}

	if err := v.s.addCredentialToUser(user, credential); err != nil {
		http.Error(w, fmt.Sprintf("error adding credential to user: %v", err), http.StatusInternalServerError)
		return
	}

	// clear the registrationStore now that we're finished
	registrationStore.Options.MaxAge = -1
	if err := registrationStore.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, "Registration complete! You may now close this page.")
}

func (v *v1) handleBeginLogin(w http.ResponseWriter, r *http.Request) {
	loginStore, err := v.s.sessionStore.Get(r, passkeyLoginKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error getting session: %v", err), http.StatusInternalServerError)
		return
	}

	options, session, err := v.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, fmt.Sprintf("error beginning webauthn login: %v", err), http.StatusInternalServerError)
		return
	}

	loginStore.Values["session"] = session
	if err := loginStore.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(options); err != nil {
		http.Error(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

func (v *v1) handleFinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// retrieve the webauthn session data from the initial phase
	loginStore, err := v.s.sessionStore.Get(r, passkeyLoginKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving session: %v", err), http.StatusInternalServerError)
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
		return
	}

	// TODO: bind the credential return value; set a LastLogin timestamp?
	user, _, err := v.webAuthn.ValidatePasskeyLogin(v.s.getUserByWebAuthnID, *session, parsedResponse)
	if err != nil {
		http.Error(w, fmt.Sprintf("error finishing webauthn login: %v", err), http.StatusInternalServerError)
		return
	}

	// set the user session now that we have authenticated the user
	userTyped := user.(*User)
	userStore, err := v.s.sessionStore.Get(r, userKey)
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
	if err := loginStore.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("error saving session: %v", err), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, fmt.Sprintf("Welcome %q", userTyped.Username))
}
