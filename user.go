package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

// randomUserID generates a 64-bit random user ID
func randomUserID() (int64, error) {
	var id int64
	if err := binary.Read(crand.Reader, binary.BigEndian, &id); err != nil {
		return 0, fmt.Errorf("failed to generate random ID: %v", err)
	}
	return id, nil
}

type User struct {
	ID                       int64
	Username                 string
	WebAuthnCredentialsSlice []webauthn.Credential `json:"-"`
}

func (u *User) WebAuthnID() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, u.ID)
	return buf.Bytes()
}

func (u *User) WebAuthnName() string {
	return u.Username
}

func (u *User) WebAuthnDisplayName() string {
	return u.Username
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.WebAuthnCredentialsSlice
}

func (s *server) getUserByID(id int64) (*User, error) {
	user := User{ID: id, WebAuthnCredentialsSlice: []webauthn.Credential{}}
	var webauthnCredentialsJSON string

	row := s.db.QueryRow("SELECT username, webauthn_credentials FROM users WHERE id = ?", id)
	if err := row.Scan(&user.Username, &webauthnCredentialsJSON); err != nil {
		return nil, fmt.Errorf("failed to scan user: %v", err)
	}
	if webauthnCredentialsJSON != "" {
		if err := json.Unmarshal([]byte(webauthnCredentialsJSON), &user.WebAuthnCredentialsSlice); err != nil {
			return nil, fmt.Errorf("failed to unmarshal webauthn credentials: %v", err)
		}
	}
	return &user, nil
}

func (s *server) getUserByWebauthnID(keyID, userID []byte) (webauthn.User, error) {
	i := int64(binary.BigEndian.Uint64(userID))
	user, err := s.getUserByID(i)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %v", err)
	}

	var validCredential bool
	for i := range user.WebAuthnCredentialsSlice {
		if subtle.ConstantTimeCompare(user.WebAuthnCredentialsSlice[i].ID, keyID) == 1 {
			validCredential = true
			break
		}
	}
	if !validCredential {
		return nil, fmt.Errorf("no credential found for user by ID %q", base64.URLEncoding.EncodeToString(keyID))
	}

	return user, nil
}

func (s *server) registerUser(username string) (*User, error) {
	uid, err := randomUserID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random ID: %v", err)
	}
	user := &User{
		ID:       uid,
		Username: username,
	}

	if _, err := s.db.Exec(`
		INSERT INTO users (id, username, webauthn_credentials)
		VALUES (?, ?, ?)
	`, uid, username, "",
	); err != nil {
		return nil, fmt.Errorf("failed to insert user: %v", err)
	}

	return user, nil
}

func (s *server) addCredentialToUser(user *User, credential *webauthn.Credential) error {
	user.WebAuthnCredentialsSlice = append(user.WebAuthnCredentialsSlice, *credential)
	webauthnCredentialsJSON, err := json.Marshal(user.WebAuthnCredentialsSlice)
	if err != nil {
		return fmt.Errorf("failed to marshal webauthn credentials: %v", err)
	}

	res, err := s.db.Exec(`UPDATE users SET webauthn_credentials = ? WHERE id = ?`, webauthnCredentialsJSON, user.ID)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}
	if n == 0 {
		return fmt.Errorf("no rows affected")
	}
	return nil
}
