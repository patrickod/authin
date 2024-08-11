package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

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
	Created                  time.Time
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

	row := s.db.QueryRow("SELECT username, created FROM users WHERE users.id = ?", id)
	if err := row.Scan(&user.Username, &user.Created); err != nil {
		return nil, fmt.Errorf("failed to scan user: %v", err)
	}

	// get credentials
	rows, err := s.db.Query("SELECT credential FROM webauthn_credentials WHERE user_id = ?", id)
	if err != nil {
		return nil, fmt.Errorf("failed to query webauthn credentials: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var credJSON string
		if err := rows.Scan(&credJSON); err != nil {
			return nil, fmt.Errorf("failed to scan webauthn credentials: %v", err)
		}
		var credential webauthn.Credential
		if err := json.Unmarshal([]byte(credJSON), &credential); err != nil {
			return nil, fmt.Errorf("failed to unmarshal webauthn credentials: %v", err)
		}
		user.WebAuthnCredentialsSlice = append(user.WebAuthnCredentialsSlice, credential)
	}

	return &user, nil
}

func (s *server) getUserByWebauthnID(keyID, userID []byte) (webauthn.User, error) {
	i := int64(binary.BigEndian.Uint64(userID))
	var dbUID int64
	row := s.db.QueryRow("SELECT user_id FROM webauthn_credentials WHERE id = ? AND user_id = ?", keyID, i)
	if ers := row.Scan(&dbUID); ers != nil {
		return nil, fmt.Errorf("failed to identify user from credential: %v", ers)
	}

	return s.getUserByID(dbUID)
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
	marshalled, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("failed to marshal credential: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO webauthn_credentials (id, user_id, credential) VALUES (?, ?, ?)`,
		credential.ID,
		user.ID,
		marshalled); err != nil {
		return fmt.Errorf("failed to insert webauthn credential")
	}
	return nil
}
