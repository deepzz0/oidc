// Package examples provides ...
package examples

import (
	"fmt"
	"time"

	"github.com/deepzz0/oidc/protocol"
)

// TestStorage storage
type TestStorage struct {
	clients   map[string]protocol.Client
	authorize map[string]*protocol.AuthorizeData
	access    map[string]*protocol.AccessData
	refresh   map[string]string
}

// NewTestStorage memory storage
func NewTestStorage() *TestStorage {
	s := &TestStorage{
		clients:   make(map[string]protocol.Client),
		authorize: make(map[string]*protocol.AuthorizeData),
		access:    make(map[string]*protocol.AccessData),
		refresh:   make(map[string]string),
	}
	s.clients["test_client_id"] = &TestClient{
		ID:       "test_client_id",
		Secret:   "aabbccdd",
		Redirect: "http://localhost:9000/oidc/callback",
	}
	return s
}

// Client loads the client by id (client_id)
func (s *TestStorage) Client(clientID string) (protocol.Client, error) {
	cli, ok := s.clients[clientID]
	if !ok {
		return nil, protocol.ErrNotFoundEntity
	}
	return cli, nil
}

// UserDataScopes get user info from scopes
func (s *TestStorage) UserDataScopes(uid string, scopes []protocol.Scope) (*protocol.UserInfo, error) {
	if uid != "1234" {
		return nil, protocol.ErrNotFoundEntity
	}
	info := &protocol.UserInfo{Subject: "1234"}
	for _, v := range scopes {
		switch v {
		case protocol.ScopeEmail:
			info.Email = "hello@example.com"
			ok := true
			info.EmailVerified = &ok
		case protocol.ScopePhone:
			info.PhoneNumber = "1234567890"
			ok := false
			info.PhoneNumberVerified = &ok
		case protocol.ScopeProfile:
			info.Profile = "https://example.com/profile"
		case protocol.ScopeOpenID:
		}
	}
	customClaims := protocol.CustomClaims{
		"test_clams": "hello",
	}
	info.MapClaims = customClaims
	return info, nil
}

// SaveAuthorize saves authorize data.
func (s *TestStorage) SaveAuthorize(code string, data *protocol.AuthorizeData, exp int) error {
	fmt.Println("save authorize: ", code)
	s.authorize[code] = data
	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *TestStorage) LoadAuthorize(code string) (data *protocol.AuthorizeData, err error) {
	fmt.Println("load authorize: ", code)
	data, ok := s.authorize[code]
	if !ok || data.CreatedAt.Add(time.Second*time.Duration(data.ExpiresIn)).Before(time.Now()) {
		return nil, protocol.ErrNotFoundEntity
	}
	return data, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *TestStorage) RemoveAuthorize(code string) error {
	fmt.Println("remove authorize: ", code)
	delete(s.authorize, code)
	return nil
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *TestStorage) SaveAccess(token string, data *protocol.AccessData, exp int) error {
	fmt.Println("save access: ", token)
	s.access[token] = data
	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *TestStorage) LoadAccess(token string) (data *protocol.AccessData, err error) {
	data, ok := s.access[token]
	if !ok || data.CreatedAt.Add(time.Second*time.Duration(data.ExpiresIn)).Before(time.Now()) {
		return nil, protocol.ErrNotFoundEntity
	}
	return data, nil
}

// RemoveAccess revokes or deletes an AccessData.
func (s *TestStorage) RemoveAccess(token string) error {
	fmt.Println("remove access: ", token)
	delete(s.access, token)
	return nil
}

// SaveRefresh save refresh token
func (s *TestStorage) SaveRefresh(refresh, token string, exp int) (err error) {
	s.refresh[refresh] = token
	return nil
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *TestStorage) LoadRefresh(refresh string) (data *protocol.AccessData, err error) {
	token, ok := s.refresh[refresh]
	if !ok {
		return nil, protocol.ErrNotFoundEntity
	}
	data, ok = s.access[token]
	if !ok {
		return nil, protocol.ErrNotFoundEntity
	}
	return data, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *TestStorage) RemoveRefresh(refresh string) error {
	delete(s.refresh, refresh)
	return nil
}
