// Package examples provides ...
package examples

import "github.com/deepzz0/oidc/protocol"

// TestStorage storage
type TestStorage struct {
	clients   map[string]protocol.Client
	authorize map[string]*protocol.AuthorizeData
	access    map[string]*protocol.AuthorizeData
	refresh   map[string]string
}

// NewTestStorage memory storage
func NewTestStorage() *TestStorage {
	s := &TestStorage{
		clients:   make(map[string]protocol.Client),
		authorize: make(map[string]*protocol.AuthorizeData),
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

// UserInfoScopes get user info from scopes
func (s *TestStorage) UserInfoScopes(scopes []string) (map[string]interface{}, error) {

	return nil, nil
}

// SaveAuthorize saves authorize data.
func (s *TestStorage) SaveAuthorize(code string, exp int, data *protocol.AuthorizeData) error {
	// TODO ignore exp
	s.authorize[code] = data
	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *TestStorage) LoadAuthorize(code string) (data *protocol.AuthorizeData, err error) {
	data, ok := s.authorize[code]
	if !ok {
		return nil, protocol.ErrNotFoundEntity
	}
	return data, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *TestStorage) RemoveAuthorize(code string) error {
	delete(s.authorize, code)
	return nil
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *TestStorage) SaveAccess(token string, data *protocol.AuthorizeData, exp int) error {
	// TODO ingored exp
	s.access[token] = data
	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *TestStorage) LoadAccess(token string) (data *protocol.AuthorizeData, err error) {
	data, ok := s.access[token]
	if !ok {
		return nil, protocol.ErrNotFoundEntity
	}
	return data, nil
}

// RemoveAccess revokes or deletes an AccessData.
func (s *TestStorage) RemoveAccess(token string) error {
	delete(s.access, token)
	return nil
}

// SaveRefresh save refresh token
func (s *TestStorage) SaveRefresh(refresh, token string, exp int) (err error) {
	// TODO ignored exp
	s.refresh[refresh] = token
	return nil
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *TestStorage) LoadRefresh(refresh string) (data *protocol.AuthorizeData, err error) {
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
