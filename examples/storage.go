// Package examples provides ...
package examples

import "github.com/deepzz0/oidc/protocol"

// TestStorage storage
type TestStorage struct {
	clients map[string]protocol.Client
}

// NewTestStorage memory storage
func NewTestStorage() *TestStorage {
	s := &TestStorage{
		clients: make(map[string]protocol.Client),
	}
	s.clients["test_client_id"] = &TestClient{}
	return s
}

// Client loads the client by id (client_id)
func (s *TestStorage) Client(clientID string) (protocol.Client, error) {

	return nil, nil
}

// UserInfoScopes get user info from scopes
func (s *TestStorage) UserInfoScopes(scopes []string) (map[string]interface{}, error) {

	return nil, nil
}

// SaveAuthorize saves authorize data.
func (s *TestStorage) SaveAuthorize(code string, exp int, data *protocol.AuthorizeData) error {

	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *TestStorage) LoadAuthorize(code string) (data *protocol.AuthorizeData, err error) {
	return nil, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *TestStorage) RemoveAuthorize(code string) error {
	return nil
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *TestStorage) SaveAccess(token string, data *protocol.AuthorizeData, exp int) error {

	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *TestStorage) LoadAccess(token string) (data *protocol.AuthorizeData, err error) {

	return nil, nil
}

// RemoveAccess revokes or deletes an AccessData.
func (s *TestStorage) RemoveAccess(token string) error {
	return nil
}

// SaveRefresh save refresh token
func (s *TestStorage) SaveRefresh(refresh, token string, exp int) (err error) {

	return nil
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *TestStorage) LoadRefresh(token string) (data *protocol.AuthorizeData, err error) {

	return nil, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *TestStorage) RemoveRefresh(token string) error {

	return nil
}
