// Package protocol provides ...
package protocol

import (
	"errors"
)

// ErrNotFoundEntity not found object
var ErrNotFoundEntity = errors.New("not found entity")

// Storage store interface
type Storage interface {
	// Client loads the client by id (client_id)
	Client(clientID string) (Client, error)
	// UserInfoScopes get user info from scopes
	UserInfoScopes(scopes []string) (map[string]interface{}, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(code string, exp int, data *AuthorizeData) error
	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string) (data *AuthorizeData, err error)
	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(token string, data *AuthorizeData, exp int) error
	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string) (data *AuthorizeData, err error)
	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string) error

	// SaveRefresh save refresh token
	SaveRefresh(refresh, token string, exp int) (err error)
	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string) (data *AuthorizeData, err error)
	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string) error
}
