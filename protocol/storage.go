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
	// UserDataScopes get user info by scopes
	UserDataScopes(uid string, scopes []Scope) (*UserInfo, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(code string, data *AuthorizeData, exp int) error
	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string) (data *AuthorizeData, err error)
	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(token string, data *AccessData, exp int) error
	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string) (data *AccessData, err error)
	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string) error

	// SaveRefresh save refresh token
	SaveRefresh(refresh, token string, exp int) (err error)
	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string) (data *AccessData, err error)
	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string) error
}
