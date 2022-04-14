// Package protocol provides ...
package protocol

import (
	"crypto"
	"errors"
)

// ErrNotFoundEntity not found object
var ErrNotFoundEntity = errors.New("not found entity")

// Storage store interface
type Storage interface {
	// GetClient loads the client by id (client_id)
	Client(clientID string) (Client, error)
	// GetPrivateKey loads the client private key
	PrivateKey(clientID string) (crypto.Signer, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(code string, req *AuthorizeRequest) error
	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string) (*AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(*AccessData) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string) (*AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string) (*AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string) error
}
