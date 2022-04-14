// Package oidc provides ...
package oidc

import (
	"encoding/base64"

	"github.com/deepzz0/oidc/protocol"

	"github.com/google/uuid"
)

// AuthorizeCodeGenFunc authorize code generator
type AuthorizeCodeGenFunc func(req *protocol.AuthorizeRequest) (code string, err error)

// DefaultAuthorizeCodeGenerator default authorize code generator
func DefaultAuthorizeCodeGenerator(req *protocol.AuthorizeRequest) (code string, err error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return
	}
	return base64.RawURLEncoding.EncodeToString(id[:]), nil
}

// AccessTokenGenFunc access token generator
type AccessTokenGenFunc func(data *protocol.AccessData, genRefresh bool) (token, refresh string, err error)

// DefaultAccessTokenGenerator default access token generator
func DefaultAccessTokenGenerator(data *protocol.AccessData, genRefresh bool) (token, refresh string, err error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return
	}
	token = base64.RawURLEncoding.EncodeToString(id[:])

	if genRefresh {
		id, err = uuid.NewRandom()
		if err != nil {
			return
		}
		refresh = base64.RawURLEncoding.EncodeToString(id[:])
	}
	return
}
