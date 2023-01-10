// Package oidc provides ...
package oidc

import (
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

func (s *Server) handlePasswordRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) error {

	// validate grant type
	if !ValidateGrantType(req.Client.GrantTypes(), protocol.GrantTypeAuthorizationCode) {
		return protocol.ErrInvalidGrant.Desc("unsupported grant type: authorization_code")
	}
	// username and password is required
	if req.Username == "" || req.Password == "" {
		return protocol.ErrInvalidGrant.Desc("username and password is required")
	}

	req.GenerateRefresh = true
	// req.UserID should set by validator
	return nil
}
