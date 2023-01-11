// Package oidc provides ...
package oidc

import (
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

// see https://www.rfc-editor.org/rfc/rfc6749#section-4.3
func (s *Server) handlePasswordRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) error {

	// username and password is required
	if req.Username == "" || req.Password == "" {
		return protocol.ErrInvalidGrant.Desc("username and password is required")
	}

	req.GenerateRefresh = true
	// req.UserID should set by caller
	return nil
}
