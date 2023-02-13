// Package oidc provides ...
package oidc

import (
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

// see https://www.rfc-editor.org/rfc/rfc6749#section-4.3
func (s *Server) handlePasswordRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) error {

	grantReq := &protocol.GrantPasswordRequest{}
	err := s.decoder.Decode(grantReq, r.Form)
	if err != nil {
		return err
	}
	// username and password is required
	if grantReq.Username == "" || grantReq.Password == "" {
		return protocol.ErrInvalidGrant.Desc("username and password is required")
	}

	req.PasswordReq = grantReq
	req.GenerateRefresh = true
	// req.UserID should set by caller
	return nil
}
