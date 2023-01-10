// Package oidc provides ...
package oidc

import (
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

func (s *Server) handleCredentialsRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) error {

	req.GenerateRefresh = false
	return nil
}
