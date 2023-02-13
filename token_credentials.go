// Package oidc provides ...
package oidc

import (
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

// see https://www.rfc-editor.org/rfc/rfc6749#section-4.4
func (s *Server) handleCredentialsRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) error {

	grantReq := &protocol.GrantClientCredentialsRequest{}
	err := s.decoder.Decode(grantReq, r.Form)
	if err != nil {
		return err
	}
	req.ClientCredentialsReq = grantReq
	req.GenerateRefresh = false
	return nil
}
