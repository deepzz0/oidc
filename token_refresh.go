// Package oidc provides ...
package oidc

import (
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

// see https://www.rfc-editor.org/rfc/rfc6749#section-6
func (s *Server) handleRefreshTokenRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) error {

	grantReq := &protocol.GrantRefreshTokenRequest{}
	err := s.decoder.Decode(grantReq, r.Form)
	if err != nil {
		return err
	}
	// refresh_token is required
	if grantReq.RefreshToken == "" {
		return protocol.ErrInvalidRequest.Desc("refresh_token is required")
	}

	// auth data
	req.AccessData, err = s.options.Storage.LoadRefresh(grantReq.RefreshToken)
	if err != nil {
		return protocol.ErrInvalidGrant.Wrap(err).Desc("refresh_token is expired or invalid")
	}

	// scope 是否相等
	m := make(map[protocol.Scope]bool)
	for _, v := range req.AccessData.Scope {
		m[v] = true
	}
	for _, v := range grantReq.Scope {
		if !m[v] {
			msg := "the requested scope must not include any scope not originally granted by the resource owner"
			return protocol.ErrAccessDenied.Desc(msg)
		}
	}
	req.RefreshTokenReq = grantReq
	req.GenerateRefresh = true
	req.UserID = req.AccessData.AccessRequest.UserID // previous user_id
	return nil
}
