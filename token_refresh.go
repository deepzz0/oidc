// Package oidc provides ...
package oidc

import (
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

func (s *Server) handleRefreshTokenRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) error {

	// validate grant type
	if !ValidateGrantType(req.Client.GrantTypes(), protocol.GrantTypeRefreshToken) {
		return protocol.ErrInvalidGrant.Desc("unsupported grant type: refresh_token")
	}
	// refresh_token is required
	if req.RefreshToken == "" {
		return protocol.ErrInvalidGrant.Desc("refresh_token is required")
	}

	// auth data
	var err error
	req.AccessData, err = s.options.Storage.LoadRefresh(req.RefreshToken)
	if err != nil {
		return protocol.ErrInvalidGrant.Wrap(err).Desc("refresh_token is expired or invalid")
	}
	if req.AccessData.AccessRequest.ClientID != req.ClientID {
		return protocol.ErrInvalidClient.Desc("client id must be the same from previous token")
	}
	// scope 是否相等
	m := make(map[protocol.Scope]bool)
	for _, v := range req.AccessData.Scope {
		m[v] = true
	}
	for _, v := range req.Scope {
		if !m[v] {
			msg := "the requested scope must not include any scope not originally granted by the resource owner"
			return protocol.ErrAccessDenied.Desc(msg)
		}
	}
	req.GenerateRefresh = true
	req.UserID = req.AccessData.AccessRequest.UserID
	return nil
}
