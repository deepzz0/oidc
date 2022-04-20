// Package oidc provides ...
package oidc

import (
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

func (s *Server) handleRefreshTokenRequest(resp *protocol.Response, r *http.Request) error {
	req := &protocol.RefreshTokenRequest{}
	err := s.decoder.Decode(req, r.Form)
	if err != nil {
		return protocol.ErrInvalidRequest.Wrap(err).Desc("error decoding form")
	}

	// client authentication
	auth := s.getClientAuth(r, s.options.AllowClientSecretInParams)
	if auth == nil {
		return protocol.ErrInvalidRequest.Desc("check auth error")
	}
	// refresh_token is required
	if req.RefreshToken == "" {
		return protocol.ErrInvalidGrant.Desc("refresh_token is required")
	}
	// TODO assertion_type

	// must have a valid client
	cli, err := s.getClient(auth, resp)
	if err != nil {
		return protocol.ErrInvalidClient.Wrap(err)
	}
	// validate grant type
	if !ValidateGrantType(cli.GrantTypes(), protocol.GrantTypeRefreshToken) {
		return protocol.ErrUnauthorizedClient
	}
	// auth data
	authData, err := s.options.Storage.LoadRefresh(req.RefreshToken)
	if err != nil {
		return protocol.ErrExpiredToken.Wrap(err)
	}
	if authData.ClientID != req.ClientID {
		return protocol.ErrInvalidClient.Desc("Client id must be the same from previous token")
	}
	// scope 是否相等
	// TODO

	token, refresh, err := s.GenerateAccessToken(authData, true)
	if err != nil {
		return protocol.ErrServerError.Wrap(err)
	}
	resp.Output["access_token"] = token
	resp.Output["refresh_token"] = refresh
	resp.Output["token_type"] = s.options.TokenType
	resp.Output["expires_in"] = authData.Client.ExpirationOptions().AccessTokenExpiration
	for _, s := range authData.Scope {
		if s == string(protocol.ScopeOpenID) {
			key, err := authData.Client.PrivateKey()
			if err != nil {
				return protocol.ErrInvalidGrant.Wrap(err)
			}
			// UserData must be id_token data
			idToken, err := signPayload(key, authData.UserData)
			if err != nil {
				return protocol.ErrServerError.Wrap(err)
			}
			resp.Output["id_token"] = idToken
			break
		}
	}
	return nil
}
