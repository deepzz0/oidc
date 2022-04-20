// Package oidc provides ...
package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/deepzz0/oidc/protocol"
)

func (s *Server) handleAuthorizationCodeRequest(resp *protocol.Response, r *http.Request) error {
	req := &protocol.AccessTokenRequest{}
	err := s.decoder.Decode(req, r.Form)
	if err != nil {
		return protocol.ErrInvalidRequest.Wrap(err).Desc("error decoding form")
	}

	// client authentication
	auth := s.getClientAuth(r, s.options.AllowClientSecretInParams)
	if auth == nil {
		return protocol.ErrInvalidRequest.Desc("check auth error")
	}
	// code is required
	if req.Code == "" {
		return protocol.ErrInvalidGrant.Desc("code is required")
	}
	// must have a valid client
	cli, err := s.getClient(auth, resp)
	if err != nil {
		return err
	}
	// must be a valid authorization code
	authData, err := s.options.Storage.LoadAuthorize(req.Code)
	if err != nil {
		if err == protocol.ErrNotFoundEntity {
			return protocol.ErrExpiredToken.Desc("authorization data is expired")
		}
		return protocol.ErrInvalidGrant.Wrap(err).Desc("error loading authorize data")
	}
	// code must be from the client
	if authData.ClientID != req.ClientID {
		return protocol.ErrInvalidGrant.Desc("client code does not match")
	}
	req.RedirectURI, err = ValidateURIList(cli.RedirectURI(), req.RedirectURI, s.options.RedirectURISeparator)
	if err != nil {
		return protocol.ErrInvalidRequest.Desc("error validating client redirect uri")
	}
	// verify PKCE, if present in the authorization data
	if authData.CodeChallenge != "" {
		// https://tools.ietf.org/html/rfc7636#section-4.1
		if !pkceMatcher.MatchString(req.CodeVerifier) {
			return protocol.ErrInvalidRequest.Desc("pkce code challenge verifier does not match")
		}

		// https: //tools.ietf.org/html/rfc7636#section-4.6
		codeVerifier := ""
		switch authData.CodeChallengeMethod {
		case "", protocol.CodeChallengeMethodPlain:
			codeVerifier = req.CodeVerifier
		case protocol.CodeChallengeMethodS256:
			hash := sha256.Sum256([]byte(req.CodeVerifier))
			codeVerifier = base64.RawURLEncoding.EncodeToString(hash[:])
		default:
			return protocol.ErrInvalidRequest.Desc("pkce transform algorithm not supported (rfc7636)")
		}
		if codeVerifier != authData.CodeChallenge {
			return protocol.ErrInvalidGrant.Wrap(errors.New("code_verifier failed comparison with code_challenge")).
				Desc("pkce code verifier does not match challenge")
		}
	}
	// create access token
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
