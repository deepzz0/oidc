// Package oidc provides ...
package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/deepzz0/oidc/protocol"
)

func (s *Server) handleAuthorizationCodeRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) error {

	// validate grant type
	if !ValidateGrantType(req.Client.GrantTypes(), protocol.GrantTypeAuthorizationCode) {
		return protocol.ErrInvalidGrant.Desc("unsupported grant type: authorization_code")
	}
	// code is required, must be a valid authorization code
	if req.Code == "" {
		return protocol.ErrInvalidGrant.Desc("code is required")
	}
	authData, err := s.options.Storage.LoadAuthorize(req.Code)
	if err != nil {
		if err == protocol.ErrNotFoundEntity {
			return protocol.ErrInvalidGrant.Desc("code is expired or invalid")
		}
		return protocol.ErrInvalidGrant.Wrap(err).Desc("error loading authorize data")
	}
	if authData.ClientID != req.ClientID {
		return protocol.ErrInvalidGrant.Desc("client code does not match")
	}
	// check expires
	if authData.CreatedAt.Add(time.Second * time.Duration(authData.ExpiresIn)).
		Before(time.Now()) {
		return protocol.ErrInvalidGrant.Desc("authorization data is expired")
	}
	// check redirect uri
	uri := req.Client.RedirectURI()
	if uri == "" {
		return protocol.ErrUnauthorizedClient.Desc("client redirect uri is empty")
	}
	req.RedirectURI, err = ValidateURIList(uri, req.RedirectURI, s.options.RedirectURISeparator)
	if err != nil {
		return protocol.ErrInvalidRequest.Desc("error validating client redirect uri")
	}
	if authData.RedirectURI != req.RedirectURI {
		return protocol.ErrInvalidRequest.Desc("client redirect does not match authorization data")
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
	req.GenerateRefresh = true
	req.UserID = authData.UserID
	return nil
}
