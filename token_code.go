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

// see https://www.rfc-editor.org/rfc/rfc6749#section-4.1
func (s *Server) handleAuthorizationCodeRequest(resp *protocol.Response, r *http.Request,
	req *protocol.AccessRequest) (err error) {

	grantReq := &protocol.GrantAuthorizationCodeRequest{}
	err = s.decoder.Decode(grantReq, r.Form)
	if err != nil {
		return
	}
	// code is required, must be a valid authorization code
	if grantReq.Code == "" {
		return protocol.ErrInvalidGrant.Desc("code is required")
	}
	req.AuthorizeData, err = s.options.Storage.LoadAuthorize(grantReq.Code)
	if err != nil {
		if err == protocol.ErrNotFoundEntity {
			return protocol.ErrInvalidGrant.Desc("code is expired or invalid")
		}
		return protocol.ErrInvalidGrant.Wrap(err).Desc("error loading authorize data")
	}
	// client id is required
	if grantReq.ClientID == "" {
		grantReq.ClientID = req.Client.ClientID()
	}
	if req.AuthorizeData.ClientID != grantReq.ClientID {
		return protocol.ErrInvalidGrant.Desc("client id does not match")
	}
	// check expires
	if req.AuthorizeData.CreatedAt.Add(time.Second * time.Duration(req.AuthorizeData.ExpiresIn)).
		Before(time.Now()) {
		return protocol.ErrInvalidGrant.Desc("authorization data is expired")
	}
	// check redirect uri
	uri := req.Client.RedirectURI()
	grantReq.RedirectURI, err = ValidateURIList(uri, grantReq.RedirectURI,
		s.options.RedirectURISeparator)
	if err != nil {
		return protocol.ErrInvalidRequest.Desc("error validating client redirect uri")
	}
	if req.AuthorizeData.RedirectURI != grantReq.RedirectURI {
		return protocol.ErrInvalidRequest.Desc("client redirect does not match authorization data")
	}
	// verify PKCE, if present in the authorization data
	if req.AuthorizeData.CodeChallenge != "" {
		// https://tools.ietf.org/html/rfc7636#section-4.1
		if !pkceMatcher.MatchString(grantReq.CodeVerifier) {
			return protocol.ErrInvalidRequest.Desc("pkce code challenge verifier does not match")
		}

		// https: //tools.ietf.org/html/rfc7636#section-4.6
		codeVerifier := ""
		switch req.AuthorizeData.CodeChallengeMethod {
		case protocol.CodeChallengeMethodPlain:
			codeVerifier = grantReq.CodeVerifier
		case protocol.CodeChallengeMethodS256:
			hash := sha256.Sum256([]byte(grantReq.CodeVerifier))
			codeVerifier = base64.RawURLEncoding.EncodeToString(hash[:])
		default:
			return protocol.ErrInvalidRequest.Desc("pkce transform algorithm not supported (rfc7636)")
		}
		if codeVerifier != req.AuthorizeData.CodeChallenge {
			return protocol.ErrInvalidGrant.Wrap(errors.New("code_verifier failed comparison with code_challenge")).
				Desc("pkce code verifier does not match challenge")
		}
	}
	// OIDC: https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
	if req.AuthorizeData.OpenID { // oidc offline_access
		req.GenerateRefresh = req.AuthorizeData.OfflineAccess
	} else {
		// OAuth2: https://www.rfc-editor.org/rfc/rfc6749#section-4.1
		req.GenerateRefresh = true
	}
	req.AuthorizationCodeReq = grantReq
	req.UserID = req.AuthorizeData.UserID
	return nil
}
