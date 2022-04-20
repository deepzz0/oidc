// Package oidc provides ...
package oidc

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/deepzz0/oidc/pkg/crypto"
	"github.com/deepzz0/oidc/protocol"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// GenerateAuthorizeCode default authorize code generator
func (s *Server) GenerateAuthorizeCode(req *protocol.AuthorizeData) (code string, err error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return
	}
	code = base64.RawURLEncoding.EncodeToString(id[:])

	exps := req.Client.ExpirationOptions()
	return code, s.options.Storage.SaveAuthorize(code, int(exps.CodeExpiration), req)
}

// GenerateAccessToken generate access token or refresh_token
func (s *Server) GenerateAccessToken(req *protocol.AuthorizeData, genRefresh bool) (token,
	refresh string, err error) {

	// access token
	id, err := uuid.NewRandom()
	if err != nil {
		return
	}
	tokenID := base64.RawURLEncoding.EncodeToString(id[:])
	// bearer token
	now := time.Now().UTC()
	exps := req.Client.ExpirationOptions()
	switch s.options.TokenType {
	case "Bearer":
		plaintext := []byte(tokenID + ":" + req.UserData["sub"].(string))
		var cipher []byte
		cipher, err = crypto.AESEncrypt(plaintext, []byte(req.Client.ClientSecret()))
		if err != nil {
			return
		}
		token = base64.RawURLEncoding.EncodeToString(cipher[:])
	case "JWT":
		claims := jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(exps.AccessTokenExpiration) *
				time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.options.Issuer,
			Subject:   req.UserData["sub"].(string),
			ID:        tokenID,
			Audience:  []string{req.ClientID},
		}
		var (
			signMethod jwt.SigningMethod
			key        interface{}
		)
		switch req.Client.JSONWebTokenSignAlg() {
		case "HS256":
			signMethod = jwt.SigningMethodHS256
			key = []byte(req.Client.ClientSecret())
		case "RS256":
			signMethod = jwt.SigningMethodRS256
			key, _ = req.Client.PrivateKey()
		}
		jwtToken := jwt.NewWithClaims(signMethod, claims)
		token, err = jwtToken.SignedString(key)
		if err != nil {
			return
		}
	default:
		err = errors.New("unsupported token type: " + string(s.options.TokenType))
		return
	}
	if err = s.options.Storage.SaveAccess(token, req, exps.AccessTokenExpiration); err != nil {
		return
	}
	// refresh token
	if genRefresh {
		var id uuid.UUID
		id, err = uuid.NewRandom()
		if err != nil {
			return
		}
		refresh = base64.RawURLEncoding.EncodeToString(id[:])
		err = s.options.Storage.SaveRefresh(refresh, token, exps.RefreshTokenExpiration)
	}
	return
}
