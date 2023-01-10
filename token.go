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

var (
	defaultAESKey        = []byte{89, 88, 86, 48, 97, 71, 57, 121, 97, 88, 112, 104, 100, 71, 108, 118}
	testHookGenerateCode func() string
)

// GenerateAuthorizeCodeAndSave default authorize code generator
func (s *Server) GenerateAuthorizeCodeAndSave(req *protocol.AuthorizeData) (code string, err error) {
	// test hook
	if testHookGenerateCode == nil {
		var id uuid.UUID
		id, err = uuid.NewRandom()
		if err != nil {
			return
		}
		code = base64.RawURLEncoding.EncodeToString(id[:])
	} else {
		code = testHookGenerateCode()
	}

	exps := req.Client.ExpirationOptions()
	req.CreatedAt = time.Now()
	req.ExpiresIn = exps.CodeExpiration
	return code, s.options.Storage.SaveAuthorize(code, req, req.ExpiresIn)
}

// GenerateAccessTokenAndSave generate access token or refresh_token
func (s *Server) GenerateAccessTokenAndSave(req *protocol.AccessData,
	genRefresh bool) (token, refresh string, err error) {

	// access token, test hook
	var (
		tokenID string
		id      uuid.UUID
	)
	if testHookGenerateCode == nil {
		id, err = uuid.NewRandom()
		if err != nil {
			return
		}
		tokenID = base64.RawURLEncoding.EncodeToString(id[:])
	} else {
		token = testHookGenerateCode()
	}
	// bearer token
	now := time.Now().UTC()
	exps := req.Client.ExpirationOptions()
	req.CreatedAt = now
	req.ExpiresIn = exps.AccessTokenExpiration
	req.TokenType = string(s.options.TokenType)
	switch s.options.TokenType {
	case "JWT":
		claims := jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(exps.AccessTokenExpiration) *
				time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.options.Issuer,
			Subject:   req.UserID,
			ID:        tokenID,
			Audience:  []string{req.Client.ClientID()},
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
	case "Bearer":
		var cipher []byte
		key := make([]byte, 16)
		copy(key, defaultAESKey)
		copy(key, []byte(req.Client.ClientSecret()))
		cipher, err = crypto.AESCBCEncrypt([]byte(tokenID), key)
		if err != nil {
			return
		}
		token = base64.RawURLEncoding.EncodeToString(cipher[:])
	default:
		err = errors.New("unsupported token type: " + string(s.options.TokenType))
		return
	}
	if err = s.options.Storage.SaveAccess(token, req, exps.AccessTokenExpiration); err != nil {
		return
	}
	// refresh token
	if genRefresh {
		if testHookGenerateCode == nil {
			id, err = uuid.NewRandom()
			if err != nil {
				return
			}
			refresh = base64.RawURLEncoding.EncodeToString(id[:])
		} else {
			refresh = testHookGenerateCode()
		}
		err = s.options.Storage.SaveRefresh(refresh, token, exps.RefreshTokenExpiration)
	}
	return
}
