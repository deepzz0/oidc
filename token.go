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
	testHookGenerateCode = func() (string, error) {
		id, err := uuid.NewRandom()
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(id[:]), nil
	}
)

// GenerateAuthorizeCodeAndSave default authorize code generator
func (s *Server) GenerateAuthorizeCodeAndSave(req *protocol.AuthorizeData) (code string, err error) {
	// test hook
	code, err = testHookGenerateCode()
	if err != nil {
		return
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
	tokenID, err := testHookGenerateCode()
	if err != nil {
		return
	}
	// bearer token
	now := time.Now().UTC()
	exps := req.Client.ExpirationOptions()
	req.CreatedAt = now
	req.ExpiresIn = exps.AccessTokenExpiration
	req.TokenType = string(s.options.TokenType)
	switch s.options.TokenType {
	case TokenTypeJWT:
		claims := jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second *
				time.Duration(exps.AccessTokenExpiration))),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    req.Iss,
			Subject:   req.UserID,
			ID:        tokenID,
			Audience:  append(req.Audience, req.Client.ClientID()),
		}
		token, err = signPayload(req.Client, claims)
		if err != nil {
			return
		}
	case TokenTypeBearer:
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
		refresh, err = testHookGenerateCode()
		if err != nil {
			return
		}
		err = s.options.Storage.SaveRefresh(refresh, token, exps.RefreshTokenExpiration)
	}
	return
}
