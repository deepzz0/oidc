// Package oidc provides ...
package oidc

import (
	"encoding/base64"
	"time"

	"github.com/deepzz0/oidc/protocol"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// AuthorizeCodeGenFunc authorize code generator
type AuthorizeCodeGenFunc func(req *protocol.AuthorizeData) (code string, err error)

// GenerateAuthorizeCode default authorize code generator
func GenerateAuthorizeCode(req *protocol.AuthorizeData) (code string, err error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return
	}
	return base64.RawURLEncoding.EncodeToString(id[:]), nil
}

// AccessTokenGenFunc access token generator
type AccessTokenGenFunc func(data *protocol.AuthorizeData,
	genRefresh bool, issuer string) (token, refresh string, err error)

// GenerateAccessToken default access token generator
func GenerateAccessToken(data *protocol.AuthorizeData,
	genRefresh bool, issuer string) (token, refresh string, err error) {

	id, err := uuid.NewRandom()
	if err != nil {
		return
	}
	token = base64.RawURLEncoding.EncodeToString(id[:])

	if genRefresh {
		id, err = uuid.NewRandom()
		if err != nil {
			return
		}
		refresh = base64.RawURLEncoding.EncodeToString(id[:])
	}
	return
}

// GenerateAccessTokenJWT access token generator jwt
func GenerateAccessTokenJWT(data *protocol.AuthorizeData, genRefresh bool,
	issuer string) (token, refresh string, err error) {

	id, err := uuid.NewRandom()
	if err != nil {
		return
	}
	jwtID := base64.RawURLEncoding.EncodeToString(id[:])
	if genRefresh {
		id, err = uuid.NewRandom()
		if err != nil {
			return
		}
		refresh = base64.RawURLEncoding.EncodeToString(id[:])
	}

	now := time.Now().UTC()
	exps := data.Client.ExpirationOptions()
	claims := jwt.RegisteredClaims{
		// A usual scenario is to set the expiration time relative to the current time
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(exps.AccessTokenExpiration) *
			time.Second)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    issuer,
		Subject:   data.UserData["sub"].(string),
		ID:        jwtID,
		Audience:  []string{data.ClientID},
	}
	var (
		signMethod jwt.SigningMethod
		key        interface{}
	)
	switch data.Client.JSONWebTokenSignAlg() {
	case "HS256":
		signMethod = jwt.SigningMethodHS256
		key = []byte(data.Client.ClientSecret())
	case "RS256":
		signMethod = jwt.SigningMethodRS256
		key, _ = data.Client.PrivateKey()
	}
	jwtToken := jwt.NewWithClaims(signMethod, claims)
	token, err = jwtToken.SignedString(key)
	return
}
