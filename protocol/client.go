// Package protocol provides ...
package protocol

import "crypto"

// DefaultExpirations default expirations
var DefaultExpirations = Expirations{
	CodeExpiration:         600,  // 10m
	AccessTokenExpiration:  3600, // 1h
	RefreshTokenExpiration: 3600, // 1h
	IDTokenExpiration:      3600, // 1h
	PollingInterval:        5,
}

// Client OAuth2/OIDC client
type Client interface {
	// ClientID return client id
	ClientID() string
	// ClientSecret return client secret
	ClientSecret() string
	// RedirectURI return client redirect uri, multiple URLs by comma-separating
	RedirectURI() string
	// allowed authorize type
	ResponseTypes() []ResponseType
	// GrantTypes grant types
	GrantTypes() []GrantType
	// allowed scopes
	IsScopeAllowed(scope string) bool

	// PrivateKey loads the client private key
	PrivateKey() (crypto.Signer, error)
	// JSONWebTokenSignAlg sign with idtoken
	JSONWebTokenSignAlg() string // HS256 | RS256
	// DeviceAuthPath device authorize path
	DeviceAuthPath() string
	// client expirations, seconds
	ExpirationOptions() Expirations
}

// Expirations settings expiration
type Expirations struct {
	CodeExpiration         int
	AccessTokenExpiration  int
	RefreshTokenExpiration int
	IDTokenExpiration      int

	PollingInterval int // device code
}
