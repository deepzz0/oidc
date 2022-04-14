// Package protocol provides ...
package protocol

// GrantType grant access type
type GrantType string

// Grant type list
const (
	// "authorization_code" used for the Token Request in the Authorization Code Flow
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// "refresh_token" used for the Token Request in the Refresh Token Flow
	GrantTypeRefreshToken GrantType = "refresh_token"
	// "client_credentials" used for the Token Request in the Client Credentials Flow
	GrantTypeClientCredentials = "client_credentials"
	// "password" used for the Token Request in the Password Flow
	GrantTypePassword = "password"
	// "__implicit" used for the Token Request in the Implicit Flow, not real
	GrantTypeImplicit = "__implicit"

	// GrantTypeBearer "urn:ietf:params:oauth:grant-type:jwt-bearer" used for the JWT Authorization Grant
	GrantTypeJwtBearer GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// GrantTypeTokenExchange "urn:ietf:params:oauth:grant-type:token-exchange" used for the OAuth Token Exchange Grant
	GrantTypeTokenExchange GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// GrantTypeDeviceCode "urn:ietf:params:oauth:grant-type:device_code" used for the Device Code Grant
	// https://datatracker.ietf.org/doc/html/rfc8628
	GrantTypeDeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// AccessData xx
type AccessData struct {
}
