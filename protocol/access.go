// Package protocol provides ...
package protocol

// GrantType grant access type
type GrantType string

// Grant type list, The correlation between the two fields is listed in the table below.
// https://www.rfc-editor.org/rfc/rfc7591#page-12
//  +-----------------------------------------------+-------------------+
//  | grant_types value includes:                   | response_types    |
//  |                                               | value includes:   |
//  +-----------------------------------------------+-------------------+
//  | authorization_code                            | code              |
//  | implicit                                      | token             |
//  | password                                      | (none)            |
//  | client_credentials                            | (none)            |
//  | refresh_token                                 | (none)            |
//  | urn:ietf:params:oauth:grant-type:jwt-bearer   | (none)            |
//  | urn:ietf:params:oauth:grant-type:saml2-bearer | (none)            |
//  +-----------------------------------------------+-------------------+
const (
	// "authorization_code" used for the Token Request in the Authorization Code Flow
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// "refresh_token" used for the Token Request in the Refresh Token Flow
	GrantTypeRefreshToken GrantType = "refresh_token"
	// "client_credentials" used for the Token Request in the Client Credentials Flow
	GrantTypeClientCredentials = "client_credentials"
	// "password" used for the Token Request in the Password Flow
	GrantTypePassword = "password"
	// "implicit" used for the Token Request in the Implicit Flow, not real
	GrantTypeImplicit = "implicit"

	// GrantTypeBearer "urn:ietf:params:oauth:grant-type:jwt-bearer" used for the JWT Authorization Grant
	// https://www.rfc-editor.org/rfc/rfc7523
	GrantTypeJwtBearer GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// GrantTypeTokenExchange "urn:ietf:params:oauth:grant-type:token-exchange" used for the OAuth Token Exchange Grant
	// https://oauth.net/2/token-exchange/
	GrantTypeTokenExchange GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// GrantTypeDeviceCode "urn:ietf:params:oauth:grant-type:device_code" used for the Device Code Grant
	// https://datatracker.ietf.org/doc/html/rfc8628
	GrantTypeDeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)
