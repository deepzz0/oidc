// Package protocol provides ...
package protocol

// TokenTypeHint A hint about the type of the token submitted for revocation.  Clients MAY pass this parameter
// in order to help the authorization server to optimize the token lookup.
type TokenTypeHint string

// token type list
const (
	// An access token as defined in [RFC6749], Section 1.4
	TokenTypeHintAccessToken TokenTypeHint = "access_token"
	// refresh_token: A refresh token as defined in [RFC6749], Section 1.5
	TokenTypeHintRefreshToken TokenTypeHint = "refresh_token"
)
