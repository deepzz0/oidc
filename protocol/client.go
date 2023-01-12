// Package protocol provides ...
package protocol

import (
	"crypto"

	"github.com/golang-jwt/jwt/v4"
)

// ClientAuthMethod This section defines a set of Client Authentication methods that are used by Clients to
// authenticate to the Authorization Server when using the Token Endpoint. During Client Registration, the RP
// (Client) MAY register a Client Authentication method. If no method is registered, the default method is
// client_secret_basic.
// https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
type ClientAuthMethod string

// client auth method list
const (
	// Clients that have received a client_secret value from the Authorization Server authenticate with the
	// Authorization Server in accordance with Section 2.3.1 of OAuth 2.0 [RFC6749] using the HTTP Basic
	// authentication scheme.
	ClientAuthMethodSecretBasic ClientAuthMethod = "client_secret_basic"
	// Clients that have received a client_secret value from the Authorization Server, authenticate with the
	// Authorization Server in accordance with Section 2.3.1 of OAuth 2.0 [RFC6749] by including the Client
	// Credentials in the request body.
	ClientAuthMethodSecretPost ClientAuthMethod = "client_secret_post"
	// Clients that have received a client_secret value from the Authorization Server create a JWT using an
	// HMAC SHA algorithm, such as HMAC SHA-256. The HMAC (Hash-based Message Authentication Code) is
	// calculated using the octets of the UTF-8 representation of the client_secret as the shared key.
	//  iss REQUIRED
	//  sub REQUIRED
	//  aud REQUIRED
	//  jti REQUIRED
	//  exp REQUIRED
	//  iat OPTIONAL
	ClientAuthMethodSecretJWT ClientAuthMethod = "client_secret_jwt"
	// Clients that have registered a public key sign a JWT using that key.
	//  iss REQUIRED
	//  sub REQUIRED
	//  aud REQUIRED
	//  jti REQUIRED
	//  exp REQUIRED
	//  iat OPTIONAL
	ClientAuthMethodPrivateKeyJWT ClientAuthMethod = "private_key_jwt"
	// The Client does not authenticate itself at the Token Endpoint, either because it uses only the Implicit
	// Flow (and so does not use the Token Endpoint) or because it is a Public Client with no Client Secret or
	// other authentication mechanism.
	ClientAuthMethodNone ClientAuthMethod = "none"

	// https://www.rfc-editor.org/rfc/rfc8705.html
	// Indicates that client authentication to the authorization server will occur with mutual TLS utilizing
	// the PKI method of associating a certificate to a client
	ClientAuthMethodTLSClientAuth = "tls_client_auth"
	// Indicates that client authentication to the authorization server will occur using mutual TLS with the
	// client utilizing a self-signed certificate.
	ClientAuthMethodSelfSignedTLSClientAuth = "self_signed_tls_client_auth"
)

// ClientAssertionType client authentication, the client uses the following parameter values and encodings.
type ClientAssertionType string

// assertion type list
const (
	// The value of the "client_assertion" parameter contains a single JWT.  It MUST NOT contain more than one
	// JWT.
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// The value of the "client_assertion" parameter MUST contain a single SAML 2.0 Assertion.  The SAML
	// Assertion XML data MUST be encoded using base64url, where the encoding adheres to the definition in
	// Section 5 of RFC 4648 [RFC4648] and where the padding bits are set to zero.  To avoid the need for
	// subsequent encoding steps (by "application/x-www-form-urlencoded" [W3C.REC-html401-19991224], for
	// example), the base64url-encoded data SHOULD NOT be line wrapped and pad characters ("=") SHOULD NOT
	// be included.
	ClientAssertionTypeSMAL2Bearer = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"
)

// Expirations settings expiration
type Expirations struct {
	// Authorize code expires
	CodeExpiration int
	// Access token expires
	AccessTokenExpiration int
	// Refresh token expires
	RefreshTokenExpiration int
	// ID token expires
	IDTokenExpiration int

	// Device code polling interval
	PollingInterval int
}

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
	// RedirectURI return client redirect uri, multiple URLs by comma-separating.
	// see https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2
	RedirectURI() string
	// ResponseTypes allowed authorize type
	ResponseTypes() []ResponseType
	// GrantTypes grant types
	GrantTypes() []GrantType
	// IsScopeAllowed allowed custom unknown scopes
	IsScopeAllowed(scope string) bool

	// PrivateKey loads the client private key
	PrivateKey() (crypto.Signer, error)
	// JWTSigningMethod sign with idtoken
	JWTSigningMethod() jwt.SigningMethod
	// DeviceAuthPath device authorize path
	DeviceAuthPath() string
	// ExpirationOptions client expirations, seconds
	ExpirationOptions() Expirations
}
