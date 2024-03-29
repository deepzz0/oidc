// Package examples provides ...
package examples

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/deepzz0/oidc/protocol"
	"github.com/golang-jwt/jwt/v4"
)

// Signer for crypto
var Signer crypto.Signer

func init() {
	key := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----`
	var err error
	Signer, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(key))
	if err != nil {
		panic(err)
	}
}

// TestClient oidc
type TestClient struct {
	ID       string
	Secret   string
	Redirect string
	Type     protocol.ClientType
}

// ClientID return client id
func (c *TestClient) ClientID() string {
	return c.ID
}

// ClientSecret return client secret
func (c *TestClient) ClientSecret() string {
	return c.Secret
}

// ClientType return client type
func (c *TestClient) ClientType() protocol.ClientType {
	return c.Type
}

// RedirectURI return client redirect uri, multiple URLs by comma-separating
func (c *TestClient) RedirectURI() string {
	return c.Redirect
}

// ResponseTypes allowed authorize type
func (c *TestClient) ResponseTypes() []protocol.ResponseType {
	return []protocol.ResponseType{
		protocol.ResponseTypeCode,
		protocol.ResponseTypeToken,
		protocol.ResponseTypeIDToken,
		protocol.ResponseTypeNone,
		protocol.ResponseTypeDevice,

		protocol.ResponseTypeCodeToken,
		protocol.ResponseTypeCodeIDToken,
		protocol.ResponseTypeTokenIDToken,
		protocol.ResponseTypeCodeTokenIDToken,
	}
}

// GrantTypes grant types
func (c *TestClient) GrantTypes() []protocol.GrantType {
	return []protocol.GrantType{
		protocol.GrantTypeAuthorizationCode,
		protocol.GrantTypeRefreshToken,
		protocol.GrantTypeRefreshToken,
		protocol.GrantTypeClientCredentials,
		protocol.GrantTypePassword,
		protocol.GrantTypeImplicit,
		protocol.GrantTypeJwtBearer,
		protocol.GrantTypeTokenExchange,
		protocol.GrantTypeDeviceCode,
	}
}

// IsScopeAllowed allowed scopes
func (c *TestClient) IsScopeAllowed(scope string) bool {
	return scope == "scope1"
}

// PrivateKey loads the client private key
func (c *TestClient) PrivateKey() (crypto.Signer, error) {
	return Signer, nil
}

// JWTSigningMethod sign with idtoken
func (c *TestClient) JWTSigningMethod() jwt.SigningMethod { // HS256 | RS256 | ES256
	signer, err := c.PrivateKey()
	if err != nil {
		return jwt.SigningMethodHS256
	}
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		return jwt.SigningMethodRS256
	case *ecdsa.PublicKey:
		return jwt.SigningMethodES256
	}
	return jwt.SigningMethodHS256
}

// DeviceAuthPath device authorize path
func (c *TestClient) DeviceAuthPath() string {

	return ""
}

// ExpirationOptions client expirations, seconds
func (c *TestClient) ExpirationOptions() protocol.Expirations {
	return protocol.DefaultExpirations
}
