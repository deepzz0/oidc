// Package protocol provides ...
package protocol

import (
	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/square/go-jose.v2"
)

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
	GrantTypePassword GrantType = "password"
	// "implicit" used for the Token Request in the Implicit Flow, not real
	GrantTypeImplicit GrantType = "__implicit"

	// GrantTypeBearer "urn:ietf:params:oauth:grant-type:jwt-bearer" used for the JWT Authorization Grant
	// https://www.rfc-editor.org/rfc/rfc7523
	GrantTypeJwtBearer GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// GrantTypeTokenExchange "urn:ietf:params:oauth:grant-type:token-exchange" used for the OAuth Token Exchange Grant
	// https://oauth.net/2/token-exchange/
	GrantTypeTokenExchange GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// GrantTypeDeviceCode "urn:ietf:params:oauth:grant-type:device_code" used for the Device Code Grant
	// https://datatracker.ietf.org/doc/html/rfc8628
	GrantTypeDeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	// GrantTypeSAML2Bearer urn:ietf:params:oauth:grant-type:saml2-bearer used for OAuth SMAL2
	// https://www.rfc-editor.org/rfc/rfc7522.html
	GrantTypeSAML2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer"
)

// IsExtensionGrants judge GrantType whether extension grants
func IsExtensionGrants(grantType GrantType) bool {
	return grantType == GrantTypeJwtBearer ||
		grantType == GrantTypeTokenExchange ||
		grantType == GrantTypeDeviceCode ||
		grantType == GrantTypeSAML2Bearer
}

// TokenType grant token type
type TokenType string

// Token type list
const (
	// https://www.rfc-editor.org/rfc/rfc7519.html
	TokenTypeJWT TokenType = "urn:ietf:params:oauth:token-type:jwt"
	// https://www.rfc-editor.org/rfc/rfc8693.html#name-token-type-identifiers
	TokenTypeAccessToken  TokenType = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken TokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      TokenType = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeSAML1        TokenType = "urn:ietf:params:oauth:token-type:saml1"
	TokenTypeSAML2        TokenType = "urn:ietf:params:oauth:token-type:saml2"
)

// IDToken The primary extension that OpenID Connect makes to OAuth 2.0 to enable End-Users to be Authenticated is the ID
// Token data structure. The ID Token is a security token that contains Claims about the Authentication of an End-User by
// an Authorization Server when using a Client, and potentially other requested Claims. The ID Token is represented as a
// JSON Web Token (JWT) [JWT].
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type IDToken struct {
	Issuer     string           `json:"iss"`
	Subject    string           `json:"sub"` // User identifier
	Audience   jwt.ClaimStrings `json:"aud"` // Must contain oauth2 client_id
	Expiration jwt.NumericDate  `json:"exp"` // Expiration time on or after which the ID Token MUST NOT be accepted for processing.
	IssuedAt   jwt.NumericDate  `json:"iat"` // Time at which the JWT was issued

	// When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED;
	// otherwise, its inclusion is OPTIONAL.
	AuthTime jwt.NumericDate `json:"auth_time,omitempty"`
	// String value used to associate a Client session with an ID Token, and to mitigate replay attacks. If present in
	// the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in
	// the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce
	// Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request.
	Nonce string `json:"nonce,omitempty"`

	// Authentication Context Class Reference. String specifying an Authentication Context Class Reference value that
	// identifies the Authentication Context Class that the authentication performed satisfied. The value "0" indicates
	// the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1.
	// eg. urn:mace:incommon:iap:silver
	ACSR string `json:"acsr,omitempty"`
	// Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in
	// the authentication. For instance, values might indicate that both password and OTP authentication methods were used.
	AMR []string `json:"amr,omitempty"`
	// Authorized party - the party to which the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID
	// of this party. This Claim is only needed when the ID Token has a single audience value and that audience is different
	// than the authorized party. It MAY be included even when the authorized party is the same as the sole audience.
	AZP string `json:"azp,omitempty"`

	// Access Token hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the
	// ASCII representation of the access_token value, where the hash algorithm used is the hash algorithm used in the alg
	// Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the access_token value with
	// SHA-256, then take the left-most 128 bits and base64url encode them. The at_hash value is a case sensitive string.
	// see https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
	ATHash string `json:"at_hash,omitempty"`
	// Code hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII
	// representation of the code value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter
	// of the ID Token's JOSE Header. For instance, if the alg is HS512, hash the code value with SHA-512, then take the
	// left-most 256 bits and base64url encode them. The c_hash value is a case sensitive string.
	// If the ID Token is issued from the Authorization Endpoint with a code, which is the case for the response_type values
	// code id_token and code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
	CHash string `json:"c_hash,omitempty"`

	// Public key used to check the signature of an ID Token issued by a Self-Issued OpenID Provider, as specified in Section 7.
	// The key is a bare key in JWK [JWK] format (not an X.509 certificate value). The sub_jwk value is a JSON object. Use of
	// the sub_jwk Claim is NOT RECOMMENDED when the OP is not Self-Issued.
	// see https://openid.net/specs/openid-connect-core-1_0.html#SelfIssuedResponse
	SubJWK jose.JSONWebKey `json:"sub_jwk"`
}

// UserInfo This specification defines a set of standard Claims. They can be requested to be returned either in the UserInfo
// Response, per Section 5.3.2, or in the ID Token, per Section 2.
type UserInfo struct {
	// Subject - Identifier for the End-User at the Issuer.
	Subject string `json:"sub,omitempty"`
	// nd-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according
	// to the End-User's locale and preferences.
	Name string `json:"name,omitempty"`
	// Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names; all
	// can be present, with the names being separated by space characters.
	GivenName string `json:"given_name,omitempty"`
	// Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family
	// name; all can be present, with the names being separated by space characters.
	FamilyName string `json:"family_name,omitempty"`
	// Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be present, with
	// the names being separated by space characters. Also note that in some cultures, middle names are not used.
	MiddleName string `json:"middle_name,omitempty"`
	// Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might
	// be returned alongside a given_name value of Michael.
	Nickname string `json:"nickname,omitempty"`
	// Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any
	// valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being
	// unique, as discussed in Section 5.7.
	PreferredUsername string `json:"preferred_username,omitempty"`
	// URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
	Profile string `json:"profile,omitempty"`
	// URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file),
	// rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the
	// End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
	Picture string `json:"picture,omitempty"`
	// URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an organization
	// that the End-User is affiliated with.
	Website string `json:"website,omitempty"`
	// End-User's preferred e-mail address. Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax. The RP MUST NOT rely
	// upon this value being unique, as discussed in Section 5.7.
	Email string `json:"email,omitempty"`
	// True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this means that the
	// OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was
	// performed. The means by which an e-mail address is verified is context-specific, and dependent upon the trust framework or
	// contractual agreements within which the parties are operating.
	EmailVerified bool `json:"email_verified,omitempty"`
	// End-User's gender. Values defined by this specification are female and male. Other values MAY be used when neither of the defined
	// values are applicable.
	Gender string `json:"gender,omitempty"`
	// End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that
	// it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the underlying platform's date related
	// function, providing just year can result in varying month and day, so the implementers need to take this factor into account
	// to correctly process the dates.
	Birthdate string `json:"birthdate,omitempty"`
	// String from zoneinfo [zoneinfo] time zone database representing the End-User's time zone. For example, Europe/Paris or
	// America/Los_Angeles.
	Zoneinfo string `json:"zoneinfo,omitempty"`
	// End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language
	// code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or
	// fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example,
	// en_US; Relying Parties MAY choose to accept this locale syntax as well.
	Locale string `json:"locale,omitempty"`
	// End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim, for example, +1 (425) 555-1212
	// or +56 (2) 687 2400. If the phone number contains an extension, it is RECOMMENDED that the extension be represented using the
	// RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
	PhoneNumber string `json:"phone_number,omitempty"`
	// True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means that the OP
	// took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed.
	// The means by which a phone number is verified is context-specific, and dependent upon the trust framework or contractual
	// agreements within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and any extensions
	// MUST be represented in RFC 3966 format.
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`
	// End-User's preferred postal address. The value of the address member is a JSON [RFC4627] structure containing some or all of the
	// members defined in Section 5.1.1.
	Address Address `json:"address,omitempty"`
	// Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds from
	// 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	UpdatedAt jwt.NumericDate `json:"updated_at,omitempty"`
}

// Address The Address Claim represents a physical mailing address.
type Address struct {
	// Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by
	// newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character
	// ("\n").
	Formatted string `json:"formatted,omitempty"`
	// Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street
	// address information. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a
	// carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
	StreetAddress string `json:"street_address,omitempty"`
	// City or locality component.
	Locality string `json:"locality,omitempty"`
	// State, province, prefecture, or region component.
	Region string `json:"region,omitempty"`
	// Zip code or postal code component.
	PostalCode string `json:"postal_code,omitempty"`
	// Country name component.
	Country string `json:"country,omitempty"`
}
