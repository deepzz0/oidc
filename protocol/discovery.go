// Package protocol provides ...
package protocol

// https://openid.net/specs/openid-connect-discovery-1_0.html

// Configuration see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
// and https://www.rfc-editor.org/rfc/rfc8414
// See example: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
type Configuration struct {
	// URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.
	// This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
	Issuer string `json:"issuer"` // REQUIRED, eg: https://example.com/oidc
	// URL of the authorization server's authorization endpoint [RFC6749].  This is REQUIRED unless no grant types
	// are supported that use the authorization endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint"` // REQUIRED, eg: https://example.com/oidc/authorize
	// URL of the authorization server's token endpoint. This is REQUIRED unless only the implicit grant type is supported.
	TokenEndpoint string `json:"token_endpoint"` // REQUIRED, eg: https://example.com/oidc/token
	// URL of the OP's UserInfo Endpoint.
	UserinfoEndpoint string `json:"userinfo_endpoint"` // REQUIRED, eg: https://example.com/oidc/userinfo
	// URL of the authorization server's JWK Set [JWK] document.
	JwksURI string `json:"jwks_uri"` // REQUIRED, eg: https://example.com/oidc/jwks.json
	// See https://www.rfc-editor.org/rfc/rfc7591 and https://openid.net/specs/openid-connect-registration-1_0.html
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"` // RECOMMENDED
	// Defines how to manage OpenID Connect sessions, including postMessage-based logout and RP-initiated logout
	// functionality, see https://openid.net/specs/openid-connect-session-1_0.html
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"` // OPTIONAL
	// OpenID Provider Metadata parameter MUST be included in the Server's discovery responses when Session Management
	// and Discovery are supported
	CheckSessionIframe string `json:"check_session_iframe,omitempty"` // OPTIONAL
	// The Device Code grant type is used by browserless or input-constrained devices in the device flow to exchange
	// a previously obtained device code for an access token. ee https://www.rfc-editor.org/rfc/rfc8628
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"` // OPTIONAL
	// This is used to enable a "log out" feature in clients, allowing the authorization server to clean up any
	// security credentials associated with the authorization. see https://oauth.net/2/token-revocation/
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"` // OPTIONAL
	// The endpoint is an OAuth 2.0 endpoint that takes a parameter representing an OAuth 2.0 token and returns a JSON
	// [RFC7159] document representing the meta information surrounding the token, including whether this token is
	// currently active. see https://www.rfc-editor.org/rfc/rfc7662
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"` // OPTIONAL

	// RECOMMENDED, scope values that this server supports
	ScopesSupported []Scope `json:"scopes_supported,omitempty"`
	// REQUIRED, code, id_token, token id_token
	ResponseTypesSupported []ResponseType `json:"response_types_supported"`
	// OPTIONAL, if omitted, default: query, fragment
	ResponseModesSupported []ResponseMode `json:"response_modes_supported,omitempty"`
	// OPTIONAL, if omitted, default: authorization_code, implicit
	GrantTypesSupported []GrantType `json:"grant_types_supported,omitempty"`
	// OPTIONAL, absolute URI or RFC6711 registered name
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`
	// REQUIRED, valid types include: pairwise and public
	SubjectTypesSupported []SubjectType `json:"subject_types_supported"`
	// REQUIRED, see JWT https://datatracker.ietf.org/doc/html/rfc7519
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// OPTIONAL, see JWT
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	// OPTIONAL, see JWT
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	// OPTIONAL, see JWS https://datatracker.ietf.org/doc/html/rfc7515
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	// OPTIONAL, see JWE https://datatracker.ietf.org/doc/html/rfc7516
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	// OPTIONAL, see JWA https://datatracker.ietf.org/doc/html/rfc7518
	UserinfoEncryptionEncValuesSupported []Display `json:"userinfo_encryption_enc_values_supported,omitempty"`
	// OPTIONAL, see Core6.1, should support none and RS256
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
	// OPTIONAL, JWE encryption algorithm
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	// OPTIONAL, JWE encryption algorithm
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	// OPTIONAL, options are: client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt
	// https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
	TokenEndpointAuthMethodsSupported []ClientAuthMethod `json:"token_endpoint_auth_methods_supported,omitempty"`
	// OPTIONAL, JWT signing algorithm, should support RS256
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	// OPTIONAL, see Core3.1.2.1
	DisplayValuesSupported []Display `json:"display_values_supported,omitempty"`
	// OPTIONAL, see Core5.6, values: normal, aggregated, distributed, if omitted, normal should support
	ClaimTypesSupported []ClaimType `json:"claim_types_supported,omitempty"`
	// RECOMMENDED
	ClaimsSupported []string `json:"claims_supported,omitempty"`
	// OPTIONAL
	ServiceDocumentation string `json:"service_documentation,omitempty"`
	// OPTIONAL, locale language
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"`
	// OPTIONAL, see BCP47 RFC5646
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`
	// OPTIONAL
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"`
	// OPTIONAL
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"`
	// OPTIONAL, specifying whether the OP supports use of the request_uri parameter, with true indicating support.
	// If omitted, the default value is true.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported,omitempty"`
	// OPTIONAL, whether the OP requires any request_uri values used to be pre-registered using the request_uris
	// registration parameter. Pre-registration is REQUIRED when the value is true. If omitted, the default value is false.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`
	// OPTIONAL
	OPPolicyURI string `json:"op_policy_uri,omitempty"`
	// OPTIONAL
	OPTosURI string `json:"op_tos_uri,omitempty"`

	// OPTIONAL, a list of client authentication methods supported by this revocation endpoint
	RevocationEndpointAuthMethodsSupported []ClientAuthMethod `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	// OPTIONAL, see JWT
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	// OPTIONAL, a list of client authentication methods supported by this introspection endpoint.
	IntrospectionEndpointAuthMethodSupported []ClientAuthMethod `json:"introspection_endpoint_auth_method_supported,omitempty"`
	// OPTIONAL, see JWS
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	// OPTIONAL, see https://oauth.net/2/pkce/
	CodeChallengeMethodsSupported []CodeChallengeMethod `json:"code_challenge_methods_supported,omitempty"`
}
