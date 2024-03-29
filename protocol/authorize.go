// Package protocol provides ...
package protocol

// ResponseType authorization endpoint is used by the authorization code grant type and implicit grant type flows
// If an authorization request is missing the "response_type" parameter, or if the response type is not understood,
// the authorization server MUST return an error response as described in Section 4.1.2.1.
// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
type ResponseType string

// Response type list, The following table lists the correspondence between response_type values that the Client
// will use and grant_type values that MUST be included in the registered grant_types list
//  code: authorization_code
//  id_token: implicit
//  token id_token: implicit
//  code id_token: authorization_code, implicit
//  code token: authorization_code, implicit
//  code token id_token: authorization_code, implicit
const (
	// "code" for requesting an authorization code
	ResponseTypeCode ResponseType = "code"
	// "token" for requesting an access token (implicit grant)
	ResponseTypeToken ResponseType = "token"
	// "id_token" for requesting an oidc on OAuth2
	// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#id_token
	ResponseTypeIDToken ResponseType = "id_token"
	// The Response Type none SHOULD NOT be combined with other Response Types.
	// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
	ResponseTypeNone ResponseType = "none"
	// "device" is custom response_type for Device Code Flow
	ResponseTypeDevice = "device"

	ResponseTypeCodeToken        = "code token"
	ResponseTypeCodeIDToken      = "code id_token"
	ResponseTypeTokenIDToken     = "token id_token"
	ResponseTypeCodeTokenIDToken = "code token id_token"
)

// CodeChallengeMethod proof key for code exchange method
type CodeChallengeMethod string

// PKCE code challenge method list
const (
	// code_verifier
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
	// BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

// ResponseMode Informs the Authorization Server of the mechanism to be used for returning
// Authorization Response parameters from the Authorization Endpoint.
// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
type ResponseMode string

// Response mode list
const (
	// In this mode, Authorization Response parameters are encoded in the query string added
	// to the redirect_uri when redirecting back to the Client.
	ResponseModeQuery ResponseMode = "query"
	// In this mode, Authorization Response parameters are encoded in the fragment added to
	// the redirect_uri when redirecting back to the Client.
	ResponseModeFragment ResponseMode = "fragment"
	// In this mode, Authorization Response parameters are encoded as HTML form values that
	// are auto-submitted in the User Agent, and thus are transmitted via the HTTP POST
	// method to the Client, with the result parameters being encoded in the body using the
	// application/x-www-form-urlencoded format.
	// see https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
	ResponseModeFormPost ResponseMode = "form_post"

	// This specification defines a new response mode for RFC6749 that uses HTML5 Web Messaging
	// (a.k.a window.postMessage()) instead of the redirect for the Authorization Response
	// from the Authorization Endpoint.
	// https://datatracker.ietf.org/doc/html/draft-sakimura-oauth-wmrm-00
	ResponseModeWebMessage ResponseMode = "web_message"
)

// Display specifies how the Authorization Server displays the authentication and consent
// user interface pages to the End-User.
type Display string

// Display list
const (
	// The Authorization Server SHOULD display the authentication and consent UI consistent
	// with a full User Agent page view. If the display parameter is not specified, this is
	// the default display mode.
	DisplayPage Display = "page"
	// The Authorization Server SHOULD display the authentication and consent UI consistent
	// with a popup User Agent window. The popup User Agent window should be of an appropriate
	// size for a login-focused dialog and should not obscure the entire window that it is
	// popping up over.
	DisplayPopup Display = "popup"
	// The Authorization Server SHOULD display the authentication and consent UI consistent
	// with a device that leverages a touch interface.
	DisplayTouch Display = "touch"
	// The Authorization Server SHOULD display the authentication and consent UI consistent
	// with a "feature phone" type display.
	DisplayWap Display = "wap"
)

// IsValidDisplay whether display option is valid
func IsValidDisplay(opt Display) bool {
	return opt == DisplayPage || opt == DisplayPopup ||
		opt == DisplayTouch || opt == DisplayWap
}

// Prompt Space delimited, case sensitive list of ASCII string values that specifies whether
// the Authorization Server prompts the End-User for reauthentication and consent.
type Prompt string

// Prompt list
const (
	// The Authorization Server MUST NOT display any authentication or consent user interface
	// pages. An error is returned if an End-User is not already authenticated or the Client
	// does not have pre-configured consent for the requested Claims or does not fulfill other
	// conditions for processing the request.
	PromptNone Prompt = "none"
	// The Authorization Server SHOULD prompt the End-User for reauthentication.
	PromptLogin Prompt = "login"
	// The Authorization Server SHOULD prompt the End-User for consent before returning
	// information to the Client.
	PromptConsent Prompt = "consent"
	// The Authorization Server SHOULD prompt the End-User to select a user account. This enables
	// an End-User who has multiple accounts at the Authorization Server to select amongst the
	// multiple accounts that they might have current sessions for.
	PromptSelectAccount Prompt = "select_account"
)

// IsValidPrompt whether prompt option is valid
func IsValidPrompt(opt Prompt) bool {
	return opt == PromptNone || opt == PromptLogin ||
		opt == PromptConsent || opt == PromptSelectAccount
}

// Scope OpenID Connect Clients use scope values, as defined in Section 3.3 of OAuth 2.0
// [RFC6749], to specify what access privileges are being requested for Access Tokens. The
// scopes associated with Access Tokens determine what resources will be available when they
// are used to access OAuth 2.0 protected endpoints. Protected Resource endpoints MAY perform
// different actions and return different information based on the scope values and other
// parameters used when requesting the presented Access Token.
// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
type Scope = string

// scope list
const (
	ScopeOpenID Scope = "openid"
	// OPTIONAL. This scope value requests access to the End-User's default profile Claims,
	// which are: name, family_name, given_name, middle_name, nickname, preferred_username,
	// profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
	ScopeProfile Scope = "profile"
	// OPTIONAL. This scope value requests access to the email and email_verified Claims.
	ScopeEmail Scope = "email"
	// OPTIONAL. This scope value requests access to the address Claim.
	ScopeAddress Scope = "address"
	// OPTIONAL. This scope value requests access to the phone_number and phone_number_verified
	// Claims.
	ScopePhone Scope = "phone"
	// This (optional) scope value requests that an OAuth 2.0 Refresh Token be issued that
	// can be used to obtain an Access Token that grants access to the End-User's UserInfo
	// Endpoint even when the End-User is not present (not logged in).
	ScopeOfflineAccess = "offline_access"
)

// SubjectType A Subject Identifier is a locally unique and never reassigned identifier within the
// Issuer for the End-User, which is intended to be consumed by the Client. Two Subject Identifier
// types are defined by this specification
type SubjectType string

// subject list
const (
	// This provides a different sub value to each Client, so as not to enable Clients to correlate
	// the End-User's activities without permission.
	SubjectTypePairwise SubjectType = "pairwise"
	// This provides the same sub (subject) value to all Clients. It is the default if the provider
	// has no subject_types_supported element in its discovery document.
	SubjectTypePublic SubjectType = "public"
)

// ClaimType the Claim Types that the OpenID Provider supports
type ClaimType string

// claim type list
const (
	// Claims that are directly asserted by the OpenID Provider.
	ClaimTypeNormal ClaimType = "normal"
	// Claims that are asserted by a Claims Provider other than the OpenID Provider but are returned
	// by OpenID Provider.
	ClaimTypeAggregated ClaimType = "aggregated"
	// Claims that are asserted by a Claims Provider other than the OpenID Provider but are returned
	// as references by the OpenID Provider.
	ClaimTypeDistributed ClaimType = "distributed"
)
