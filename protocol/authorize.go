// Package protocol provides ...
package protocol

// ResponseType authorization endpoint is used by the authorization code grant type and implicit grant type flows
// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
type ResponseType string

// Response type list
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
)

// IsSupportedResponseTypes check response type
func IsSupportedResponseTypes(types []ResponseType, ty ResponseType) bool {
	for _, v := range types {
		if v == ty {
			return true
		}
	}
	return false
}

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
	ResponseModeQuery    ResponseMode = "query"
	ResponseModeFragment ResponseMode = "fragment"
	ResponseModeFormPost ResponseMode = "form_post"
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

// Scope OpenID Connect Clients use scope values, as defined in Section 3.3 of OAuth 2.0
// [RFC6749], to specify what access privileges are being requested for Access Tokens. The
// scopes associated with Access Tokens determine what resources will be available when they
// are used to access OAuth 2.0 protected endpoints. Protected Resource endpoints MAY perform
// different actions and return different information based on the scope values and other
// parameters used when requesting the presented Access Token.
// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
type Scope string

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
