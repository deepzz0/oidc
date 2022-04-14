// Package protocol provides ...
package protocol

// AuthorizeRequest An Authentication Request is an OAuth 2.0 Authorization Request that requests that
// the End-User be authenticated by the Authorization Server.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthorizeRequest struct {
	Scope        SpaceDelimitedArr `json:"scope" schema:"scope"`
	ResponseType ResponseType      `json:"response_type" schema:"response_type"`
	ClientID     string            `json:"client_id" schema:"client_id"`
	RedirectURI  string            `json:"redirect_uri" schema:"redirect_uri"`
	State        string            `json:"state" schema:"state"`

	Nonce        string            `json:"nonce" schema:"nonce"`
	ResponseMode ResponseMode      `json:"response_mode" schema:"response_mode"`
	Display      Display           `json:"display" schema:"display"`
	Prompt       SpaceDelimitedArr `json:"prompt" schema:"prompt"`
	MaxAge       int               `json:"max_age" schema:"max_age"`
	UILocales    Locales           `json:"ui_locales" schema:"ui_locales"`
	IDTokenHint  string            `json:"id_token_hint" schema:"id_token_hint"`
	LoginHint    string            `json:"login_hint" schema:"login_hint"`
	ACRValues    []string          `json:"acr_values" schema:"acr_values"`

	CodeChallenge       string              `json:"code_challenge" schema:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method" schema:"code_challenge_method"`

	Request string `schema:"request"`

	UserData map[string]interface{} `schema:"-"`
	Client   Client                 `schema:"-"`
}

// AccessRequest is a request for access tokens
type AccessRequest struct {
}
