// Package protocol provides ...
package protocol

// AuthorizeData An Authentication Request is an OAuth 2.0 Authorization Request that requests that
// the End-User be authenticated by the Authorization Server.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthorizeData struct {
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

// AccessData is a request for access tokens
type AccessData struct {
	GrantType GrantType `schema:"grant_type"`

	// authorization_code
	Code         string `schema:"code"`
	RedirectURI  string `schema:"redirect_uri"`
	CodeVerifier string `schema:"code_verifier"`
	// refresh_token
	RefreshToken string `schema:"refresh_token"`
	// client_credentials

	// password

	// urn:ietf:params:oauth:grant-type:jwt-bearer
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	IssuedAt  Time     `json:"iat"`
	ExpiresAt Time     `json:"exp"`
	// urn:ietf:params:oauth:grant-type:token-exchange
	subjectToken       string   `schema:"subject_token"`
	subjectTokenType   string   `schema:"subject_token_type"`
	actorToken         string   `schema:"actor_token"`
	actorTokenType     string   `schema:"actor_token_type"`
	resource           []string `schema:"resource"`
	audience           Audience `schema:"audience"`
	requestedTokenType string   `schema:"requested_token_type"`
	// urn:ietf:params:oauth:grant-type:device_code

	// refresh_token & jwt-bearer & token-exchange
	Scope SpaceDelimitedArr `json:"scope" schema:"scope"`
	// authorization_code & refresh_token
	ClientID            string `schema:"client_id"`
	ClientSecret        string `schema:"client_secret"`
	ClientAssertion     string `schema:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type"`

	Client   Client      `schema:"-"`
	UserData interface{} `schema:"-"`
}

// AccessTokenRequest access token request
type AccessTokenRequest struct {
	Code                string `schema:"code"`
	RedirectURI         string `schema:"redirect_uri"`
	ClientID            string `schema:"client_id"`
	ClientSecret        string `schema:"client_secret"`
	CodeVerifier        string `schema:"code_verifier"`
	ClientAssertion     string `schema:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type"`
}

// RefreshTokenRequest refresh token request
type RefreshTokenRequest struct {
	RefreshToken        string            `schema:"refresh_token"`
	Scope               SpaceDelimitedArr `schema:"scope"`
	ClientID            string            `schema:"client_id"`
	ClientSecret        string            `schema:"client_secret"`
	ClientAssertion     string            `schema:"client_assertion"`
	ClientAssertionType string            `schema:"client_assertion_type"`
}
