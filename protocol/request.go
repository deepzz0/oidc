// Package protocol provides ...
package protocol

import "time"

// AuthorizeRequest An Authentication Request is an OAuth 2.0 Authorization Request that requests that
// the End-User be authenticated by the Authorization Server.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthorizeRequest struct {
	// required & recommended
	ResponseType ResponseType      `json:"response_type" schema:"response_type"`
	ClientID     string            `json:"client_id" schema:"client_id"`
	RedirectURI  string            `json:"redirect_uri" schema:"redirect_uri"`
	State        string            `json:"state" schema:"state"`
	Scope        SpaceDelimitedArr `json:"scope" schema:"scope"`
	// openid optional
	Nonce        string            `json:"nonce,omitempty" schema:"nonce"`
	ResponseMode ResponseMode      `json:"response_mode,omitempty" schema:"response_mode"`
	Display      Display           `json:"display,omitempty" schema:"display"`
	Prompt       SpaceDelimitedArr `json:"prompt,omitempty" schema:"prompt"`
	MaxAge       int               `json:"max_age,omitempty" schema:"max_age"`
	UILocales    Locales           `json:"ui_locales,omitempty" schema:"ui_locales"`
	IDTokenHint  string            `json:"id_token_hint,omitempty" schema:"id_token_hint"`
	LoginHint    string            `json:"login_hint,omitempty" schema:"login_hint"`
	ACRValues    []string          `json:"acr_values,omitempty" schema:"acr_values"`
	// code challenge
	CodeChallenge       string              `json:"code_challenge,omitempty" schema:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method,omitempty" schema:"code_challenge_method"`
	// request object TODO
	Request string `json:"request,omitempty" schema:"request"`

	UserID string `json:"user_id,omitempty" schema:"-"` // logined userID
	Client Client `json:"-" schema:"-"`
}

// AuthorizeData authorize data
type AuthorizeData struct {
	*AuthorizeRequest

	ExpiresIn int       `json:"expires_in" schema:"-"`
	CreatedAt time.Time `json:"created_at" schema:"-"`
}

// AccessRequest is a request for access tokens
type AccessRequest struct {
	GrantType GrantType `json:"grant_type" schema:"grant_type"`

	// authorization_code
	Code         string `json:"code,omitempty" schema:"code"`
	RedirectURI  string `json:"redirect_uri,omitempty" schema:"redirect_uri"`
	CodeVerifier string `json:"code_verifier,omitempty" schema:"code_verifier"`
	// refresh_token
	RefreshToken string `json:"refresh_token,omitempty" schema:"refresh_token"`
	// client_credentials nothing todo
	// password
	Username string `json:"username,omitempty" schema:"username"`
	Password string `json:"password,omitempty" schema:"password"`

	// urn:ietf:params:oauth:grant-type:jwt-bearer
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  Audience `json:"aud,omitempty"`
	IssuedAt  Time     `json:"iat,omitempty"`
	ExpiresAt Time     `json:"exp,omitempty"`
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
	// client_credentials & password
	Scope SpaceDelimitedArr `json:"scope,omitempty" schema:"scope"`
	// authorization_code & refresh_token
	ClientID            string `json:"client_id" schema:"client_id"`
	ClientSecret        string `json:"-" schema:"client_secret"`
	ClientAssertion     string `json:"client_assertion,omitempty" schema:"client_assertion"`
	ClientAssertionType string `json:"client_assertion_type,omitempty" schema:"client_assertion_type"`

	AccessData      *AccessData `json:"-" schema:"-"` // previous access data
	UserID          string      `json:"user_id" schema:"-"`
	Client          Client      `json:"-" schema:"-"`
	GenerateRefresh bool        `json:"-" schema:"-"`
}

// AccessData access data
type AccessData struct {
	*AccessRequest

	UserData  interface{}       `json:"user_data"`
	CreatedAt time.Time         `json:"created_at"`
	Scope     SpaceDelimitedArr `json:"scope"`

	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`

	Client Client `json:"-"`
}
