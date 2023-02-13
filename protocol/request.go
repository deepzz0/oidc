// Package protocol provides ...
package protocol

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// AuthorizeRequest An Authentication Request is an OAuth 2.0 Authorization Request that requests that
// the End-User be authenticated by the Authorization Server.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthorizeRequest struct {
	// required & recommended
	ResponseType SpaceDelimitedArr `schema:"response_type" json:"response_type"`
	ClientID     string            `schema:"client_id" json:"client_id"`
	RedirectURI  string            `schema:"redirect_uri" json:"redirect_uri"`
	State        string            `schema:"state" json:"state"`
	Scope        SpaceDelimitedArr `schema:"scope" json:"scope"`
	// openid optional
	Nonce        string            `schema:"nonce" json:"nonce,omitempty"`
	ResponseMode ResponseMode      `schema:"response_mode" json:"response_mode,omitempty"`
	Display      Display           `schema:"display" json:"display,omitempty"`
	Prompt       SpaceDelimitedArr `schema:"prompt" json:"prompt,omitempty"`
	MaxAge       int               `schema:"max_age" json:"max_age,omitempty"`
	UILocales    Locales           `schema:"ui_locales" json:"ui_locales,omitempty"`
	IDTokenHint  string            `schema:"id_token_hint" json:"id_token_hint,omitempty"`
	LoginHint    string            `schema:"login_hint" json:"login_hint,omitempty"`
	ACRValues    []string          `schema:"acr_values" json:"acr_values,omitempty"`
	// code challenge
	CodeChallenge       string              `schema:"code_challenge" json:"code_challenge,omitempty"`
	CodeChallengeMethod CodeChallengeMethod `schema:"code_challenge_method" json:"code_challenge_method,omitempty"`
	// request object
	Request string `schema:"request" json:"request,omitempty"`

	Issuer        string `schema:"-" json:"-"` // dynamic issuer
	Client        Client `schema:"-" json:"-"`
	UserID        string `schema:"-" json:"user_id,omitempty"` // logined userID
	OpenID        bool   `schema:"-" json:"open_id,omitempty"`
	OfflineAccess bool   `schema:"-" json:"offline_access,omitempty"`
}

// AuthorizeData authorize data
type AuthorizeData struct {
	*AuthorizeRequest

	ExpiresIn int       `json:"expires_in"`
	CreatedAt time.Time `json:"created_at"`
}

// GrantAuthorizationCodeRequest authorization_code
type GrantAuthorizationCodeRequest struct {
	Code         string `schema:"code" json:"code"`
	RedirectURI  string `schema:"redirect_uri" json:"redirect_uri"`
	CodeVerifier string `schema:"code_verifier" json:"code_verifier"` // PKCE
	ClientID     string `schema:"client_id" json:"client_id"`
	// Extension grants
	ClientAssertion     string `schema:"client_assertion" json:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type" json:"client_assertion_type"`
}

// GrantRefreshTokenRequest refresh_token
type GrantRefreshTokenRequest struct {
	RefreshToken string            `schema:"refresh_token" json:"refresh_token"`
	Scope        SpaceDelimitedArr `schema:"scope" json:"scope"`
	// Extension grants
	ClientAssertion     string `schema:"client_assertion" json:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type" json:"client_assertion_type"`
}

// GrantClientCredentialsRequest client_credentials
type GrantClientCredentialsRequest struct {
	Scope SpaceDelimitedArr `schema:"scope" json:"scope"`
}

// GrantPasswordRequest passowrd
type GrantPasswordRequest struct {
	Username string            `schema:"username" json:"username"`
	Password string            `schema:"password" json:"password"`
	Scope    SpaceDelimitedArr `schema:"scope" json:"scope"`
}

// GrantImplicitRequest implicit
type GrantImplicitRequest struct {
	RedirectURI string            `json:"redirect_uri"`
	Scope       SpaceDelimitedArr `json:"scope"`
}

// GrantJwtBearerRequest urn:ietf:params:oauth:grant-type:jwt-bearer
type GrantJwtBearerRequest struct {
	ClientID  string            `schema:"client_id" json:"client_id"`
	Assertion string            `schema:"assertion" json:"assertion"`
	Scope     SpaceDelimitedArr `schema:"scope" json:"scope"`
}

// GrantTokenExchangeRequest urn:ietf:params:oauth:grant-type:token-exchange
type GrantTokenExchangeRequest struct {
	SubjectToken       string            `schema:"subject_token" json:"subject_token"`
	SubjectTokenType   string            `schema:"subject_token_type" json:"subject_token_type"`
	ActorToken         string            `schema:"actor_token" json:"actor_token,omitempty"`
	ActorTokenType     string            `schema:"actor_token_type" json:"actor_token_type,omitempty"`
	Resource           []string          `schema:"resource" json:"resource,omitempty"` // required if actor_token present
	Audience           jwt.ClaimStrings  `schema:"audience" json:"audience,omitempty"`
	RequestedTokenType string            `schema:"requested_token_type" json:"requested_token_type,omitempty"`
	Scope              SpaceDelimitedArr `schema:"scope" json:"scope,omitempty"`
}

// GrantDeviceCodeRequest urn:ietf:params:oauth:grant-type:device_code
type GrantDeviceCodeRequest struct {
	ClientID string            `schema:"client_id" json:"client_id"`
	Scope    SpaceDelimitedArr `schema:"scope" json:"scope,omitempty"`
}

// GrantSaml2BearerRequest urn:ietf:params:oauth:grant-type:saml2-bearer
type GrantSaml2BearerRequest struct {
	ClientID  string            `schema:"client_id" json:"client_id"`
	Assertion string            `schema:"assertion" json:"assertion"`
	Scope     SpaceDelimitedArr `schema:"scope" json:"scope"`
}

// AccessRequest is a request for access tokens
type AccessRequest struct {
	GrantType GrantType `json:"grant_type"`

	// authorization_code
	AuthorizationCodeReq *GrantAuthorizationCodeRequest `json:"authorization_code_req,omitempty"`
	// refresh_token
	RefreshTokenReq *GrantRefreshTokenRequest `json:"refresh_token_req,omitempty"`
	// client_credentials nothing todo
	ClientCredentialsReq *GrantClientCredentialsRequest `json:"client_credentials_req,omitempty"`
	// password
	PasswordReq *GrantPasswordRequest `json:"password_req,omitempty"`
	// implicit
	ImplicitReq *GrantImplicitRequest `json:"implicit_req,omitempty"`
	// urn:ietf:params:oauth:grant-type:jwt-bearer
	JwtBearerReq *GrantJwtBearerRequest `json:"jwt_bearer_req,omitempty"`
	// urn:ietf:params:oauth:grant-type:token-exchange
	TokenExchangeReq *GrantTokenExchangeRequest `json:"token_exchange_req,omitempty"`
	// urn:ietf:params:oauth:grant-type:device_code
	DeviceCodeReq *GrantDeviceCodeRequest `json:"device_code_req,omitempty"`
	// urn:ietf:params:oauth:grant-type:saml2-bearer
	Saml2BearerReq *GrantSaml2BearerRequest `json:"saml2_bearer_req,omitempty"`

	Issuer          string         `json:"-" schema:"-"` // dynamic issuer
	Client          Client         `json:"-" schema:"-"` // client
	GenerateRefresh bool           `json:"-" schema:"-"` // should generate refresh_token
	AccessData      *AccessData    `json:"-" schema:"-"` // previous access data
	UserID          string         `json:"user_id" schema:"-"`
	AuthorizeData   *AuthorizeData `json:"authorize_data,omitempty" schema:"-"`
}

// AccessData access data
type AccessData struct {
	*AccessRequest
	// final authorization result
	UserData  *UserInfo         `json:"user_data"`
	Scope     SpaceDelimitedArr `json:"scope"`
	CreatedAt time.Time         `json:"created_at"`

	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`

	Client Client `json:"-"`
}

// UserInfoRequest userinfo request
type UserInfoRequest struct {
	Token string `schema:"-"`

	Issuer     string      `schema:"-"` // dynamic issuer
	Subject    string      `schema:"-"`
	AccessData *AccessData `schema:"-"`
}

// RevocationRequest revocation endpoint
type RevocationRequest struct {
	Token         string        `schema:"token"` // access_token or refresh_token
	TokenTypeHint TokenTypeHint `schema:"token_type_hint"`

	Issuer string `schema:"-"` // dynamic issuer
	Client Client `schema:"-"`
}

// CheckSessionRequest check_session_iframe endpoint
type CheckSessionRequest struct {
	ClientID string `schema:"client_id"`

	Issuer    string `schema:"-"` // dynamic issuer
	Origin    string `schema:"-"`
	ExpiresIn int    `schema:"-"`
}

// EndSessionRequest end_session endpoint
type EndSessionRequest struct {
	IDTokenHint           string `schema:"id_token_hint"`
	ClientID              string `schema:"client_id"`
	PostLogoutRedirectURI string `schema:"post_logout_redirect_uri"`
	State                 string `schema:"state"`

	Issuer string `schema:"-"` // dynamic issuer
}
