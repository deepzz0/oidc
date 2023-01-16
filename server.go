// Package oidc provides ...
package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deepzz0/oidc/protocol"
	"github.com/golang-jwt/jwt/v4"

	"github.com/fatih/structs"
	"github.com/gorilla/schema"
)

// Server OAuth2/OIDC
type Server struct {
	options Options

	decoder *schema.Decoder
	encoder *schema.Encoder
}

// NewServer new OAuth/OIDC server
func NewServer(options ...Option) *Server {
	opts := Options{ // default config
		TokenType:                 TokenTypeBearer,
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
		RedirectURISeparator:      ",",
		ForcePKCEForPublicClients: true,
		SupportedRequestObject:    false,
		RetainTokenAfrerRefresh:   false,
		DefaultScopes:             []protocol.Scope{protocol.ScopeProfile},
	}
	for _, o := range options {
		o(&opts)
	}
	if opts.Storage == nil {
		panic("must specify storage for store data")
	}
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	encoder := schema.NewEncoder()
	return &Server{
		options: opts,
		decoder: decoder,
		encoder: encoder,
	}
}

// HandleAuthorizeRequest authorization endpoint
func (s *Server) HandleAuthorizeRequest(resp *protocol.Response, r *http.Request, issuer string) *protocol.AuthorizeRequest {
	// The authorization server MUST support the use of the HTTP "GET" method [RFC2616] for the authorization
	// endpoint and MAY support the use of the "POST" method as well.
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("Unsupported HTTP Method, should be GET or POST"), "", "")
		return nil
	}
	err := r.ParseForm() // parse form
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err), "", "")
		return nil
	}
	// The query component MUST be retained when adding additional query parameters. The endpoint URI MUST NOT
	// include a fragment component.
	if r.URL.Fragment != "" {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("URI must not include a fragment component"), "", "")
		return nil
	}

	// Decode form params to struct
	req := &protocol.AuthorizeRequest{Iss: issuer}
	err = s.decoder.Decode(req, r.Form)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err), "", "")
		return nil
	}
	// step. query client instance by storage
	cli, err := s.options.Storage.Client(req.ClientID)
	if err != nil {
		if err == protocol.ErrNotFoundEntity {
			resp.SetErrorURI(protocol.ErrUnauthorizedClient.Wrap(err), "", req.State)
		} else {
			resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
		}
		return nil
	}
	// must exist redirect_uri
	if cli.RedirectURI() == "" {
		resp.SetErrorURI(protocol.ErrUnauthorizedClient.Desc("client redirect uri is empty"), "", req.State)
		return nil
	}
	req.Client = cli
	// step. redirect uri, oauth2 is optional, oidc is required
	req.RedirectURI, err = url.QueryUnescape(req.RedirectURI)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequestURI.Wrap(err), "", req.State)
		return nil
	}
	req.RedirectURI, err = ValidateURIList(cli.RedirectURI(), req.RedirectURI, s.options.RedirectURISeparator)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err).
			Desc("The requested redirect_uri is missing in the client configuration or invalid"), "", req.State)
		return nil
	}
	resp.SetRedirectURL(req.RedirectURI)
	if req.ResponseMode != "" {
		resp.ResponseMode = req.ResponseMode
	}
	// step. check resposne type
	typesOK, err := ValidateResponseType(cli, req.ResponseType)
	if err != nil {
		resp.SetErrorURI(protocol.ErrUnsupportedResponseType.Wrap(err), "", req.State)
		return nil
	}
	// step. If the client omits the scope parameter when requesting authorization, the authorization server
	// MUST either process the request using a pre-defined default value or fail the request indicating an
	// invalid scope. The authorization server SHOULD document its scope requirements and default value (if defined).
	// https://www.rfc-editor.org/rfc/rfc6749#section-3.3
	// https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
	req.Scope, req.OpenID, req.OfflineAccess = ValidateScopes(cli, req.Scope, s.options.DefaultScopes,
		typesOK.ResponseTypeCode, req.Prompt)
	if len(req.Scope) == 0 {
		resp.SetErrorURI(protocol.ErrInvalidScope, "", req.State)
		return nil
	}
	if req.OpenID { // oidc
		// check prompt
		req.MaxAge, err = ValidatePrompt(req.Prompt, req.MaxAge)
		if err != nil {
			resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err).Desc(err.Error()), "", req.State)
			return nil
		}
		// step. check request object
		// TODO not implements
		//
		// "token" can't be provided by its own.
		// https://openid.net/specs/openid-connect-core-1_0.html#Authentication
		if typesOK.ResponseTypeToken && !typesOK.ResponseTypeCode && !typesOK.ResponseTypeIDToken {
			resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("response type 'token' must be provided with type 'id_token' and/or 'code'"),
				"", req.State)
			return nil
		}
		// Either "id_token token" or "id_token" has been provided which implies the
		// implicit flow. Implicit flow requires a nonce value.
		// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
		if !typesOK.ResponseTypeCode && req.Nonce == "" {
			resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("Implicit flow requires a nonce value"), "", req.State)
			return nil
		}
		// check display
		if req.Display != "" && !protocol.IsValidDisplay(req.Display) {
			resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("Invalid display option"), "", req.State)
			return nil
		}
		// check id_token_hint
		userID, err := ValidateIDTokenHint(req.IDTokenHint)
		if err != nil {
			resp.SetErrorURI(protocol.ErrLoginRequired.Desc("The id_token_hint is invalid"), "", req.State)
			return nil
		}
		req.UserID = userID
	}
	// step. check code challenge with PKCE
	if typesOK.ResponseTypeCode || typesOK.ResponseTypeDevice { // oauth2 flow
		// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
		if req.CodeChallenge == "" {
			if s.options.ForcePKCEForPublicClients && ValidateClientSecret(cli, "") {
				resp.SetErrorURI(protocol.ErrInvalidRequest.
					Desc("code_challenge (rfc7636) required for public client"), "", req.State)
				return nil
			}
		}
		codeChallMethod, ok := ValidateCodeChallenge(req.CodeChallenge, req.CodeChallengeMethod)
		if !ok && s.options.ForcePKCEForPublicClients {
			// https://tools.ietf.org/html/rfc7636#section-4.4.1
			resp.SetErrorURI(protocol.ErrInvalidRequest.
				Desc("code_challenge (rfc7636) required for public clients"), "", req.State)
			return nil
		}
		req.CodeChallengeMethod = codeChallMethod
	}
	// step. check device flow
	// TODO
	return req
}

// FinishAuthorizeRequest finish authorize request
func (s *Server) FinishAuthorizeRequest(resp *protocol.Response, r *http.Request, req *protocol.AuthorizeRequest) {
	if req.UserID == "" { // check user authorized
		resp.SetErrorURI(protocol.ErrLoginRequired, "", req.State)
		return
	}
	isContains := func(arr []string, rt protocol.ResponseType) bool {
		for _, v := range arr {
			if v == string(rt) {
				return true
			}
		}
		return false
	}
	// none in response type
	if isContains(req.ResponseType, protocol.ResponseTypeNone) {
		if req.State != "" {
			resp.Output["state"] = req.State
		}
		return
	}
	// code in response_type
	if isContains(req.ResponseType, protocol.ResponseTypeCode) {
		// AuthorizeData
		ret := &protocol.AuthorizeData{AuthorizeRequest: req}

		// generate & save code
		code, err := s.GenerateAuthorizeCodeAndSave(ret)
		if err != nil {
			resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", ret.State)
			return
		}

		// redirect with code
		resp.Output["code"] = code
		resp.Output["state"] = req.State
	}
	// token in response_type, should be front of id_token
	if isContains(req.ResponseType, protocol.ResponseTypeToken) {
		// The implicit grant type does not include client authentication, and relies on the presence of the
		// resource owner and the registration of the redirection URI.
		// The redirection URI includes the access token in the URI fragment.
		// see https://www.rfc-editor.org/rfc/rfc6749#section-4.2
		resp.SetResponseMode(protocol.ResponseModeFragment)
		// generate & save token
		accessReq := &protocol.AccessRequest{
			GrantType:   protocol.GrantTypeImplicit,
			Scope:       req.Scope,
			RedirectURI: req.RedirectURI,

			UserID:          req.UserID,
			Client:          req.Client,
			GenerateRefresh: false, // do not return refresh_token
		}
		s.FinishTokenRequest(resp, r, accessReq)
		if req.State != "" && resp.ErrCode == nil {
			resp.Output["state"] = req.State
		}
	}
	// id_token in response_type
	if isContains(req.ResponseType, protocol.ResponseTypeIDToken) {
		// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
		resp.SetResponseMode(protocol.ResponseModeFragment)

		userData, err := s.options.Storage.UserDataScopes(req.UserID, req.Scope)
		if err != nil {
			resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
			return
		}
		claims := s.rebuildIDToken(req.Client, req, userData, req.Iss)
		// check at_hash, https://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
		if at, ok := resp.Output["access_token"]; ok {
			hash := sha256.Sum256([]byte(at.(string)))
			claims.ATHash = base64.URLEncoding.EncodeToString(hash[:])
		}
		// user data must be id_token data
		idToken, err := signPayload(req.Client, claims)
		if err != nil {
			resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
			return
		}
		resp.Output["id_token"] = idToken
		resp.Output["state"] = req.State
	}
}

// HandleTokenRequest token endpoint
func (s *Server) HandleTokenRequest(resp *protocol.Response, r *http.Request, issuer string) *protocol.AccessRequest {
	// The client MUST use the HTTP "POST" method when making access token requests.
	// see https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2
	if r.Method != http.MethodPost {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("Unsupported HTTP Method, should be POST"), "", "")
		return nil
	}
	err := r.ParseForm() // parse form
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err), "", "")
		return nil
	}
	// The query component MUST be retained when adding additional query parameters. The endpoint URI MUST NOT
	// include a fragment component.
	if r.URL.Fragment != "" {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("URI must not include a fragment component"), "", "")
		return nil
	}

	req := &protocol.AccessRequest{Iss: issuer}
	err = s.decoder.Decode(req, r.Form)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err).Desc("error decoding form"), "", "")
		return nil
	}
	// The client uses an extension grant type by specifying the grant type using an absolute URI (defined by
	// the authorization server) as the value of the "grant_type" parameter of the token endpoint, and by adding
	// any additional parameters necessary.
	// https://www.rfc-editor.org/rfc/rfc6749#section-4.5
	if !protocol.IsExtensionGrants(req.GrantType) {
		// client authentication
		auth := s.getClientAuth(r, s.options.AllowClientSecretInParams)
		if auth == nil {
			resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("check auth error"), "", "")
			return nil
		}
		if req.ClientID == "" { // client_id from auth
			req.ClientID = auth.Username
		}
		// must have a valid client
		cli, err := s.getClient(auth, resp)
		if err != nil {
			resp.SetErrorURI(protocol.ErrUnauthorizedClient.Wrap(err), "", "")
			return nil
		}
		req.Client = cli
	}
	// validate grant type
	if !ValidateGrantType(req.Client.GrantTypes(), req.GrantType) {
		resp.SetErrorURI(protocol.ErrUnsupportedGrantType.Desc("unsupported grant type: "+string(req.GrantType)), "", "")
		return nil
	}
	var grantType = protocol.GrantType(r.FormValue("grant_type"))
	switch grantType {
	case protocol.GrantTypeAuthorizationCode:
		err = s.handleAuthorizationCodeRequest(resp, r, req)
	case protocol.GrantTypeRefreshToken:
		err = s.handleRefreshTokenRequest(resp, r, req)
	case protocol.GrantTypePassword:
		err = s.handlePasswordRequest(resp, r, req)
	case protocol.GrantTypeClientCredentials:
		err = s.handleCredentialsRequest(resp, r, req)
	case protocol.GrantTypeJwtBearer:
		// TODO
		fallthrough
	case protocol.GrantTypeTokenExchange:
		// TODO
		fallthrough
	case protocol.GrantTypeDeviceCode:
		// TODO
		fallthrough
	default:
		err = protocol.ErrUnsupportedGrantType.Desc("unknown grant type or not implements")
	}
	if err != nil {
		resp.SetErrorURI(err.(protocol.Error), "", "")
		return nil
	}
	return req
}

// FinishTokenRequest token request finish
func (s *Server) FinishTokenRequest(resp *protocol.Response, r *http.Request, req *protocol.AccessRequest) {
	var (
		ui  *protocol.UserInfo
		err error
	)
	if req.GrantType != protocol.GrantTypeClientCredentials {
		if req.UserID == "" {
			resp.SetErrorURI(protocol.ErrAccessDenied, "", "")
			return
		}
		ui, err = s.options.Storage.UserDataScopes(req.UserID, req.Scope)
		if err != nil {
			resp.SetErrorURI(protocol.ErrAccessDenied.Wrap(err), "", "")
			return
		}
		// oidc must return subject
		if ui.Subject == "" {
			ui.Subject = req.UserID
		}
	}
	ret := &protocol.AccessData{
		AccessRequest: req,

		UserData: ui,
		Scope:    req.Scope,

		Client: req.Client,
	}
	ret.AccessToken, ret.RefreshToken, err = s.GenerateAccessTokenAndSave(ret, req.GenerateRefresh)
	if err != nil {
		resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", "")
		return
	}
	// remove authorization token
	if req.Code != "" {
		s.options.Storage.RemoveAuthorize(req.Code)
	}
	// remove previous access token
	if req.AccessData != nil && !s.options.RetainTokenAfrerRefresh {
		if req.AccessData.RefreshToken != "" {
			s.options.Storage.RemoveRefresh(req.AccessData.RefreshToken)
		}
		s.options.Storage.RemoveAccess(req.AccessData.AccessToken)
	}
	// output data
	resp.Output["access_token"] = ret.AccessToken
	resp.Output["token_type"] = s.options.TokenType
	resp.Output["expires_in"] = req.Client.ExpirationOptions().AccessTokenExpiration
	if ret.RefreshToken != "" {
		resp.Output["refresh_token"] = ret.RefreshToken
	}
	if len(ret.Scope) > 0 {
		resp.Output["scope"] = ret.Scope.Encode()
	}
	// Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request
	// (so that an ID Token will be returned from the Token Endpoint). must be authorization_code
	if ad := req.AuthorizeData; ad != nil && ad.OpenID {
		// UserData must be id_token data
		claims := s.rebuildIDToken(req.Client, ad.AuthorizeRequest, ret.UserData, req.Issuer)

		idToken, err := signPayload(req.Client, claims)
		if err != nil {
			resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", "")
			return
		}
		resp.Output["id_token"] = idToken
	}
}

// HandleUserInfoRequest userinfo endpoint, should support CORS
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
func (s *Server) HandleUserInfoRequest(resp *protocol.Response, r *http.Request, issuer string) *protocol.UserInfoRequest {
	// The Client sends the UserInfo Request using either HTTP GET or HTTP POST. The Access Token obtained from an
	// OpenID Connect Authentication Request MUST be sent as a Bearer Token, per Section 2 of OAuth 2.0 Bearer Token
	// Usage [RFC6750].
	// It is RECOMMENDED that the request use the HTTP GET method and the Access Token be sent using the Authorization
	// header field.
	// see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("Unsupported HTTP Method, should be GET or POST"), "", "")
		return nil
	}
	err := r.ParseForm() // parse form
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err), "", "")
		return nil
	}
	token := s.getBearerAuth(r)
	if token == "" {
		resp.SetErrorURI(protocol.ErrInvalidToken, "", "")
		return nil
	}

	req := &protocol.UserInfoRequest{
		Token: token,

		Iss: issuer,
	}
	req.AccessData, err = s.options.Storage.LoadAccess(req.Token)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidToken.Wrap(err), "", "")
		return nil
	}
	return req
}

// FinishUserInfoRequest userinfo request finish
// The sub (subject) Claim MUST always be returned in the UserInfo Response.
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (s *Server) FinishUserInfoRequest(resp *protocol.Response, r *http.Request, req *protocol.UserInfoRequest) {
	resp.Output = structs.Map(req.AccessData.UserData)
}

// HandleRevocationRequest revocation endpoint, Implementations MUST support the revocation of refresh tokens and
// SHOULD support the revocation of access tokens (see Implementation Note).
func (s *Server) HandleRevocationRequest(resp *protocol.Response, r *http.Request, issuer string) *protocol.RevocationRequest {
	// The client requests the revocation of a particular token by making an HTTP POST request to the token
	// revocation endpoint URL.
	// https://www.rfc-editor.org/rfc/rfc7009
	if r.Method != http.MethodPost {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("Unsupported HTTP Method, should be POST"), "", "")
		return nil
	}
	err := r.ParseForm() // parse form
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err), "", "")
		return nil
	}

	req := &protocol.RevocationRequest{Iss: issuer}
	err = s.decoder.Decode(req, r.Form)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err).Desc("error decoding form"), "", "")
		return nil
	}
	if req.Token == "" {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err).Desc("token is required"), "", "")
		return nil
	}
	if !ValidateTokenHint(req.TokenTypeHint) {
		resp.SetErrorURI(protocol.ErrUnsupportedTokenType.Wrap(err), "", "")
		return nil
	}
	// client authentication
	auth := s.getClientAuth(r, s.options.AllowClientSecretInParams)
	if auth == nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("check auth error"), "", "")
		return nil
	}
	// must have a valid client
	cli, err := s.getClient(auth, resp)
	if err != nil {
		resp.SetErrorURI(protocol.ErrUnauthorizedClient.Wrap(err), "", "")
		return nil
	}
	req.Client = cli

	return req
}

// FinishRevocationRequest revocation request finish
func (s *Server) FinishRevocationRequest(resp *protocol.Response, r *http.Request, req *protocol.RevocationRequest) {
	// The authorization server responds with HTTP status code 200 if the token has been revoked successfully
	// or if the client submitted an invalid token.
	switch req.TokenTypeHint {
	case protocol.TokenTypeHintAccessToken: // and revoke refresh_token
		ad, _ := s.options.Storage.LoadAccess(req.Token)
		if ad != nil {
			_ = s.options.Storage.RemoveAccess(req.Token)
			_ = s.options.Storage.RemoveRefresh(ad.RefreshToken)
		}
	case protocol.TokenTypeHintRefreshToken: // and revoke access_token
		ad, _ := s.options.Storage.LoadRefresh(req.Token)
		if ad != nil {
			_ = s.options.Storage.RemoveAccess(req.Token)
			_ = s.options.Storage.RemoveRefresh(ad.RefreshToken)
		}
	}
	// An invalid token type hint value is ignored by the authorization server and does not influence the
	// revocation response.
}

// HandleCheckSessionEndpoint check_session endpoint
// https://technospace.medium.com/managing-sessions-with-openid-connect-d3b6fb4f552b
func (s *Server) HandleCheckSessionEndpoint(resp *protocol.Response, r *http.Request, issuer string) *protocol.CheckSessionRequest {
	if s.options.Session == nil {
		resp.SetErrorURI(protocol.ErrServerError.Desc("The op dose not support session endpoint"), "", "")
		return nil
	}
	// check referer host
	req := &protocol.CheckSessionRequest{Iss: issuer}
	err := s.decoder.Decode(req, r.Form)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err).Desc("error decoding form"), "", "")
		return nil
	}
	origin, err := ValidateURI(s.options.Session.AllowedOrigin(), r.Header.Get("Referer"))
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("failed to validate Referer"), "", "")
		return nil
	}
	req.Origin = origin
	// check log state
	cookie := r.Header.Get("Cookie")
	req.ExpiresIn = s.options.Session.SessionExpiresIn(cookie)
	return req
}

// FinishCheckSessionRequest check_session_iframe request finish
func (s *Server) FinishCheckSessionRequest(resp *protocol.Response, w http.ResponseWriter, req *protocol.CheckSessionRequest) {
	resp.Output["origin"] = req.Origin

	u, _ := url.Parse(req.Iss)
	sid := &http.Cookie{
		Name:  "sid",
		Value: fmt.Sprint(req.ExpiresIn > 0), // true / false

		Domain: u.Host,
		Path:   "/",

		MaxAge: req.ExpiresIn,
		Secure: true,
	}
	if sid.MaxAge > 0 {
		sid.Expires = time.Now().Add(time.Duration(sid.MaxAge) * time.Second)
	}
	http.SetCookie(w, sid)
	err := protocol.CheckSessionIframe.Execute(w, resp.Output)
	if err != nil {
		resp.SetErrorURI(protocol.ErrServerError.Desc("failed to render template, please contact admin"), "", "")
		return
	}
}

// HandleEndSessionEndpoint end_session endpoint
func (s *Server) HandleEndSessionEndpoint(resp *protocol.Response, r *http.Request, issuer string) *protocol.EndSessionRequest {

	return nil
}

// FinishEndSessionRequest end_session request finish
func (s *Server) FinishEndSessionRequest(resp *protocol.Response, r *http.Request, req *protocol.EndSessionRequest) {

}

// HandleIntrospectionEndpoint https://www.rfc-editor.org/rfc/rfc7662
// FinishIntrospectionRequest

func (s *Server) getClient(auth *BasicAuth, resp *protocol.Response) (protocol.Client, error) {
	cli, err := s.options.Storage.Client(auth.Username)
	if err == protocol.ErrNotFoundEntity {
		return nil, protocol.ErrUnauthorizedClient.Wrap(err).Desc("not found")
	}
	if err != nil {
		return nil, protocol.ErrServerError.Wrap(err).Desc("error finding client")
	}
	if !ValidateClientSecret(cli, auth.Password) {
		return nil, protocol.ErrUnauthorizedClient.Desc("client check failed: " + auth.Username)
	}
	if cli.RedirectURI() == "" {
		return nil, protocol.ErrUnauthorizedClient.Desc("client redirect uri is empty")
	}
	return cli, nil
}

// Including the client credentials in the request-body using the two parameters is NOT RECOMMENDED and SHOULD be
// limited to clients unable to directly utilize the HTTP Basic authentication scheme (or other password-based
// HTTP authentication schemes).  The parameters can only be transmitted in the request-body and MUST NOT be
// included in the request URI.
func (s *Server) getClientAuth(r *http.Request, inParams bool) *BasicAuth {
	if inParams {
		// Allow for auth without password
		if _, ok := r.Form["client_secret"]; ok {
			auth := &BasicAuth{
				Username: r.FormValue("client_id"),
				Password: r.FormValue("client_secret"),
			}
			if auth.Username != "" {
				return auth
			}
		}
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		return nil
	}
	return &BasicAuth{username, password}
}

// https://www.rfc-editor.org/rfc/rfc6750
func (s *Server) getBearerAuth(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	token := r.FormValue("access_token")
	if auth == "" && token == "" {
		return ""
	}

	if auth != "" {
		sli := strings.SplitN(auth, " ", 2)
		if len(sli) == 2 {
			if sli[0] != string(s.options.TokenType) {
				return ""
			}
			token = sli[1]
		}
	}
	return token
}

var testHookTimeNow = func() time.Time { return time.Now() }

func (s *Server) rebuildIDToken(cli protocol.Client, req *protocol.AuthorizeRequest,
	ui *protocol.UserInfo, issuer string) *protocol.IDToken {

	now := testHookTimeNow()
	exps := cli.ExpirationOptions()
	idToken := &protocol.IDToken{
		Issuer:     issuer,
		Subject:    ui.Subject,
		Audience:   jwt.ClaimStrings{cli.ClientID()},
		Expiration: jwt.NewNumericDate(now.Add(time.Second * time.Duration(exps.IDTokenExpiration))),
		IssuedAt:   jwt.NewNumericDate(now),
		Nonce:      req.Nonce,
	}
	if req.MaxAge > 0 {
		idToken.AuthTime = jwt.NewNumericDate(now.Add(time.Second * time.Duration(req.MaxAge)))
	}
	return idToken
}

func signPayload(cli protocol.Client, claims jwt.Claims) (string, error) {
	var key interface{}

	alg := cli.JWTSigningMethod()
	switch alg {
	case jwt.SigningMethodHS256:
		key = []byte(cli.ClientSecret())
	case jwt.SigningMethodRS256,
		jwt.SigningMethodES256:
		var err error
		key, err = cli.PrivateKey()
		if err != nil {
			return "", err
		}
	}
	jwtToken := jwt.NewWithClaims(alg, claims)
	return jwtToken.SignedString(key)
}
