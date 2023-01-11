// Package oidc provides ...
package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/deepzz0/oidc/protocol"

	"github.com/gorilla/schema"
	"gopkg.in/square/go-jose.v2"
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
		ForcePKCEForPublicClients: false,
		SupportedRequestObject:    false,
		RetainTokenAfrerRefresh:   false,
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

// HandleAuthorizeRequest authorization request handler
func (s *Server) HandleAuthorizeRequest(resp *protocol.Response, r *http.Request) *protocol.AuthorizeRequest {
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
	req := new(protocol.AuthorizeRequest)
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
	// step. check request object
	// TODO not implements
	//
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
	var openIDScope bool
	req.Scope, openIDScope = ValidateScopes(cli, req.Scope, s.options.DefaultScopes)
	if len(req.Scope) == 0 {
		resp.SetErrorURI(protocol.ErrInvalidScope, "", "")
		return nil
	}
	if openIDScope { // oidc
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
		// check id_token_hint
		userID, err := ValidateIDTokenHint(req.IDTokenHint)
		if err != nil {
			resp.SetErrorURI(protocol.ErrLoginRequired.Desc("The id_token_hint is invalid"), "", req.State)
			return nil
		}
		fmt.Println(userID)
	}
	// step. check code challenge
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
		resp.SetErrorURI(protocol.ErrAccessDenied, "", req.State)
		return
	}
	// support hybrid
	for _, v := range strings.Fields(string(req.ResponseType)) {
		ty := protocol.ResponseType(v)
		switch ty {
		case protocol.ResponseTypeCode:
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
		case protocol.ResponseTypeToken:
			resp.SetResponseMode(protocol.ResponseModeFragment)
			// generate & save token
			accessReq := &protocol.AccessRequest{
				GrantType:   protocol.GrantTypeImplicit,
				Scope:       req.Scope,
				RedirectURI: req.RedirectURI,

				UserID:          req.UserID,
				Client:          req.Client,
				GenerateRefresh: false,
			}
			s.FinishTokenRequest(resp, r, accessReq)
			if req.State != "" && resp.ErrCode == nil {
				resp.Output["state"] = req.State
			}
		case protocol.ResponseTypeIDToken:
			resp.SetResponseMode(protocol.ResponseModeFragment)

			key, err := req.Client.PrivateKey()
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
				return
			}
			userData, err := s.options.Storage.UserDataScopes(req.UserID, req.Scope)
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
				return
			}
			// user data must be id_token data
			idToken, err := signPayload(key, userData)
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
				return
			}
			resp.Output["id_token"] = idToken
			resp.Output["state"] = req.State
		}
	}
}

// HandleTokenRequest token request handler
func (s *Server) HandleTokenRequest(resp *protocol.Response, r *http.Request) *protocol.AccessRequest {
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

	req := &protocol.AccessRequest{}
	err = s.decoder.Decode(req, r.Form)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Wrap(err).Desc("error decoding form"), "", "")
		return nil
	}
	// client authentication
	auth := s.getClientAuth(r, s.options.AllowClientSecretInParams)
	if auth == nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("check auth error"), "", "")
		return nil
	}
	if req.ClientID == "" {
		req.ClientID = auth.Username
	}
	// must have a valid client
	cli, err := s.getClient(auth, resp)
	if err != nil {
		resp.SetErrorURI(protocol.ErrUnauthorizedClient.Wrap(err), "", "")
		return nil
	}
	req.Client = cli
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
	case protocol.GrantTypeImplicit:
		// nothing todo
	case protocol.GrantTypeJwtBearer:

	case protocol.GrantTypeTokenExchange:

	case protocol.GrantTypeDeviceCode:

	default:
		err = protocol.ErrUnsupportedGrantType.Desc("unknown grant type")
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
		ui  interface{}
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
	for _, s := range ret.Scope {
		if s == protocol.ScopeOpenID {
			key, err := req.Client.PrivateKey()
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", "")
				return
			}
			// UserData must be id_token data
			idToken, err := signPayload(key, ret.UserData)
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError, "", "")
				return
			}
			resp.Output["id_token"] = idToken
			break
		}
	}
}

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

func signPayload(key crypto.Signer, idToken interface{}) (string, error) {
	algo, err := signatureAlgorithm(key)
	if err != nil {
		return "", err
	}

	// jwt signer
	sk := jose.SigningKey{Algorithm: algo, Key: key}
	signer, err := jose.NewSigner(sk, &jose.SignerOptions{})
	if err != nil {
		panic(err)
	}
	// payload
	payload, err := json.Marshal(idToken)
	if err != nil {
		return "", err
	}
	// sign
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// Determine the signature algorithm for a JWT.
func signatureAlgorithm(signer crypto.Signer) (jose.SignatureAlgorithm, error) {
	if signer == nil {
		return "", errors.New("no signing key")
	}
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		// Because OIDC mandates that we support RS256, we always return that
		// value. In the future, we might want to make this configurable on a
		// per client basis. For example allowing PS256 or ECDSA variants.
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		// We don't actually support ECDSA keys yet, but they're tested for
		// in case we want to in the future.
		//
		// These values are prescribed depending on the ECDSA key type. We
		// can't return different values.
		switch key.Params() {
		case elliptic.P256().Params():
			return jose.ES256, nil
		case elliptic.P384().Params():
			return jose.ES384, nil
		default:
			return "", errors.New("unsupported ecdsa curve")
		}
	default:
		return "", fmt.Errorf("unsupported signing key type %T", key)
	}
}
