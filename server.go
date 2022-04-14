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
	opts := Options{
		TokenType:                 "Bearer",
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
		RedirectURISeparator:      ",",
		ForcePKCEForPublicClients: false,
		SupportedRequestObject:    false,

		AuthorizeCodeGen: DefaultAuthorizeCodeGenerator,
		AccessTokenGen:   DefaultAccessTokenGenerator,
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
	r.ParseForm()

	// check method: must be GET or POST
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		resp.SetErrorURI(protocol.ErrInvalidRequest.Desc("Unsupported HTTP Method, should be GET or POST"), "", "")
		return nil
	}

	// decode form params to struct
	req := new(protocol.AuthorizeRequest)
	err := s.decoder.Decode(req, r.Form)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest, "", "")
		return nil
	}
	// query client
	cli, err := s.options.Storage.Client(req.ClientID)
	if err != nil {
		if err != protocol.ErrNotFoundEntity {
			resp.SetErrorURI(protocol.ErrUnauthorizedClient.Wrap(err), "", req.State)
		} else {
			resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
		}
		return nil
	}
	// 1. check redirect uri
	req.RedirectURI, err = url.QueryUnescape(req.RedirectURI)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequestURI, "", req.State)
		return nil
	}
	req.RedirectURI, err = ValidateURIList(cli.RedirectURI(), req.RedirectURI, s.options.RedirectURISeparator)
	if err != nil {
		resp.SetErrorURI(protocol.ErrInvalidRequest.
			Desc("The requested redirect_uri is missing in the client configuration or invalid"), "", req.State)
		return nil
	}
	resp.SetRedirectURL(req.RedirectURI)

	// 2. check resposne type
	typesOK, err := ValidateResponseType(cli, string(req.ResponseType))
	if err != nil {
		resp.SetErrorURI(protocol.ErrUnsupportedResponseType, "", req.State)
		return nil
	}
	// 3. check scopes
	var openIDScope bool
	req.Scope, openIDScope = ValidateScopes(cli, req.Scope)
	// oidc flow
	if openIDScope {
		// "token" can't be provided by its own.
		//
		// https://openid.net/specs/openid-connect-core-1_0.html#Authentication
		if typesOK.ResponseTypeToken && !typesOK.ResponseTypeCode && !typesOK.ResponseTypeIDToken {
			resp.SetErrorURI(protocol.ErrInvalidRequest, "", req.State)
			return nil
		}
		// Either "id_token token" or "id_token" has been provided which implies the
		// implicit flow. Implicit flow requires a nonce value.
		//
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
		// TODO
		fmt.Println(userID)
	}
	// oauth2 flow
	// 4. check code challenge
	if typesOK.ResponseTypeCode || typesOK.ResponseTypeDevice {
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
	// 5. check device flow
	// TODO
	return req
}

// FinishAuthorizeRequest finish authorize request
func (s *Server) FinishAuthorizeRequest(resp *protocol.Response, r *http.Request, req *protocol.AuthorizeRequest) {
	for _, v := range strings.Fields(string(req.ResponseType)) {
		ty := protocol.ResponseType(v)
		switch ty {
		case protocol.ResponseTypeCode:
			// generate token code
			code, err := s.options.AuthorizeCodeGen(req)
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
				return
			}

			// save
			err = s.options.Storage.SaveAuthorize(code, req)
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
				return
			}

			// redirect with code
			resp.Output["code"] = code
			resp.Output["state"] = req.State
		case protocol.ResponseTypeToken:
			resp.SetResponseMode(protocol.ResponseModeFragment)
			// TODO

			if req.State != "" && resp.ErrCode == nil {
				resp.Output["state"] = req.State
			}
		case protocol.ResponseTypeIDToken:
			resp.SetResponseMode(protocol.ResponseModeFragment)

			key, err := s.options.Storage.PrivateKey(req.Client.ClientID())
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
				return
			}
			// user data must be id_token data
			idToken, err := signPayload(key, req.UserData)
			if err != nil {
				resp.SetErrorURI(protocol.ErrServerError.Wrap(err), "", req.State)
				return
			}
			resp.Output["id_token"] = idToken
			resp.Output["state"] = req.State
		}
	}
}

// HandleToken token request handler
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) error {
	r.ParseForm()

	return nil
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
		case elliptic.P521().Params():
			return jose.ES512, nil
		default:
			return "", errors.New("unsupported ecdsa curve")
		}
	default:
		return "", fmt.Errorf("unsupported signing key type %T", key)
	}
}
