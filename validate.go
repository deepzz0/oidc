// Package oidc provides ...
package oidc

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/deepzz0/oidc/protocol"
)

// URIValidationError error returned when validation don't match
type URIValidationError string

// Error implement error
func (e URIValidationError) Error() string {
	return string(e)
}

func newURIValidationError(msg string, base string, redirect string) URIValidationError {
	return URIValidationError(fmt.Sprintf("%s: %s / %s", msg, base, redirect))
}

// ParseMatchURL resolving uri references to base url
func ParseMatchURL(baseURL, redirectURL string) (retBaseURL, retRedirectURL *url.URL, err error) {
	// parse base url
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil, err
	}

	// parse redirect url
	redirect, err := url.Parse(redirectURL)
	if err != nil {
		return nil, nil, err
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return nil, nil, newURIValidationError("url must not include fragment.", baseURL, redirectURL)
	}

	// Scheme must match
	if redirect.Scheme != base.Scheme {
		return nil, nil, newURIValidationError("scheme mismatch", baseURL, redirectURL)
	}

	var (
		redirectMatch bool
		host          string
	)

	// verify the hosts match
	if redirect.Host == base.Host {
		redirectMatch = true
		host = base.Host
	} else if baseIP := net.ParseIP(base.Host); baseIP != nil && baseIP.IsLoopback() && base.Scheme == "http" {
		// if the registered redirect URI is lookback, then match the input redirect without the port.
		if redirectIP := net.ParseIP(redirect.Hostname()); redirectIP != nil && redirectIP.IsLoopback() {
			redirectMatch = true
			host = redirect.Host
		}
	}

	// Hosts must match
	if !redirectMatch {
		return nil, nil, newURIValidationError("host mismatch", baseURL, redirectURL)
	}

	// resolve references to base url
	retBaseURL = (&url.URL{Scheme: base.Scheme, Host: host}).
		ResolveReference(&url.URL{Path: base.Path})
	retRedirectURL = (&url.URL{Scheme: base.Scheme, Host: host}).
		ResolveReference(&url.URL{Path: redirect.Path, RawQuery: redirect.RawQuery})
	return
}

// ValidateURI validates that redirectURI is contained in baseURI
func ValidateURI(baseURI, redirectURI string) (realRedirectURI string, err error) {
	if baseURI == "" || redirectURI == "" {
		return "", errors.New("urls cannot be blank")
	}

	base, redirect, err := ParseMatchURL(baseURI, redirectURI)
	if err != nil {
		return "", err
	}

	// allow exact path matched
	if base.Path == redirect.Path {
		return redirect.String(), nil
	}

	// ensure prefix matches are actually subpaths
	requiredPrefix := strings.TrimRight(base.Path, "/") + "/"
	if !strings.HasPrefix(redirect.Path, requiredPrefix) {
		return "", newURIValidationError("path prefix doesn't match", baseURI, redirectURI)
	}
	return redirect.String(), nil
}

// ValidateURIList validates that redirectURI is contained in baseURIList.
func ValidateURIList(baseURIList, redirectURI, separator string) (realRedirectURI string, err error) {
	uris := strings.Split(baseURIList, separator)
	// if there are multiple client redirect uri's don't set the uri
	if redirectURI == "" {
		return "", newURIValidationError("redirect_uri not found", baseURIList, "")
	}
	// validates that redirectURI is contained in baseURIList.
	for _, v := range uris {
		realRedirectURI, err = ValidateURI(v, redirectURI)
		// validated, return no error
		if err == nil {
			return realRedirectURI, nil
		}

		// if there was an error that is not a validation error, return it
		if _, ok := err.(URIValidationError); !ok {
			return "", err
		}
	}
	return "", newURIValidationError("urls don't validate", baseURIList, redirectURI)
}

// ValidateScopes validates the scopes & remove invalid scope
func ValidateScopes(cli protocol.Client, scopes []string, defaultScopes []string,
	respTypeCode bool, prompt []string) ([]string, bool, bool) {

	openIDScope := false
	offlineAccessScope := 0
	for i := len(scopes) - 1; i >= 0; i-- {
		scope := scopes[i]

		if scope == protocol.ScopeOpenID {
			openIDScope = true
			continue
		}
		if scope == protocol.ScopeOfflineAccess {
			offlineAccessScope = i
		}
		if !(scope == protocol.ScopeProfile || scope == protocol.ScopeEmail ||
			scope == protocol.ScopeAddress || scope == protocol.ScopePhone ||
			scope == protocol.ScopeOfflineAccess) && !cli.IsScopeAllowed(scope) { // ignore unknown scope
			scopes[i] = scopes[len(scopes)-1]
			scopes = scopes[:len(scopes)-1]
		}
	}
	// MUST ignore the offline_access request unless the Client is using a response_type value that would
	// result in an Authorization Code being returned,
	// https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
	if offlineAccessScope > 0 {
		found := false
		for _, p := range prompt {
			if protocol.Prompt(p) == protocol.PromptConsent {
				found = true
			}
		}
		// not oidc or not found consent prompt
		if !openIDScope || !found {
			offlineAccessScope = 0
			scopes = append(scopes[:offlineAccessScope], scopes[offlineAccessScope+1:]...)
		}
	}
	if len(scopes) == 0 {
		scopes = defaultScopes
	}
	return scopes, openIDScope, offlineAccessScope > 0
}

func containsResponseType(types []protocol.ResponseType, ty string) bool {
	for _, t := range types {
		if string(t) == ty {
			return true
		}
	}
	return false
}

// ResponseTypeOK response type ok
type ResponseTypeOK struct {
	ResponseTypeCode    bool
	ResponseTypeToken   bool
	ResponseTypeIDToken bool
	ResponseTypeNone    bool
	ResponseTypeDevice  bool
}

// ValidateResponseType validates the response type
func ValidateResponseType(cli protocol.Client, reqTypes []string) (ResponseTypeOK, error) {
	ret := ResponseTypeOK{}
	if len(reqTypes) == 0 {
		return ret, protocol.ErrInvalidRequest.Desc("The response type is missing in your request. ")
	}
	types := cli.ResponseTypes()

	for _, t := range reqTypes {
		if !containsResponseType(types, t) {
			return ret, protocol.ErrInvalidRequest.Desc("The requested response type is missing in the client configuration.")
		}
		switch protocol.ResponseType(t) {
		case protocol.ResponseTypeCode:
			ret.ResponseTypeCode = true
		case protocol.ResponseTypeToken:
			ret.ResponseTypeToken = true
		case protocol.ResponseTypeIDToken:
			ret.ResponseTypeIDToken = true
		case protocol.ResponseTypeNone:
			ret.ResponseTypeNone = true
		case protocol.ResponseTypeDevice:
			ret.ResponseTypeDevice = true
		}
	}
	// The Response Type none SHOULD NOT be combined with other Response Types.
	// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
	if ret.ResponseTypeNone && len(reqTypes) > 1 {
		return ret, protocol.ErrInvalidRequest.Desc("Response Type none SHOULD NOT be combined with other Response Types")
	}
	return ret, nil
}

// ValidateIDTokenHint validates the id_token_hint (if passed as parameter in the request)
// and returns the `sub` claim
func ValidateIDTokenHint(idTokenHit string) (string, error) {
	if idTokenHit == "" {
		return "", nil
	}
	// TODO
	return "", nil
}

var pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")

// ValidateCodeChallenge validates the code challenge
// https://tools.ietf.org/html/rfc7636
func ValidateCodeChallenge(codeChall string, codeChallMethod protocol.CodeChallengeMethod) (protocol.CodeChallengeMethod, bool) {

	if codeChall == "" {
		return "", false
	}

	// allowed values are "plain" (default) and "S256",
	// per https://tools.ietf.org/html/rfc7636#section-4.3
	if codeChallMethod == "" {
		codeChallMethod = protocol.CodeChallengeMethodPlain
	}
	if codeChallMethod != protocol.CodeChallengeMethodPlain &&
		codeChallMethod != protocol.CodeChallengeMethodS256 {
		return "", false
	}

	// https://tools.ietf.org/html/rfc7636#section-4.2
	if pkceMatcher.MatchString(codeChall) {
		return "", false
	}
	return codeChallMethod, true
}

// ValidateClientSecret determines whether the given secret matches a secret held by the client.
// Public clients return true for a secret of ""
func ValidateClientSecret(client protocol.Client, secret string) bool {
	return subtle.ConstantTimeCompare([]byte(client.ClientSecret()), []byte(secret)) == 1
}

// ValidateGrantType validates the client grant type support
func ValidateGrantType(types []protocol.GrantType, ty protocol.GrantType) bool {
	for _, v := range types {
		if v == ty {
			return true
		}
	}
	return false
}

// ValidatePrompt validate prompt, set max_age=0 if prompt login is present
func ValidatePrompt(prompts []string, maxAge int) (int, error) {
	for _, v := range prompts {
		p := protocol.Prompt(v)
		if !protocol.IsValidPrompt(p) {
			return 0, errors.New("Unsupported prompt parameter: " + v)
		}
		//  If this parameter contains none with any other value, an error is returned.
		if p == protocol.PromptNone && len(prompts) > 1 {
			return 0, errors.New("The prompt parameter 'none' must only be used as a signle value")
		}
		if p == protocol.PromptLogin {
			maxAge = 0
		}
	}
	return maxAge, nil
}

// ValidateTokenHint only support access_token & refresh_token
func ValidateTokenHint(hint protocol.TokenTypeHint) bool {
	return hint == protocol.TokenTypeHintAccessToken ||
		hint == protocol.TokenTypeHintRefreshToken
}

// ValidateOfflineAccess validate offline_access
func ValidateOfflineAccess(prompt []string, scopes []string) ([]string, bool, error) {
	// ignoreScope := true
	// for _, p := range prompt {
	// 	if protocol.Prompt(p) == protocol.PromptConsent {
	// 		for _, s := range scopes {
	// 			if s == protocol.ScopeOfflineAccess {
	// 				return true
	// 			}
	// 		}
	// 	}
	// }
	//
	return nil, false, nil
}
