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
		if uris[0] == baseURIList {
			redirectURI = baseURIList
		}
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

// ValidateScopes validates the scopes
func ValidateScopes(cli protocol.Client, scopes []string) ([]string, bool) {
	openIDScope := false
	for i := len(scopes) - 1; i >= 0; i-- {
		scope := scopes[i]
		if scope == string(protocol.ScopeOpenID) {
			openIDScope = true
			continue
		}
		if !(scope == string(protocol.ScopeProfile) ||
			scope == string(protocol.ScopeEmail) ||
			scope == string(protocol.ScopeAddress) ||
			scope == string(protocol.ScopePhone) ||
			scope == string(protocol.ScopeOfflineAccess)) &&
			!cli.IsScopeAllowed(scope) {
			scopes[i] = scopes[len(scopes)-1]
			scopes = scopes[:len(scopes)-1]
		}
	}
	return scopes, openIDScope
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
func ValidateResponseType(cli protocol.Client, typ string) (ResponseTypeOK, error) {
	ret := ResponseTypeOK{}
	if typ == "" {
		return ret, protocol.ErrInvalidRequest.Desc("The response type is missing in your request. ")
	}
	types := cli.ResponseTypes()

	reqTypes := strings.Fields(typ)
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
		}
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
