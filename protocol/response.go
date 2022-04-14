// Package protocol provides ...
package protocol

import (
	"fmt"
	"net/http"
	"net/url"
)

// Response response for request
type Response struct {
	Header http.Header
	Output map[string]interface{}

	// oauth2 or oidc error code
	ErrCode error

	ResponseMode ResponseMode
	RedirectURL  string
}

// NewResponse output
func NewResponse() *Response {
	header := http.Header{}
	header.Add(
		"Cache-Control",
		"no-cache, no-store, max-age=0, must-revalidate",
	)
	header.Add("Pragma", "no-cache")
	header.Add("Expires", "Fri, 01 Jan 1990 00:00:00 GMT")
	return &Response{
		Header: header,
		Output: make(map[string]interface{}),
	}
}

// SetRedirectURL changes the response to redirect to the given uri
func (resp *Response) SetRedirectURL(url string) {
	resp.RedirectURL = url
}

// SetErrorURI sets an error id, description, state, and uri on the Response
func (resp *Response) SetErrorURI(err Error, uri, state string) {
	// clear output
	resp.Output = make(map[string]interface{})
	resp.Output["error"] = err.ErrorCode
	resp.Output["error_description"] = err.Description
	if uri != "" {
		resp.Output["error_uri"] = uri
	}
	if state != "" {
		resp.Output["state"] = state
	}
	resp.ErrCode = err
}

// SetResponseMode sets response mode
func (resp *Response) SetResponseMode(mode ResponseMode) {
	resp.ResponseMode = mode
}

// GetStatusCode get the http status code
func (resp *Response) GetStatusCode() int {
	// redirect status code
	if resp.RedirectURL != "" {
		return http.StatusFound
	}
	if resp.ErrCode != nil {
		// define status code
		e, ok := resp.ErrCode.(Error)
		if !ok {
			return http.StatusBadRequest
		}
		return e.statusCode
	}
	return http.StatusOK
}

// GetRedirectURL returns the redirect url with all query string parameters
func (resp *Response) GetRedirectURL() (string, error) {
	u, err := url.Parse(resp.RedirectURL)
	if err != nil {
		return "", err
	}

	var q url.Values
	// https://tools.ietf.org/html/rfc6749#section-4.2.2
	// Fragment should be encoded as application/x-www-form-urlencoded (%-escaped,
	// spaces are represented as '+')
	// The stdlib URL#String() doesn't make that easy to accomplish, so build this ourselves
	switch resp.ResponseMode {
	case ResponseModeQuery:
		q = u.Query()
	case ResponseModeFragment:
		q = url.Values{}
	default: // query
		q = u.Query()
	}
	// add parameters
	for n, v := range resp.Output {
		q.Set(n, fmt.Sprint(v))
	}
	if resp.ResponseMode == ResponseModeFragment {
		u.Fragment = ""
		redirectURI := u.String() + "#" + q.Encode()
		return redirectURI, nil
	}
	// Otherwise, update the query and encode normally
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}
