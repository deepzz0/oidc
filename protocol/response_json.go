// Package protocol provides ...
package protocol

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// OutputJSON encodes the Response to JSON and writes to the http.ResponseWriter
func OutputJSON(resp *Response, w http.ResponseWriter, r *http.Request) error {
	// add headers
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Set(k, vv)
		}
	}
	// status code
	w.WriteHeader(resp.GetStatusCode())

	switch resp.ResponseMode {
	case ResponseModeFormPost:
		return responseFormPost(resp, w)
	default: // response_mode==query || response_mode==fragment
		// redirect
		if resp.RedirectURL != "" {
			// output redirect with parameters
			url, err := resp.GetRedirectURL()
			if err != nil {
				return err
			}
			w.Header().Add("Location", url)
			return nil
		}
	}
	// set content type if the response doesn't already have one associated with it
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	}
	encoder := json.NewEncoder(w)
	return encoder.Encode(resp.Output)
}

// see https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
func responseFormPost(resp *Response, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")

	w.Write([]byte(`<html>
 <head><title>Submit This Form</title></head>
 <body onload="javascript:document.forms[0].submit()">`))
	// callback
	w.Write([]byte(`<form method="post" action="` + resp.RedirectURL + `">`))
	// fields
	for n, v := range resp.Output {
		w.Write([]byte(`<input type="hidden" name="` + n + `" value="` + fmt.Sprint(v) + `"/>`))
	}
	w.Write([]byte(`</form></body></html>`))
	return nil
}
