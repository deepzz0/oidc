// Package protocol provides ...
package protocol

import (
	"encoding/json"
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
	// set content type if the response doesn't already have one associated with it
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	encoder := json.NewEncoder(w)
	return encoder.Encode(resp.Output)
}
