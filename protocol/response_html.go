// Package protocol provides ...
package protocol

import (
	"net/http"
	"text/template"
)

var errorTemplate *template.Template

func init() {
	var err error
	errorTemplate, err = template.New("error_html").Parse(`error: {{.error}}
error_description: {{.error_description}}
{{if .error_uri}}error_uri: {{.error_uri}}{{end}}`)
	if err != nil {
		panic(err)
	}
}

// OutputHTML encodes the Response to HTML and writes to the http.ResponseWriter
func OutputHTML(resp *Response, w http.ResponseWriter, r *http.Request) error {
	// add headers
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Set(k, vv)
		}
	}
	// status code
	w.WriteHeader(resp.GetStatusCode())

	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	if resp.ErrCode != nil {
		_ = errorTemplate.Execute(w, resp.Output)
	}
	return nil
}
