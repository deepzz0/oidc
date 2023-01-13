// Package examples provides ...
package examples

// TestSession test
type TestSession struct{}

// AllowedOrigin is that postMessage from op host
func (s *TestSession) AllowedOrigin() string {
	return "http://localhost:8090"
}

// SessionExpiresIn user session expires with cookie
func (s *TestSession) SessionExpiresIn(cookie string) int {
	return 2000
}
