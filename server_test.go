// Package oidc provides ...
package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/deepzz0/oidc/examples"
	"github.com/deepzz0/oidc/protocol"
	"github.com/stretchr/testify/assert"
)

var (
	server *Server
	issuer = "http://localhost:8080/oidc"
)

func init() {
	server = NewServer(
		WithIssuer(issuer),
		WithStorage(examples.NewTestStorage()),
		WithDefaultScopes([]string{protocol.ScopeEmail}),
	)
	// inject code & token generate
	testHookGenerateCode = func() string {
		return "test_hook_code"
	}
}

type testcase struct {
	vals     url.Values
	expected error
}

var authorizeCases = []testcase{
	// no client_id
	{
		vals: url.Values{
			"response_type": {"code"},
			"state":         {"test_state"},
		},
		expected: protocol.ErrUnauthorizedClient,
	},
	// no redirect uri
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"code"},
			"redirect_uri":  {""},
			"state":         {"test_state"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// invalid client
	{
		vals: url.Values{
			"client_id":     {"1234"},
			"response_type": {"code"},
			"state":         {"test_state"},
		},
		expected: protocol.ErrUnauthorizedClient,
	},
	// invalid response_type
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"code1"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
		},
		expected: protocol.ErrUnsupportedResponseType,
	},
	// openid scope & response_type should contains code or id_token
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"token"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email", "openid"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// no response_type=code implicit, should with nonce
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"token", "id_token"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email", "openid"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// ok: specify response mode
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"code"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email"},
			"response_mode": {"form_post"},
		},
		expected: nil,
	},
	// ok: invalid scope
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"code"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email", "invalid scope"},
		},
		expected: nil,
	},
	// ok: authorization_code/code
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"code"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
		},
		expected: nil,
	},
	// ok: authorization_code/token
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"token"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
		},
		expected: nil,
	},
	// ok: authorization_code/id_token
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"id_token"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email"},
		},
		expected: nil,
	},
	// ok: authorization_code/hybrid
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"code token"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email"},
		},
		expected: nil,
	},
	// ok: authorization_code/hybrid
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"code id_token"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email"},
		},
		expected: nil,
	},
	// ok: authorization_code/hybrid
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"token id_token"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email"},
		},
		expected: nil,
	},
	// ok: authorization_code/hybrid
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"code token id_token"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
			"state":         {"test_state"},
			"scope":         {"email"},
		},
		expected: nil,
	},
}

// example:
//  client_id=xxx&response_type=code&redirect_uri=xxx&state=xxx
func TestAuthorizationEndpoint(t *testing.T) {
	for _, v := range authorizeCases {
		url := issuer + "/autorize?" + v.vals.Encode()
		r := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()

		resp := protocol.NewResponse()
		req := server.HandleAuthorizeRequest(resp, r)
		assertExpectedEqualError(t, v, resp.ErrCode)
		// authorization_code ok
		if resp.ErrCode == nil {
			// login user
			req.UserID = "1234"
			server.FinishAuthorizeRequest(resp, r, req)

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			// redirect
			if v.vals.Get("response_mode") == "form_post" {
				assert.Equal(t, 200, w.Code)
			} else {
				assert.Equal(t, 302, w.Code)
			}
			assert.Equal(t, "test_state", resp.Output["state"], resp.Output)
			location := w.Header().Get("Location")
			switch v.vals.Get("response_type") {
			case "code":
				assert.Equal(t, "test_hook_code", resp.Output["code"])

				if v.vals.Get("response_mode") == "form_post" {
					t.Log(w.Body.String())
				} else {
					assert.Equal(t, "http://localhost:9000/oidc/callback?code=test_hook_code&state=test_state", location)
				}
			case "token":
				assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"], resp.Output)
				assert.EqualValues(t, "Bearer", resp.Output["token_type"], resp.Output)

				assert.Equal(t, "http://localhost:9000/oidc/callback#access_token=3D3etRBHQjqKEhfh3_kr6Q&expires_in=3600&scope=email&state=test_state&token_type=Bearer", location)
			case "id_token":
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.oH-7rQKjg3Vaw-J6a5HBGUJ5WcNlds6kZQRoewdztQZFNbXXJzPK90jwEPHdS5JDmwn8zLSvL39057zZP0_D8mPBnq0l44inXI40Mfuyo-xBZGs5JWXruL69KCsLrtcvQsKae-yO9SF33P0VSOltreJ0p7c2idHBKkyCAvY8qEYRRsGIx1cNfSyI-wNHhF1cEMOyjy1pDfHexMGUKQJxmtUJC3x_SYTmSM7-7I3y1Kju26lgl8gQjGbyKTFOH19v8uxQAVkpOVX7ZHpkbXu5bYJ0L-8E1aHV7pkyCuMNcWdBnKSdZiIyN8V_uXlnDzu5b9l45LJX5AE8YJwE6Pcgug", resp.Output["id_token"], resp.Output)

				assert.Equal(t, "http://localhost:9000/oidc/callback#id_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.oH-7rQKjg3Vaw-J6a5HBGUJ5WcNlds6kZQRoewdztQZFNbXXJzPK90jwEPHdS5JDmwn8zLSvL39057zZP0_D8mPBnq0l44inXI40Mfuyo-xBZGs5JWXruL69KCsLrtcvQsKae-yO9SF33P0VSOltreJ0p7c2idHBKkyCAvY8qEYRRsGIx1cNfSyI-wNHhF1cEMOyjy1pDfHexMGUKQJxmtUJC3x_SYTmSM7-7I3y1Kju26lgl8gQjGbyKTFOH19v8uxQAVkpOVX7ZHpkbXu5bYJ0L-8E1aHV7pkyCuMNcWdBnKSdZiIyN8V_uXlnDzu5b9l45LJX5AE8YJwE6Pcgug&state=test_state", location)
			case "code token":
				assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "test_hook_code", resp.Output["code"])
			case "code id_token":
				assert.Equal(t, "test_hook_code", resp.Output["code"])
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.oH-7rQKjg3Vaw-J6a5HBGUJ5WcNlds6kZQRoewdztQZFNbXXJzPK90jwEPHdS5JDmwn8zLSvL39057zZP0_D8mPBnq0l44inXI40Mfuyo-xBZGs5JWXruL69KCsLrtcvQsKae-yO9SF33P0VSOltreJ0p7c2idHBKkyCAvY8qEYRRsGIx1cNfSyI-wNHhF1cEMOyjy1pDfHexMGUKQJxmtUJC3x_SYTmSM7-7I3y1Kju26lgl8gQjGbyKTFOH19v8uxQAVkpOVX7ZHpkbXu5bYJ0L-8E1aHV7pkyCuMNcWdBnKSdZiIyN8V_uXlnDzu5b9l45LJX5AE8YJwE6Pcgug", resp.Output["id_token"], resp.Output)
			case "token id_token":
				assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.oH-7rQKjg3Vaw-J6a5HBGUJ5WcNlds6kZQRoewdztQZFNbXXJzPK90jwEPHdS5JDmwn8zLSvL39057zZP0_D8mPBnq0l44inXI40Mfuyo-xBZGs5JWXruL69KCsLrtcvQsKae-yO9SF33P0VSOltreJ0p7c2idHBKkyCAvY8qEYRRsGIx1cNfSyI-wNHhF1cEMOyjy1pDfHexMGUKQJxmtUJC3x_SYTmSM7-7I3y1Kju26lgl8gQjGbyKTFOH19v8uxQAVkpOVX7ZHpkbXu5bYJ0L-8E1aHV7pkyCuMNcWdBnKSdZiIyN8V_uXlnDzu5b9l45LJX5AE8YJwE6Pcgug", resp.Output["id_token"], resp.Output)

				assert.Equal(t, "http://localhost:9000/oidc/callback#access_token=3D3etRBHQjqKEhfh3_kr6Q&expires_in=3600&id_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.oH-7rQKjg3Vaw-J6a5HBGUJ5WcNlds6kZQRoewdztQZFNbXXJzPK90jwEPHdS5JDmwn8zLSvL39057zZP0_D8mPBnq0l44inXI40Mfuyo-xBZGs5JWXruL69KCsLrtcvQsKae-yO9SF33P0VSOltreJ0p7c2idHBKkyCAvY8qEYRRsGIx1cNfSyI-wNHhF1cEMOyjy1pDfHexMGUKQJxmtUJC3x_SYTmSM7-7I3y1Kju26lgl8gQjGbyKTFOH19v8uxQAVkpOVX7ZHpkbXu5bYJ0L-8E1aHV7pkyCuMNcWdBnKSdZiIyN8V_uXlnDzu5b9l45LJX5AE8YJwE6Pcgug&scope=email&state=test_state&token_type=Bearer", location, resp.Output)
			case "code token id_token":
				assert.Equal(t, "test_hook_code", resp.Output["code"])
				assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.oH-7rQKjg3Vaw-J6a5HBGUJ5WcNlds6kZQRoewdztQZFNbXXJzPK90jwEPHdS5JDmwn8zLSvL39057zZP0_D8mPBnq0l44inXI40Mfuyo-xBZGs5JWXruL69KCsLrtcvQsKae-yO9SF33P0VSOltreJ0p7c2idHBKkyCAvY8qEYRRsGIx1cNfSyI-wNHhF1cEMOyjy1pDfHexMGUKQJxmtUJC3x_SYTmSM7-7I3y1Kju26lgl8gQjGbyKTFOH19v8uxQAVkpOVX7ZHpkbXu5bYJ0L-8E1aHV7pkyCuMNcWdBnKSdZiIyN8V_uXlnDzu5b9l45LJX5AE8YJwE6Pcgug", resp.Output["id_token"], resp.Output)
			}
		}
	}
}

var authorizationCodeCases = []testcase{
	// not form data
	{
		vals: url.Values{
			"grant_type": {"authorization_code"},
		},
		expected: protocol.ErrUnsupportedGrantType,
	},
	// not client auth
	{
		vals: url.Values{
			"grant_type": {"authorization_code"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// authorization_code, no code
	{
		vals: url.Values{
			"grant_type": {"authorization_code"},
		},
		expected: protocol.ErrInvalidGrant,
	},
	// no client_id
	{
		vals: url.Values{
			"grant_type": {"authorization_code"},
			"code":       {"test_hook_code"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// no redirect_uri
	{
		vals: url.Values{
			"grant_type": {"authorization_code"},
			"code":       {"test_hook_code"},
			"client_id":  {"test_client_id"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// invalid redirect_uri
	{
		vals: url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"test_hook_code"},
			"client_id":    {"test_client_id"},
			"redirect_uri": {"http://localhost"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// invalid AllowClientSecretInParams
	{
		vals: url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"test_hook_code"},
			"client_id":     {"test_client_id"},
			"client_secret": {"aabbccdd"},
			"redirect_uri":  {"http://localhost:9000/oidc/callback"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// ok: authorization_code
	{
		vals: url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"test_hook_code"},
			"client_id":    {"test_client_id"},
			"redirect_uri": {"http://localhost:9000/oidc/callback"},
		},
		expected: nil,
	},
}

func TestTokenAuthorizationCode(t *testing.T) {
	authorizeCases = []testcase{
		// ok: authorization_code/code
		{
			vals: url.Values{
				"client_id":     {"test_client_id"},
				"response_type": {"code"},
				"redirect_uri":  {"http://localhost:9000/oidc/callback"},
				"state":         {"test_state"},
			},
			expected: nil,
		},
	}
	TestAuthorizationEndpoint(t)

	for i, v := range authorizationCodeCases {
		url := issuer + "/token"
		r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(v.vals.Encode()))
		if i != 0 { // not form data
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if i != 1 && i != 6 { // no client auth
			r.SetBasicAuth("test_client_id", "aabbccdd")
		}
		w := httptest.NewRecorder()

		resp := protocol.NewResponse()
		req := server.HandleTokenRequest(resp, r)
		assertExpectedEqualError(t, v, resp.ErrCode)

		// access ok
		if resp.ErrCode == nil {
			server.FinishTokenRequest(resp, r, req)

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, 200, w.Code)

			assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"])
			assert.Equal(t, "test_hook_code", resp.Output["refresh_token"])
			assert.EqualValues(t, "Bearer", resp.Output["token_type"])
		}
	}
}

var refreshTokenCases = []testcase{
	// no refresh_token
	{
		vals: url.Values{
			"grant_type": {"refresh_token"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// invalid refresh_token
	{
		vals: url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"hello"},
		},
		expected: protocol.ErrInvalidGrant,
	},
	// ok: refresh_token
	{
		vals: url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"test_hook_code"},
		},
		expected: nil,
	},
}

func TestTokenRefreshToken(t *testing.T) {
	authorizeCases = []testcase{
		// ok: authorization_code/code
		{
			vals: url.Values{
				"client_id":     {"test_client_id"},
				"response_type": {"code"},
				"redirect_uri":  {"http://localhost:9000/oidc/callback"},
				"state":         {"test_state"},
			},
			expected: nil,
		},
	}
	TestAuthorizationEndpoint(t)

	authorizationCodeCases = []testcase{
		// not form data
		{
			vals: url.Values{
				"grant_type": {"authorization_code"},
			},
			expected: protocol.ErrUnsupportedGrantType,
		},
		// not client auth
		{
			vals: url.Values{
				"grant_type": {"authorization_code"},
			},
			expected: protocol.ErrInvalidRequest,
		},
		// ok: authorization_code
		{
			vals: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {"test_hook_code"},
				"client_id":    {"test_client_id"},
				"redirect_uri": {"http://localhost:9000/oidc/callback"},
			},
			expected: nil,
		},
	}
	TestTokenAuthorizationCode(t)

	for _, v := range refreshTokenCases {
		url := issuer + "/token"
		r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(v.vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("test_client_id", "aabbccdd")
		w := httptest.NewRecorder()

		resp := protocol.NewResponse()
		req := server.HandleTokenRequest(resp, r)
		assertExpectedEqualError(t, v, resp.ErrCode)

		// access ok
		if resp.ErrCode == nil {
			server.FinishTokenRequest(resp, r, req)

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, 200, w.Code)

			assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"])
			assert.Equal(t, "test_hook_code", resp.Output["refresh_token"])
			assert.EqualValues(t, "Bearer", resp.Output["token_type"])
		}
	}
}

var passwordCases = []testcase{
	// no username or password
	{
		vals: url.Values{
			"grant_type": {"password"},
		},
		expected: protocol.ErrInvalidGrant,
	},
	// invalid username or password
	{
		vals: url.Values{
			"grant_type": {"password"},
			"username":   {"1234"},
			"password":   {"1234"},
		},
		expected: protocol.ErrAccessDenied,
	},
	// ok: password
	{
		vals: url.Values{
			"grant_type": {"password"},
			"username":   {"hello"},
			"password":   {"world"},
			"scope":      {"email"},
		},
		expected: nil,
	},
}

func TestTokenPassword(t *testing.T) {
	for i, v := range passwordCases {
		url := issuer + "/token"
		r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(v.vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("test_client_id", "aabbccdd")
		w := httptest.NewRecorder()

		resp := protocol.NewResponse()
		req := server.HandleTokenRequest(resp, r)
		if i < 1 { // valid by next
			assertExpectedEqualError(t, v, resp.ErrCode)
		}

		// access ok
		if resp.ErrCode == nil {
			// validate username & password
			if req.Username == "hello" && req.Password == "world" {
				req.UserID = "1234"
			}
			server.FinishTokenRequest(resp, r, req)
			assertExpectedEqualError(t, v, resp.ErrCode)
			if resp.ErrCode != nil {
				continue
			}

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, 200, w.Code)
			assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"])
			assert.Equal(t, "test_hook_code", resp.Output["refresh_token"])
			assert.EqualValues(t, "Bearer", resp.Output["token_type"])
		}
	}
}

var credentialsCases = []testcase{
	// ok
	{
		vals: url.Values{
			"grant_type": {"client_credentials"},
		},
		expected: nil,
	},
}

func TestTokenCredentials(t *testing.T) {
	for _, v := range credentialsCases {
		url := issuer + "/token"
		r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(v.vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("test_client_id", "aabbccdd")
		w := httptest.NewRecorder()

		resp := protocol.NewResponse()
		req := server.HandleTokenRequest(resp, r)
		assertExpectedEqualError(t, v, resp.ErrCode)

		// access ok
		if resp.ErrCode == nil {
			server.FinishTokenRequest(resp, r, req)

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, 200, w.Code)

			assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"])
			assert.EqualValues(t, "Bearer", resp.Output["token_type"])
		}
	}
}

var userinfoCases = []testcase{
	// no token
	{
		vals:     url.Values{},
		expected: protocol.ErrInvalidToken,
	},
	// ok: token in header
	{
		vals:     url.Values{},
		expected: nil,
	},
	// ok: token in query
	{
		vals: url.Values{
			"access_token": {"3D3etRBHQjqKEhfh3_kr6Q"},
		},
		expected: nil,
	},
	// ok: token in body
	{
		vals: url.Values{
			"access_token": {"3D3etRBHQjqKEhfh3_kr6Q"},
		},
		expected: nil,
	},
}

func TestUserInfoEndpoint(t *testing.T) {
	TestTokenPassword(t)

	for i, v := range userinfoCases {
		resp := protocol.NewResponse()
		w := httptest.NewRecorder()
		var r *http.Request
		switch i {
		case 0:
			url := issuer + "/userinfo?" + v.vals.Encode()
			r = httptest.NewRequest(http.MethodGet, url, nil)
		case 1:
			url := issuer + "/userinfo?" + v.vals.Encode()
			r = httptest.NewRequest(http.MethodGet, url, nil)
			r.Header.Set("Authorization", string(server.options.TokenType)+" "+"3D3etRBHQjqKEhfh3_kr6Q")
		case 2:
			url := issuer + "/userinfo?" + v.vals.Encode()
			r = httptest.NewRequest(http.MethodGet, url, nil)
		case 3:
			url := issuer + "/userinfo"
			r = httptest.NewRequest(http.MethodPost, url, strings.NewReader(v.vals.Encode()))
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req := server.HandleUserInfoRequest(resp, r)
		assertExpectedEqualError(t, v, resp.ErrCode)
		if req != nil {
			server.FinishUserInfoRequest(resp, r, req)

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, 200, w.Code)
			t.Log(strings.TrimSpace(w.Body.String()))
		}
	}
}

func assertExpectedEqualError(t *testing.T, v testcase, errcode error) {
	if v.expected == nil && errcode != nil {
		t.Fatalf("expected: %v, but got: %v", v.expected, errcode)
	}
	if v.expected != nil && errcode == nil {
		t.Fatalf("expected: %v, but got: %v", v.expected, errcode)
	}
	if v.expected != nil && errcode != nil {
		if v.expected.(protocol.Error).ErrorCode != errcode.(protocol.Error).ErrorCode {
			t.Fatalf("expected: %v, but got: %v, vals: %v", v.expected, errcode, v.vals)
		}
	}
}
