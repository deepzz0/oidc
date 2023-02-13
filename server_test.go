// Package oidc provides ...
package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
		WithForcePKCEForPublicClients(false),
		WithStorage(examples.NewTestStorage()),
		WithDefaultScopes([]string{protocol.ScopeEmail}),
	)
	// inject code & token generate
	testHookGenerateCode = func() (string, error) {
		return "test_hook_code", nil
	}
	testHookTimeNow = func() time.Time {
		return time.Time{}
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
			"state":         {"test_state"},
		},
		expected: protocol.ErrUnsupportedResponseType,
	},
	// openid scope & response_type should contains code or id_token
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"token"},
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
			"state":         {"test_state"},
		},
		expected: nil,
	},
	// ok: authorization_code/token
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"token"},
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
			"state":         {"test_state"},
		},
		expected: nil,
	},
	// ok: authorization_code/id_token
	{
		vals: url.Values{
			"client_id":     {"test_client_id"},
			"response_type": {"id_token"},
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
		req := server.HandleAuthorizeRequest(resp, r, issuer)
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
					assert.Equal(t, "http://localhost:8090/oidc/callback?code=test_hook_code&state=test_state", location)
				}
			case "token":
				assert.Equal(t, "WHwAII5NYaTQda7SdGw0Pg", resp.Output["access_token"], resp.Output)
				assert.EqualValues(t, "Bearer", resp.Output["token_type"], resp.Output)

				assert.Equal(t, "http://localhost:8090/oidc/callback#access_token=WHwAII5NYaTQda7SdGw0Pg&expires_in=3600&scope=email&state=test_state&token_type=Bearer", location)
			case "id_token":
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkYyIsInN1YiI6IjEyMzQiLCJhdWQiOlsidGVzdF9jbGllbnRfaWQiXSwiZXhwIjotNjc5NTM2MDk3OSwiaWF0IjotNjc5NTM2NDU3OX0.vPjyHpHFF0AcJqc-RO2XPfOr5u5Fo2nW7f-rvl6cUiqd0jKKPAeAUohiGUhU4PHtScPd2A-YLJOImywmxuSRP9AKzd96u2leeG-e7ZIGINcVXFy8n6xr9AUKSoaeHnMNd4QALolQ9WhNvAeUkLX9z-EgEd4RarrevrOyGI8bm1h9nJu2lrGweYSlry3lfh02ayrCYYsucZOaY7su3nxoVbkr6lrxiud3h1HqpOFXyCTmX51YLy159RcLLjs3cIHGMzDUVZmb0_M6oKM9YHjtaGXr4zt8JHFdiqmDsUinRVbLr3udyRiqd_LxpAgQtJzEqi6CfpF-8Rp1WzTx9KhVzw", resp.Output["id_token"], resp.Output)

				assert.Equal(t, "http://localhost:8090/oidc/callback#id_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkYyIsInN1YiI6IjEyMzQiLCJhdWQiOlsidGVzdF9jbGllbnRfaWQiXSwiZXhwIjotNjc5NTM2MDk3OSwiaWF0IjotNjc5NTM2NDU3OX0.vPjyHpHFF0AcJqc-RO2XPfOr5u5Fo2nW7f-rvl6cUiqd0jKKPAeAUohiGUhU4PHtScPd2A-YLJOImywmxuSRP9AKzd96u2leeG-e7ZIGINcVXFy8n6xr9AUKSoaeHnMNd4QALolQ9WhNvAeUkLX9z-EgEd4RarrevrOyGI8bm1h9nJu2lrGweYSlry3lfh02ayrCYYsucZOaY7su3nxoVbkr6lrxiud3h1HqpOFXyCTmX51YLy159RcLLjs3cIHGMzDUVZmb0_M6oKM9YHjtaGXr4zt8JHFdiqmDsUinRVbLr3udyRiqd_LxpAgQtJzEqi6CfpF-8Rp1WzTx9KhVzw&state=test_state", location)
			case "code token":
				assert.Equal(t, "WHwAII5NYaTQda7SdGw0Pg", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "test_hook_code", resp.Output["code"])
			case "code id_token":
				assert.Equal(t, "test_hook_code", resp.Output["code"])
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkYyIsInN1YiI6IjEyMzQiLCJhdWQiOlsidGVzdF9jbGllbnRfaWQiXSwiZXhwIjotNjc5NTM2MDk3OSwiaWF0IjotNjc5NTM2NDU3OX0.vPjyHpHFF0AcJqc-RO2XPfOr5u5Fo2nW7f-rvl6cUiqd0jKKPAeAUohiGUhU4PHtScPd2A-YLJOImywmxuSRP9AKzd96u2leeG-e7ZIGINcVXFy8n6xr9AUKSoaeHnMNd4QALolQ9WhNvAeUkLX9z-EgEd4RarrevrOyGI8bm1h9nJu2lrGweYSlry3lfh02ayrCYYsucZOaY7su3nxoVbkr6lrxiud3h1HqpOFXyCTmX51YLy159RcLLjs3cIHGMzDUVZmb0_M6oKM9YHjtaGXr4zt8JHFdiqmDsUinRVbLr3udyRiqd_LxpAgQtJzEqi6CfpF-8Rp1WzTx9KhVzw", resp.Output["id_token"], resp.Output)
			case "token id_token":
				assert.Equal(t, "WHwAII5NYaTQda7SdGw0Pg", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkYyIsInN1YiI6IjEyMzQiLCJhdWQiOlsidGVzdF9jbGllbnRfaWQiXSwiZXhwIjotNjc5NTM2MDk3OSwiaWF0IjotNjc5NTM2NDU3OSwiYXRfaGFzaCI6ImVrdXA5akxsdm5ReEtlWV9JRHBubGNwNVNqeGp4N01XZ0Mwcks0S0VkTzQ9In0.u9X6K0OZSbcgijpNBHvEh4D5DOkpQ4U3arzHrgcy-wdSptp0MAyRKinF5QJQ0UqOFZZO0eqFuM8-mdtAMZRDNCQuGxQ3pkLst2duNmFl3QskiolaOVWkLXl3G3BX7kO5oM897HCusK-AFT2oET_QQ5slQ75dsW4KRaqTfChxv7Rca0gEV6baonfCnbRbDGSk4MnVcxPq_WWhRStkIP8E59DqA0IGrORmA5AMYaXNm8RE00alGen9ml5q5wONZKLyWPBY96SJBCmborQNQj9VtfFIGhwQ5FSayYunbDDLbUNE6BlABzGTM-Y97jKn6TEYaEFS-CJOD0S5gcSXmonW6g", resp.Output["id_token"], resp.Output)

				assert.Equal(t, "http://localhost:8090/oidc/callback#access_token=WHwAII5NYaTQda7SdGw0Pg&expires_in=3600&id_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkYyIsInN1YiI6IjEyMzQiLCJhdWQiOlsidGVzdF9jbGllbnRfaWQiXSwiZXhwIjotNjc5NTM2MDk3OSwiaWF0IjotNjc5NTM2NDU3OSwiYXRfaGFzaCI6ImVrdXA5akxsdm5ReEtlWV9JRHBubGNwNVNqeGp4N01XZ0Mwcks0S0VkTzQ9In0.u9X6K0OZSbcgijpNBHvEh4D5DOkpQ4U3arzHrgcy-wdSptp0MAyRKinF5QJQ0UqOFZZO0eqFuM8-mdtAMZRDNCQuGxQ3pkLst2duNmFl3QskiolaOVWkLXl3G3BX7kO5oM897HCusK-AFT2oET_QQ5slQ75dsW4KRaqTfChxv7Rca0gEV6baonfCnbRbDGSk4MnVcxPq_WWhRStkIP8E59DqA0IGrORmA5AMYaXNm8RE00alGen9ml5q5wONZKLyWPBY96SJBCmborQNQj9VtfFIGhwQ5FSayYunbDDLbUNE6BlABzGTM-Y97jKn6TEYaEFS-CJOD0S5gcSXmonW6g&scope=email&state=test_state&token_type=Bearer", location, resp.Output)
			case "code token id_token":
				assert.Equal(t, "test_hook_code", resp.Output["code"])
				assert.Equal(t, "WHwAII5NYaTQda7SdGw0Pg", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkYyIsInN1YiI6IjEyMzQiLCJhdWQiOlsidGVzdF9jbGllbnRfaWQiXSwiZXhwIjotNjc5NTM2MDk3OSwiaWF0IjotNjc5NTM2NDU3OSwiYXRfaGFzaCI6ImVrdXA5akxsdm5ReEtlWV9JRHBubGNwNVNqeGp4N01XZ0Mwcks0S0VkTzQ9In0.u9X6K0OZSbcgijpNBHvEh4D5DOkpQ4U3arzHrgcy-wdSptp0MAyRKinF5QJQ0UqOFZZO0eqFuM8-mdtAMZRDNCQuGxQ3pkLst2duNmFl3QskiolaOVWkLXl3G3BX7kO5oM897HCusK-AFT2oET_QQ5slQ75dsW4KRaqTfChxv7Rca0gEV6baonfCnbRbDGSk4MnVcxPq_WWhRStkIP8E59DqA0IGrORmA5AMYaXNm8RE00alGen9ml5q5wONZKLyWPBY96SJBCmborQNQj9VtfFIGhwQ5FSayYunbDDLbUNE6BlABzGTM-Y97jKn6TEYaEFS-CJOD0S5gcSXmonW6g", resp.Output["id_token"], resp.Output)
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
			"client_id":  {"test_client_id"},
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
			"redirect_uri":  {"http://localhost:8090/oidc/callback"},
		},
		expected: protocol.ErrInvalidRequest,
	},
	// ok: authorization_code
	{
		vals: url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"test_hook_code"},
			"client_id":    {"test_client_id"},
			"redirect_uri": {"http://localhost:8090/oidc/callback"},
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
				"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
		req := server.HandleTokenRequest(resp, r, issuer)
		assertExpectedEqualError(t, v, resp.ErrCode)

		// access ok
		if resp.ErrCode == nil {
			server.FinishTokenRequest(resp, r, req)

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, 200, w.Code)

			assert.Equal(t, "WHwAII5NYaTQda7SdGw0Pg", resp.Output["access_token"])
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
				"redirect_uri":  {"http://localhost:8090/oidc/callback"},
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
				"redirect_uri": {"http://localhost:8090/oidc/callback"},
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
		req := server.HandleTokenRequest(resp, r, issuer)
		assertExpectedEqualError(t, v, resp.ErrCode)

		// access ok
		if resp.ErrCode == nil {
			server.FinishTokenRequest(resp, r, req)

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, 200, w.Code)

			assert.Equal(t, "WHwAII5NYaTQda7SdGw0Pg", resp.Output["access_token"])
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
			"scope":      {"email", "phone"},
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
		req := server.HandleTokenRequest(resp, r, issuer)
		if i < 1 { // valid by next
			assertExpectedEqualError(t, v, resp.ErrCode)
		}

		// access ok
		if resp.ErrCode == nil {
			// validate username & password
			if req.PasswordReq.Username == "hello" && req.PasswordReq.Password == "world" {
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
			assert.Equal(t, "WHwAII5NYaTQda7SdGw0Pg", resp.Output["access_token"])
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
		req := server.HandleTokenRequest(resp, r, issuer)
		assertExpectedEqualError(t, v, resp.ErrCode)

		// access ok
		if resp.ErrCode == nil {
			server.FinishTokenRequest(resp, r, req)

			err := protocol.OutputJSON(resp, w, r)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, 200, w.Code)

			assert.Equal(t, "WHwAII5NYaTQda7SdGw0Pg", resp.Output["access_token"])
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
			"access_token": {"WHwAII5NYaTQda7SdGw0Pg"},
		},
		expected: nil,
	},
	// ok: token in body
	{
		vals: url.Values{
			"access_token": {"WHwAII5NYaTQda7SdGw0Pg"},
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
			r.Header.Set("Authorization", string(server.options.TokenType)+" "+"WHwAII5NYaTQda7SdGw0Pg")
		case 2:
			url := issuer + "/userinfo?" + v.vals.Encode()
			r = httptest.NewRequest(http.MethodGet, url, nil)
		case 3:
			url := issuer + "/userinfo"
			r = httptest.NewRequest(http.MethodPost, url, strings.NewReader(v.vals.Encode()))
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req := server.HandleUserInfoRequest(resp, r, issuer)
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
