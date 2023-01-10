// Package oidc provides ...
package oidc

import (
	"fmt"
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
	// ok: authorization_code/hybird
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
	// ok: authorization_code/hybird
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
	// ok: authorization_code/hybird
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
	// ok: authorization_code/hybird
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
func TestAuthorization(t *testing.T) {
	for _, v := range authorizeCases {
		url := issuer + "/autorize?" + v.vals.Encode()
		r := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()

		resp := protocol.NewResponse()
		req := server.HandleAuthorizeRequest(resp, r)
		assertExpectedEqualError(t, v.expected, resp.ErrCode)
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
			assert.Equal(t, 302, w.Code)
			assert.Equal(t, "test_state", resp.Output["state"], resp.Output)
			location := w.Header().Get("Location")
			switch v.vals.Get("response_type") {
			case "code":
				assert.Equal(t, "test_hook_code", resp.Output["code"])

				assert.Equal(t, "http://localhost:9000/oidc/callback?code=test_hook_code&state=test_state", location)
				if len(v.vals["scope"]) > 1 {
					fmt.Println(v.vals["scope"])
					t.Log(resp.Output)
				}
			case "token":
				assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"], resp.Output)
				assert.EqualValues(t, "Bearer", resp.Output["token_type"], resp.Output)

				assert.Equal(t, "http://localhost:9000/oidc/callback#access_token=3D3etRBHQjqKEhfh3_kr6Q&expires_in=3600&state=test_state&token_type=Bearer", location)
			case "id_token":
				assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.V_S8fSJ9IjAkYANfRv9czLNyJcUbTxU8CY8DhsJYkF9mmY2Y8qUGGjQ2t2avOWRHbngKfpUfhPQanohdoNz65fBFupNP2g0rRSNY3NRZShU_VMVEKOuid4FDEJAId52czadoxnyHJ2pSQX9HC8JkC0BEq1E76HaU0nc8qAZ9IBwoKDUx6oVGMlmGIr8q2q-EmR8D0kX0fKLF0OnFckFicQUClxbExkxRXSXAzyVjLbC928R--J2Tv62Sw9mkB-K23Qcw2bPmHpxy5QpuMV6SdAQ9l7jNX9maNG_UB9NBDcsoVbD4U7cIfYiO73HXRz_VFFECXmfTPJe9yCtd4Xpp_g", resp.Output["id_token"], resp.Output)

				assert.Equal(t, "http://localhost:9000/oidc/callback#id_token=eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.V_S8fSJ9IjAkYANfRv9czLNyJcUbTxU8CY8DhsJYkF9mmY2Y8qUGGjQ2t2avOWRHbngKfpUfhPQanohdoNz65fBFupNP2g0rRSNY3NRZShU_VMVEKOuid4FDEJAId52czadoxnyHJ2pSQX9HC8JkC0BEq1E76HaU0nc8qAZ9IBwoKDUx6oVGMlmGIr8q2q-EmR8D0kX0fKLF0OnFckFicQUClxbExkxRXSXAzyVjLbC928R--J2Tv62Sw9mkB-K23Qcw2bPmHpxy5QpuMV6SdAQ9l7jNX9maNG_UB9NBDcsoVbD4U7cIfYiO73HXRz_VFFECXmfTPJe9yCtd4Xpp_g&state=test_state", location)
			case "code token":
				assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "test_hook_code", resp.Output["code"])
			case "code id_token":
				assert.Equal(t, "test_hook_code", resp.Output["code"])
				assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.V_S8fSJ9IjAkYANfRv9czLNyJcUbTxU8CY8DhsJYkF9mmY2Y8qUGGjQ2t2avOWRHbngKfpUfhPQanohdoNz65fBFupNP2g0rRSNY3NRZShU_VMVEKOuid4FDEJAId52czadoxnyHJ2pSQX9HC8JkC0BEq1E76HaU0nc8qAZ9IBwoKDUx6oVGMlmGIr8q2q-EmR8D0kX0fKLF0OnFckFicQUClxbExkxRXSXAzyVjLbC928R--J2Tv62Sw9mkB-K23Qcw2bPmHpxy5QpuMV6SdAQ9l7jNX9maNG_UB9NBDcsoVbD4U7cIfYiO73HXRz_VFFECXmfTPJe9yCtd4Xpp_g", resp.Output["id_token"], resp.Output)
			case "token id_token":
				assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.V_S8fSJ9IjAkYANfRv9czLNyJcUbTxU8CY8DhsJYkF9mmY2Y8qUGGjQ2t2avOWRHbngKfpUfhPQanohdoNz65fBFupNP2g0rRSNY3NRZShU_VMVEKOuid4FDEJAId52czadoxnyHJ2pSQX9HC8JkC0BEq1E76HaU0nc8qAZ9IBwoKDUx6oVGMlmGIr8q2q-EmR8D0kX0fKLF0OnFckFicQUClxbExkxRXSXAzyVjLbC928R--J2Tv62Sw9mkB-K23Qcw2bPmHpxy5QpuMV6SdAQ9l7jNX9maNG_UB9NBDcsoVbD4U7cIfYiO73HXRz_VFFECXmfTPJe9yCtd4Xpp_g", resp.Output["id_token"], resp.Output)

				assert.Equal(t, "http://localhost:9000/oidc/callback#access_token=3D3etRBHQjqKEhfh3_kr6Q&expires_in=3600&id_token=eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.V_S8fSJ9IjAkYANfRv9czLNyJcUbTxU8CY8DhsJYkF9mmY2Y8qUGGjQ2t2avOWRHbngKfpUfhPQanohdoNz65fBFupNP2g0rRSNY3NRZShU_VMVEKOuid4FDEJAId52czadoxnyHJ2pSQX9HC8JkC0BEq1E76HaU0nc8qAZ9IBwoKDUx6oVGMlmGIr8q2q-EmR8D0kX0fKLF0OnFckFicQUClxbExkxRXSXAzyVjLbC928R--J2Tv62Sw9mkB-K23Qcw2bPmHpxy5QpuMV6SdAQ9l7jNX9maNG_UB9NBDcsoVbD4U7cIfYiO73HXRz_VFFECXmfTPJe9yCtd4Xpp_g&scope=email&state=test_state&token_type=Bearer", location, resp.Output)
			case "code token id_token":
				assert.Equal(t, "test_hook_code", resp.Output["code"])
				assert.Equal(t, "3D3etRBHQjqKEhfh3_kr6Q", resp.Output["access_token"], resp.Output)
				assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImhlbGxvQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.V_S8fSJ9IjAkYANfRv9czLNyJcUbTxU8CY8DhsJYkF9mmY2Y8qUGGjQ2t2avOWRHbngKfpUfhPQanohdoNz65fBFupNP2g0rRSNY3NRZShU_VMVEKOuid4FDEJAId52czadoxnyHJ2pSQX9HC8JkC0BEq1E76HaU0nc8qAZ9IBwoKDUx6oVGMlmGIr8q2q-EmR8D0kX0fKLF0OnFckFicQUClxbExkxRXSXAzyVjLbC928R--J2Tv62Sw9mkB-K23Qcw2bPmHpxy5QpuMV6SdAQ9l7jNX9maNG_UB9NBDcsoVbD4U7cIfYiO73HXRz_VFFECXmfTPJe9yCtd4Xpp_g", resp.Output["id_token"], resp.Output)
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
		expected: protocol.ErrInvalidGrant,
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
	TestAuthorization(t)

	for i, v := range authorizationCodeCases {
		url := issuer + "/token"
		r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(v.vals.Encode()))
		if i != 0 { // not form data
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if i != 1 { // no client auth
			r.SetBasicAuth("test_client_id", "aabbccdd")
		}
		w := httptest.NewRecorder()

		resp := protocol.NewResponse()
		req := server.HandleTokenRequest(resp, r)
		assertExpectedEqualError(t, v.expected, resp.ErrCode)

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
	TestAuthorization(t)

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
		assertExpectedEqualError(t, v.expected, resp.ErrCode)

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

func assertExpectedEqualError(t *testing.T, expected, errcode error) {
	if expected == nil && errcode != nil {
		t.Fatalf("expected: %v, but got: %v", expected, errcode)
	}
	if expected != nil && errcode == nil {
		t.Fatalf("expected: %v, but got: %v", expected, errcode)
	}
	if expected != nil && errcode != nil {
		if expected.(protocol.Error).ErrorCode != errcode.(protocol.Error).ErrorCode {
			t.Fatalf("expected: %v, but got: %v", expected, errcode)
		}
	}
}
