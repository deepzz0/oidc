// Package oidc provides ...
package oidc

import (
	"strings"
	"testing"

	"github.com/deepzz0/oidc/examples"
	"github.com/deepzz0/oidc/protocol"
)

var cli protocol.Client

func init() {
	storage := examples.NewTestStorage()
	var err error
	cli, err = storage.Client("test_client_id")
	if err != nil {
		panic(err)
	}
}

func TestValidateScopes(t *testing.T) {
	testcases := [][]string{
		{ // all
			protocol.ScopeProfile,
			protocol.ScopeEmail,
			protocol.ScopeAddress,
			protocol.ScopePhone,
			protocol.ScopeOfflineAccess,
			protocol.ScopeOpenID,
		},
		{ // ignore unknown
			protocol.ScopeProfile,
			"scope1",
			"scope2",
		},
		{}, // default scope
		{ // ignore offline_access
			protocol.ScopeOfflineAccess,
			protocol.ScopeProfile,
		},
		{
			protocol.ScopeOfflineAccess,
		},
	}
	for i, v := range testcases {
		var (
			respTypeCode bool
			prompt       []string
		)
		if i == 4 {
			respTypeCode = true
			prompt = []string{
				"consent",
			}
		}
		scope, openid, offline := ValidateScopes(cli, v, []string{"scope3"}, respTypeCode, prompt)
		t.Log(scope, openid, offline)
	}
}

func TestValidateResponseType(t *testing.T) {
	testcases := []protocol.ResponseType{
		protocol.ResponseTypeCode,
		protocol.ResponseTypeToken,
		protocol.ResponseTypeIDToken,
		protocol.ResponseTypeNone,
		protocol.ResponseTypeDevice,

		protocol.ResponseTypeCodeToken,
		protocol.ResponseTypeCodeIDToken,
		protocol.ResponseTypeTokenIDToken,
		protocol.ResponseTypeCodeTokenIDToken,

		"token code",
	}
	for _, v := range testcases {
		types := strings.Fields(string(v))
		typeOK, err := ValidateResponseType(cli, types)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(typeOK)
	}
}
