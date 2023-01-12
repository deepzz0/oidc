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
		{
			protocol.ScopeProfile,
			protocol.ScopeEmail,
			protocol.ScopeAddress,
			protocol.ScopePhone,
			protocol.ScopeOfflineAccess,
			protocol.ScopeOpenID,
		},
		{
			protocol.ScopeProfile,
			protocol.ScopeOfflineAccess,
			"scope1",
			"scope2",
		},
		{},
	}
	for _, v := range testcases {
		scope, openid := ValidateScopes(cli, v, []string{"scope3"})
		t.Log(scope, openid)
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
