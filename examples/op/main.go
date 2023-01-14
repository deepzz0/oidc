// Package main provides ...
package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/deepzz0/oidc"
	"github.com/deepzz0/oidc/examples"
	"github.com/deepzz0/oidc/protocol"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/square/go-jose.v2"
)

var (
	issuer = "http://localhost:8080/oidc"
	server = oidc.NewServer(
		oidc.WithIssuer(issuer),
		oidc.WithStorage(examples.NewTestStorage()),
		oidc.WithDefaultScopes([]string{protocol.ScopeEmail}),
		oidc.WithSession(&examples.TestSession{}),
	)
)

func main() {
	e := gin.Default()

	oidc := e.Group("/oidc", func(c *gin.Context) {
		c.Set("clientid", "1234")
	})
	{
		oidc.GET("/.well-known/openid-configuration", handleOIDCDiscovery)
		oidc.GET("/jwks.json", handleOIDCJwksJSON)
		oidc.GET("/authorize", handleOIDCAuthorize)
		oidc.POST("/token", handleOIDCToken)
		oidc.GET("/userinfo", handleOIDCUserInfo)
		oidc.GET("/check-session", handleCheckSession)
		oidc.GET("/end-session", handleOIDCEndSession)
		oidc.GET("/revocation", handleOIDCRevocation)
	}
	e.Run(":8080")
}

func handleOIDCDiscovery(c *gin.Context) {
	// For other example see: https://accounts.google.com/.well-known/openid-configuration
	// https://openid.net/specs/openid-connect-discovery-1_0.html
	config := protocol.Configuration{
		Issuer:                      issuer,
		JwksURI:                     issuer + "/jwks.json",
		AuthorizationEndpoint:       issuer + "/authorize",
		TokenEndpoint:               issuer + "/token",
		UserinfoEndpoint:            issuer + "/userinfo",
		CheckSessionIframe:          issuer + "/check-session",
		EndSessionEndpoint:          issuer + "/end-session",
		RevocationEndpoint:          issuer + "/revocation",
		DeviceAuthorizationEndpoint: issuer + "/device-code",

		ResponseTypesSupported: []protocol.ResponseType{
			protocol.ResponseTypeCode,
			protocol.ResponseTypeToken,
			protocol.ResponseTypeIDToken,
			protocol.ResponseTypeCodeToken,
			protocol.ResponseTypeCodeIDToken,
			protocol.ResponseTypeTokenIDToken,
			protocol.ResponseTypeCodeTokenIDToken,
			protocol.ResponseTypeNone,
		},
		IDTokenSigningAlgValuesSupported: []string{jwt.SigningMethodRS256.Name},
		ScopesSupported: []protocol.Scope{
			protocol.ScopeOpenID,
			protocol.ScopeEmail,
			protocol.ScopeProfile,
			protocol.ScopeOfflineAccess,
		},
		TokenEndpointAuthMethodsSupported: []protocol.ClientAuthMethod{
			protocol.ClientAuthMethodSecretPost,
			protocol.ClientAuthMethodSecretBasic,
		},
		ClaimsSupported: []string{
			"aud",
			"email",
			"email_verified",
			"exp",
			"family_name",
			"given_name",
			"iat",
			"iss",
			"locale",
			"name",
			"picture",
			"sub",
		},
		CodeChallengeMethodsSupported: []protocol.CodeChallengeMethod{
			protocol.CodeChallengeMethodS256,
			protocol.CodeChallengeMethodPlain,
		},
		GrantTypesSupported: []protocol.GrantType{
			protocol.GrantTypeAuthorizationCode,
			protocol.GrantTypePassword,
			protocol.GrantTypeRefreshToken,
			protocol.GrantTypeImplicit,
			protocol.GrantTypeDeviceCode,
			protocol.GrantTypeJwtBearer,
		},
		SubjectTypesSupported: []protocol.SubjectType{
			protocol.SubjectTypePublic,
		},
	}
	c.JSON(http.StatusOK, config)
}

func handleOIDCJwksJSON(c *gin.Context) {
	pubKey := examples.Signer.Public()
	pkey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Println(err)
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	h := sha1.Sum(pkey)
	kid := hex.EncodeToString(h[:])
	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       pubKey,
				Algorithm: jwt.SigningMethodRS256.Name,
				Use:       "sig",
				KeyID:     kid,
			},
		},
	}
	c.JSON(http.StatusOK, keySet)
}

func handleOIDCAuthorize(c *gin.Context) {
	resp := protocol.NewResponse()
	if req := server.HandleAuthorizeRequest(resp, c.Request); req != nil {
		// TODO 判断是否登录，未登录重定向到登录页面

		req.UserID = "1234"
		fmt.Println("authorized ", req.UserID)
		server.FinishAuthorizeRequest(resp, c.Request, req)
	}
	if resp.ErrCode != nil {
		log.Println(resp.ErrCode)
	}
	protocol.OutputJSON(resp, c.Writer, c.Request)
}

func handleOIDCToken(c *gin.Context) {
	resp := protocol.NewResponse()
	if req := server.HandleTokenRequest(resp, c.Request); req != nil {
		fmt.Println(req.UserID)
		// if grant_type == passord, should authenticate user
		if req.GrantType == protocol.GrantTypePassword {
			// validate username and password
			if req.Username == "1234" && req.Password == "4321" {
				req.UserID = "1234"
			}
		}
		server.FinishTokenRequest(resp, c.Request, req)
	}
	if resp.ErrCode != nil {
		fmt.Println("ERROR: ", resp.ErrCode)
	}
	protocol.OutputJSON(resp, c.Writer, c.Request)
}

func handleOIDCUserInfo(c *gin.Context) {
	resp := protocol.NewResponse()
	if req := server.HandleUserInfoRequest(resp, c.Request); req != nil {
		server.FinishUserInfoRequest(resp, c.Request, req)
	}
	if resp.ErrCode != nil {
		fmt.Println("ERROR: ", resp.ErrCode)
	}
	protocol.OutputJSON(resp, c.Writer, c.Request)
}

func handleCheckSession(c *gin.Context) {
	resp := protocol.NewResponse()
	if req := server.HandleCheckSessionEndpoint(resp, c.Request); req != nil {
		server.FinishCheckSessionRequest(resp, c.Writer, req)
	}
	if resp.ErrCode != nil {
		fmt.Println("ERROR: ", resp.ErrCode)
	}
	protocol.OutputHTML(resp, c.Writer, c.Request)
}

func handleOIDCEndSession(c *gin.Context) {

}

func handleOIDCRevocation(c *gin.Context) {

}

func handleOIDCDeviceCode(c *gin.Context) {

}
