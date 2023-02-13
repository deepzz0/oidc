// Package main provides ...
package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/deepzz0/oidc/protocol"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// oauth2cofig
var oauth2Config = oauth2.Config{
	ClientID:     "test_client_id",
	ClientSecret: "aabbccdd",
	RedirectURL:  "http://localhost:8090/oidc/callback",
	Scopes:       []string{"openid", "phone", "email"},
}
var (
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
)

func init() {
	var err error
	provider, err = oidc.NewProvider(context.Background(), "http://localhost:8080/oidc")
	if err != nil {
		panic(err)
	}
	oauth2Config.Endpoint = provider.Endpoint()
	verifier = provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})
}

func main() {
	e := gin.Default()

	e.GET("/homepage", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.Writer.WriteString(`
<iframe id="inlineFrameExample"
    title="Inline Frame Example"
    width="300"
    height="200"
	src="http://localhost:8080/oidc/check-session">
</iframe>
		`)
	})

	oidc := e.Group("/oidc")
	{
		oidc.GET("/auth-url", handleOIDCAuthURL)
		oidc.GET("/callback", handleOIDCCallback)
	}

	e.Run(":8090")
}

func handleOIDCAuthURL(c *gin.Context) {
	url := oauth2Config.AuthCodeURL("test")
	c.Redirect(http.StatusFound, url)
}

func handleOIDCCallback(c *gin.Context) {
	if c.Query("error") != "" {
		c.String(http.StatusBadRequest, c.Query("error_description"))
		return
	}
	oauth2Token, err := oauth2Config.Exchange(context.Background(), c.Query("code"))
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	idToken := oauth2Token.Extra("id_token").(string)

	token, err := verifier.Verify(context.Background(), idToken)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	fmt.Println(token.Audience)
	fmt.Println(oauth2Token.AccessToken)

	// userinfo
	source := oauth2Config.TokenSource(context.Background(), oauth2Token)
	userInfo, err := provider.UserInfo(context.Background(), source)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	ui := protocol.UserInfo{}
	err = userInfo.Claims(&ui)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	fmt.Printf("%#v   %s\n", ui, ui.MapClaims["test_clams"])
}
