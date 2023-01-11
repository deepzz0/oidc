# oidc
Golang OAuth2/OIDC Server Library.

![OpenIDConnect-Map-4Feb2014.png](./assets/OpenIDConnect-Map-4Feb2014.png)

**Our goals:**

- Security.
- KISS.
- Simple API.

### Features

- [x] Authorization Code
- [ ] PKCE
- [x] Client Credentials
- [ ] Device Code
- [x] Refresh Token
- [x] Implicit Flow `Legacy`
- [x] Password Grant `Legacy`
- [ ] Session Management
- [ ] Revocation
- [ ] Request Object
- [ ] JWT Profile
- [ ] Token Exchange
- [ ] SAML2 Bearer
- [x] Hybrid Response Type
- [x] Response Mode Support: `query`, `fragment`,`form_post`

Have fun!

### Building

This library uses Go modules and uses semantic versioning. Building is done with the `go` tool, so the following should work:

```
go get github.com/deepzz0/oidc
```

### Examples

A short "how to use the API" is at the beginning of doc.go (this also will show when you call `godoc github.com/deepzz0/oidc`).

Example programs can be found in the [Examples](https://github.com/deepzz0/oidc/tree/master/examples) repository.

### RFCs

*Try our best, see https://oauth.net/specs/ and  https://openid.net/developers/specs/.*

**OAuth2:**

* [6749](https://www.rfc-editor.org/rfc/rfc6749) - OAuth 2.0 Authorization Framework
* [6750](http://tools.ietf.org/html/rfc6750) - OAuth 2.0 Authorization Framework: Bearer Token Usage
* [6755](https://www.rfc-editor.org/rfc/rfc6755) - An IETF URN Sub-Namespace for OAuth
* [6819](https://www.rfc-editor.org/rfc/rfc6819) - OAuth 2.0 Threat Model and Security Considerations
* [7009](http://tools.ietf.org/html/rfc7009) - OAuth 2.0 Token Revocation
* [7519](https://tools.ietf.org/html/rfc7519) - JSON Web Token (JWT)
* [7521](https://www.rfc-editor.org/rfc/rfc7521.html) - Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants
* [7522](https://www.rfc-editor.org/rfc/rfc7522) - SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants
* [7523](https://www.rfc-editor.org/rfc/rfc7523.html) - JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants
* [7591](https://www.rfc-editor.org/rfc/rfc7591) - OAuth 2.0 Dynamic Client Registration Protocol
* [7592](https://www.rfc-editor.org/rfc/rfc7592) - OAuth 2.0 Dynamic Client Registration Management Protocol
* [7636](http://tools.ietf.org/html/rfc7636) - Proof Key for Code Exchange by OAuth Public Clients `PKCE`
* [7662](https://www.rfc-editor.org/rfc/rfc7662) - OAuth 2.0 Token Introspection
* [7800](https://www.rfc-editor.org/rfc/rfc7800) - Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)
* [8176](https://www.rfc-editor.org/rfc/rfc8176) - Authentication Method Reference Values
* [8252](http://tools.ietf.org/html/rfc8252) - OAuth 2.0 for Native Apps
* [8414](https://www.rfc-editor.org/rfc/rfc8414) - OAuth 2.0 Authorization Server Metadata
* [8628](https://www.rfc-editor.org/rfc/rfc8628) - OAuth 2.0 Device Authorization Grant
* [8693](https://datatracker.ietf.org/doc/html/rfc8693) - OAuth 2.0 Token Exchange
* [8705](https://tools.ietf.org/html/rfc8705) - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
* [8707](https://www.rfc-editor.org/rfc/rfc8707) - Resource Indicators for OAuth 2.0
* [8725](https://www.rfc-editor.org/rfc/rfc8725) - JSON Web Token Best Current Practices
* [9101](https://www.rfc-editor.org/rfc/rfc9101) - The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)
* [9126](https://datatracker.ietf.org/doc/html/rfc9126) - OAuth 2.0 Pushed Authorization Requests
* [9207](https://www.rfc-editor.org/rfc/rfc9207) - OAuth 2.0 Authorization Server Issuer Identification
* [9278](https://www.rfc-editor.org/rfc/rfc9278) - JWK Thumbprint URI
* [9608](https://datatracker.ietf.org/doc/html/rfc9068) - JWT Profile for OAuth 2.0 Access Tokens



* [OAuth Parameters](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml)
* [WebAuthn]([www.w3.org/TR/webauthn](https://www.w3.org/TR/webauthn/))

**OIDC:**

* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
* [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
* [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
* [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
* [OpenID 2.0 to OpenID Connect Migration 1.0](https://openid.net/specs/openid-connect-migration-1_0.html)
* [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
* [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)
* [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
* [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
* [OpenID Connect Core Error Code unmet_authentication_requirements](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html)
* [Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html)

FAPI

* [Financial-grade API Security Profile 1.0 - Part 1: Baseline](https://openid.net/specs/openid-financial-api-part-1-1_0.html)
* [Financial-grade API Security Profile 1.0 - Part 2: Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html)
* [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm.html)

MODRNA

* [OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)

**Optional follow experimental and draft Specs:**

* [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
* [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
* [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop)
* [OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar)
* [OAuth 2.0 Incremental Authorization](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-incremental-authz)
* [OAuth 2.0 Step-up Authentication Challenge Protocol](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-step-up-authn-challenge)
* [OAuth 2.0 Client Discovery](https://www.ietf.org/archive/id/draft-looker-oauth-client-discovery-01.html)
* [OAuth 2.1 Authorization Framework](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-07.html)
* [OAuth 2.0 Step-up Authentication Challenge Protocol](https://www.ietf.org/archive/id/draft-ietf-oauth-step-up-authn-challenge-08.html)
* [JWT Response for OAuth Token Introspection](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response)
* [HTTP Message Signatures](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures)
* [Digest Fields](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-digest-headers)
* [JSON Web Token (JWT) Embedded Tokens](https://www.ietf.org/archive/id/draft-yusef-oauth-nested-jwt-06.html)
* [Cross-Device Flows: Security Best Current Practice](https://www.ietf.org/archive/id/draft-ietf-oauth-cross-device-security-00.html)
* [Selective Disclosure for JWTs (SD-JWT)](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-02.html)

### OAuth 2.1?

See [https://oauth.net/2.1/](https://oauth.net/2.1/).

