// Package oidc provides ...
package oidc

import "github.com/deepzz0/oidc/protocol"

// BasicAuth http basic auth
type BasicAuth struct {
	Username string
	Password string
}

// TokenType access token type
type TokenType string

// token type list
const (
	TokenTypeBearer = "Bearer"
	TokenTypeJWT    = "JWT"
)

// Option custon option
type Option func(opts *Options)

// Options oidc server options
type Options struct {
	Issuer string

	// Token type access: default Bearer
	TokenType TokenType
	// If true allows client secret algo in params: default false
	AllowClientSecretInParams bool
	// If true allows access request using GET, else only POST: default false
	AllowGetAccessRequest bool
	// Separator to support multiple URIs in Client.RedirectURI()
	RedirectURISeparator string
	// ForcePKCEForPublicClients  authoorize_code flow must be PKCE
	ForcePKCEForPublicClients bool
	// Supported request object
	SupportedRequestObject bool
	// Retain token after refresh
	RetainTokenAfrerRefresh bool

	Storage protocol.Storage
}

// WithIssuer specify the issuer for jwt
func WithIssuer(iss string) Option {
	return func(opts *Options) {
		opts.Issuer = iss
	}
}

// WithTokenType change default: Bearer to anothor
func WithTokenType(ty TokenType) Option {
	return func(opts *Options) {
		opts.TokenType = ty
	}
}

// WithAllowClientSecretInParams whether client secret also in params
func WithAllowClientSecretInParams(allow bool) Option {
	return func(opts *Options) {
		opts.AllowClientSecretInParams = allow
	}
}

// WithAllowGetAccessRequest whether access request using GET
func WithAllowGetAccessRequest(allow bool) Option {
	return func(opts *Options) {
		opts.AllowGetAccessRequest = allow
	}
}

// WithRedirectURISeparator separator to support multiple URIs
func WithRedirectURISeparator(s string) Option {
	return func(opts *Options) {
		opts.RedirectURISeparator = s
	}
}

// WithForcePKCEForPublicClients PKCE for public clients
func WithForcePKCEForPublicClients(force bool) Option {
	return func(opts *Options) {
		opts.ForcePKCEForPublicClients = force
	}
}

// WithSupportedRequestObject the authorize request obj
func WithSupportedRequestObject(s bool) Option {
	return func(opts *Options) {
		opts.SupportedRequestObject = s
	}
}

// WithRetainTokenAfterRefresh retain token afrer refresh until expired
func WithRetainTokenAfterRefresh(s bool) Option {
	return func(opts *Options) {
		opts.RetainTokenAfrerRefresh = s
	}
}

// WithStorage implements protocol.Storage object
func WithStorage(storage protocol.Storage) Option {
	return func(opts *Options) {
		opts.Storage = storage
	}
}
