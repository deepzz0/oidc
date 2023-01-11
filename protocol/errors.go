// Package protocol provides ...
package protocol

import "fmt"

// Error OAuth2 error codes
type Error struct {
	ErrorCode   string `json:"error" schema:"error"`
	Description string `json:"description" schema:"error_description"`
	State       string `json:"state" schema:"state"`

	statusCode  int
	internalErr error
}

// Error implements error interface
func (e Error) Error() string {
	if e.internalErr != nil {
		return fmt.Sprintf("%s: %s (%v)", e.ErrorCode, e.Description, e.internalErr)
	}
	return e.ErrorCode + ": " + e.Description
}

// Wrap wrap error
func (e Error) Wrap(err error) Error {
	e.internalErr = err
	return e
}

// Desc custom description
func (e Error) Desc(desc string) Error {
	e.Description = desc
	return e
}

// error code list
var (
	// https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1
	ErrInvalidRequest = Error{
		ErrorCode:   "invalid_request",
		Description: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
		statusCode:  400,
	}
	ErrInvalidToken = Error{
		ErrorCode:   "invalid_token",
		Description: "The access token provided is expired, revoked, malformed, or invalid for other reasons.",
		statusCode:  401,
	}
	ErrInsufficientScope = Error{
		ErrorCode:   "insufficient_scope",
		Description: "The request requires higher privileges than provided by the access token.",
		statusCode:  403,
	}
	// https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2.1
	ErrUnsupportedTokenType = Error{
		ErrorCode:   "unsupported_token_type",
		Description: "The authorization server does not support the revocation of the presented token type.",
		statusCode:  400,
	}
	ErrUnauthorizedClient = Error{
		ErrorCode:   "unauthorized_client",
		Description: "The client is not authorized to request a token using this method.",
		statusCode:  401,
	}
	ErrAccessDenied = Error{
		ErrorCode:   "access_denied",
		Description: "The resource owner or authorization server denied the request.",
		statusCode:  403,
	}
	ErrUnsupportedResponseType = Error{
		ErrorCode:   "unsupported_response_type",
		Description: "The authorization server does not support obtaining a token using this method.",
		statusCode:  401,
	}
	ErrInvalidScope = Error{
		ErrorCode:   "invalid_scope",
		Description: "The requested scope is invalid, unknown, or malformed.",
		statusCode:  400,
	}
	ErrServerError = Error{
		ErrorCode:   "server_error",
		Description: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		statusCode:  500,
	}
	ErrTemporarilyUnavailable = Error{
		ErrorCode:   "temporarily_unavailable",
		Description: "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
		statusCode:  503,
	}
	ErrUnsupportedGrantType = Error{
		ErrorCode:   "unsupported_grant_type",
		Description: "The authorization grant type is not supported by the authorization server.",
		statusCode:  401,
	}
	ErrInvalidGrant = Error{
		ErrorCode:   "invalid_grant",
		Description: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
		statusCode:  401,
	}
	ErrInvalidClient = Error{
		ErrorCode:   "invalid_client",
		Description: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
		statusCode:  401,
	}
	// Device Access Token Response
	// https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
	ErrAuthorizationPending = Error{
		ErrorCode:   "authorization_pending",
		Description: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.",
		statusCode:  400,
	}
	ErrSlowDown = Error{
		ErrorCode:   "slow_down",
		Description: "the authorization request is still pending and polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.",
		statusCode:  400,
	}
	ErrExpiredToken = Error{
		ErrorCode:   "expired_token",
		Description: "The device_code has expired, and the device authorization session has concluded.",
		statusCode:  400,
	}
	// https://www.rfc-editor.org/rfc/rfc8707.html#name-resource-parameter
	ErrInvalidTarget = Error{
		ErrorCode:   "invalid_target",
		Description: "The requested resource is invalid, missing, unknown, or malformed.",
		statusCode:  400,
	}
	// https://www.rfc-editor.org/rfc/rfc9200.html#section-5.8.3
	ErrUnsupportedPopKey = Error{
		ErrorCode:   "unsupported_pop_key",
		Description: "The client submits an asymmetric key in the token request that the RS cannot process.",
		statusCode:  400,
	}
	ErrIncompatibleAceProfiles = Error{
		ErrorCode:   "incompatible_ace_profiles",
		Description: "The client and the RS it has requested an access token for do not share a common profile.",
		statusCode:  400,
	}
	// https://datatracker.ietf.org/doc/draft-ietf-oauth-rar/22/
	ErrInvalidAuthorizationDetails = Error{
		ErrorCode:   "invalid_authorization_details",
		Description: "Unknown authorization details type or authorization details not conforming to the respective type definition.",
		statusCode:  400,
	}
	// Authentication Error Response
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
	ErrInteractionRequired = Error{
		ErrorCode:   "interaction_required",
		Description: "The Authorization Server requires End-User interaction of some form to proceed, but prompt is none.",
		statusCode:  400,
	}
	ErrLoginRequired = Error{
		ErrorCode:   "login_required",
		Description: "The Authorization Server requires End-User authentication.",
		statusCode:  400,
	}
	ErrAccountSelectionRequired = Error{
		ErrorCode:   "account_selection_required",
		Description: "The End-User is REQUIRED to select a session at the Authorization Server.",
		statusCode:  400,
	}
	ErrConsentRequired = Error{
		ErrorCode:   "consent_required",
		Description: "The Authorization Server requires End-User consent.",
		statusCode:  400,
	}
	ErrInvalidRequestURI = Error{
		ErrorCode:   "invalid_request_uri",
		Description: "The request_uri in the Authorization Request returns an error or contains invalid data.",
		statusCode:  400,
	}
	ErrInvalidRequestObject = Error{
		ErrorCode:   "invalid_request_object",
		Description: "The request parameter contains an invalid Request Object.",
		statusCode:  400,
	}
	ErrRequestNotSupported = Error{
		ErrorCode:   "request_not_supported",
		Description: "Does not support use of the request parameter",
		statusCode:  400,
	}
	ErrRequestURINotSupported = Error{
		ErrorCode:   "request_uri_not_supported",
		Description: "Does not support use of the request_uri parameter",
		statusCode:  400,
	}
	ErrRegistrationNotSupported = Error{
		ErrorCode:   "registration_not_supported",
		Description: "Does not support use of the registration parameter",
		statusCode:  400,
	}
)
