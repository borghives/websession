package websession

import (
	"errors"
	"fmt"
	"net/http"
)

var SESSION_ERROR_NONE = 0
var SESSION_ERROR_NO_SESSION = 1 << 1
var SESSION_ERROR_DECODING_FAILED = 1 << 2
var SESSION_ERROR_SESSION_EXPIRED = 1 << 3
var SESSION_ERROR_IP_MISMATCH = 1 << 4
var SESSION_ERROR_CLIENT_MISMATCH = 1 << 4

type WebSessionError struct {
	Message string
	Code    int
}

func (e *WebSessionError) Error() string {
	return fmt.Sprintf("Error 0x%X: %s", e.Code, e.Message)
}

func (e *WebSessionError) HasNoSession() bool {
	return (e.Code & SESSION_ERROR_NO_SESSION) != 0
}

func (e *WebSessionError) DecodingFailed() bool {
	return (e.Code & SESSION_ERROR_DECODING_FAILED) != 0
}

func (e *WebSessionError) SessionExpired() bool {
	return (e.Code & SESSION_ERROR_SESSION_EXPIRED) != 0
}

func (e *WebSessionError) IpMismatch() bool {
	return (e.Code & SESSION_ERROR_IP_MISMATCH) != 0
}

func (e *WebSessionError) ClientMismatch() bool {
	return (e.Code & SESSION_ERROR_CLIENT_MISMATCH) != 0
}

// VerifySession verifies that the session is valid

func GetAndVerifySession(r *http.Request) (*WebSession, error) {
	// Get the session from the request
	var sessionError *WebSessionError
	session, err := GetRequestSession(r)

	if err != nil {
		errors.As(err, &sessionError)
	}

	if sessionError == nil {
		sessionError = &WebSessionError{}
	}

	if session == nil {
		sessionError.Message += "Session Empty; "
		sessionError.Code |= SESSION_ERROR_NO_SESSION
		return session, sessionError
	}

	// Check if the session is valid

	if session.GetAge() > WEB_SESSION_TTL {
		sessionError.Message += "Session expired; "
		sessionError.Code |= SESSION_ERROR_SESSION_EXPIRED
	}

	// realip := GetRealIPFromRequest(r)
	// if realip != string(session.FromIp) {
	// 	sessionError.Message += "IP mismatch; "
	// 	sessionError.Code |= SESSION_ERROR_IP_MISMATCH
	// }

	client := GetClientSignature(r)
	clientHash := HashToIdHexString(client)
	if clientHash != session.ClientHash {
		sessionError.Message += "Client mismatch; "
		sessionError.Code |= SESSION_ERROR_CLIENT_MISMATCH
	}

	if sessionError.Code == 0 {
		return session, nil
	}

	return session, sessionError
}
