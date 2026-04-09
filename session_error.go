package websession

import (
	"fmt"
)

const (
	SESSION_ERROR_NONE            = 0
	SESSION_ERROR_NO_SESSION      = 1 << 1
	SESSION_ERROR_DECODING_FAILED = 1 << 2
	SESSION_ERROR_SESSION_EXPIRED = 1 << 3
	SESSION_ERROR_IP_MISMATCH     = 1 << 4
	SESSION_ERROR_CLIENT_MISMATCH = 1 << 5
)

type WebSessionError struct {
	Message string
	Code    int
}

func (e *WebSessionError) Error() string {
	return fmt.Sprintf("Error 0x%X: %s", e.Code, e.Message)
}

// Is supports errors.Is for Go 1.13+ error unwrapping.
// It matches if the target is a WebSessionError and the bits align.
func (e *WebSessionError) Is(target error) bool {
	t, ok := target.(*WebSessionError)
	if !ok {
		return false
	}
	if t.Code == SESSION_ERROR_NONE && e.Code == SESSION_ERROR_NONE {
		return true
	}
	// Check if all of target's bits are set in e
	return (e.Code & t.Code) == t.Code
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
