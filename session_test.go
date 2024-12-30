package websession

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestNewWebSession(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "localhost")
	session := newWebSession(GetRealIPFromRequest(r), GetClientSignature(r))
	if session.ID == primitive.NilObjectID {
		t.Errorf("NewWebSession: expected session ID to be non-nil")
	}
	if session.GenerateTime.IsZero() {
		t.Errorf("NewWebSession: expected session GenerateTime to be non-zero")
	}

	if !session.GenerateFrom.IsZero() {
		t.Errorf("NewWebSession: expected session GenerateFrom to be zero")
	}
	if session.FirstTime.IsZero() {
		t.Errorf("NewWebSession: expected session FirstTime to be non-zero")
	}

}

func TestRefreshWebSession(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "localhost")

	session := newWebSession(GetRealIPFromRequest(r), GetClientSignature(r))
	newSession := refreshWebSession(GetRealIPFromRequest(r), GetClientSignature(r), session)
	if newSession.ID == session.ID {
		t.Errorf("RefreshWebSession: expected new session ID to be different from old session ID")
	}
	if newSession.GenerateTime.IsZero() {
		t.Errorf("RefreshWebSession: expected new session GenerateTime to be non-zero")
	}

	if newSession.GenerateFrom != session.ID {
		t.Errorf("RefreshWebSession: expected new session GenerateFrom to be old session ID")
	}
	if newSession.FirstTime != session.FirstTime {
		t.Errorf("RefreshWebSession: expected new session FirstTime to be old session FirstTime")
	}

}

func TestEncodeSession(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	session := newWebSession(GetRealIPFromRequest(r), GetClientSignature(r))
	encodedSession, err := EncodeSession(*session)
	if err != nil {
		t.Errorf("EncodeSession: expected no error, got %v", err)
	}
	if encodedSession == "" {
		t.Errorf("EncodeSession: expected encoded session to be non-empty")
	}
}

func TestDecodeSession(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "localhost")

	session := newWebSession(GetRealIPFromRequest(r), GetClientSignature(r))
	encodedSession, err := EncodeSession(*session)
	if err != nil {
		t.Errorf("EncodeSession: expected no error, got %v", err)
	}
	decodedSession, err := DecodeSession(encodedSession)
	if err != nil {
		t.Errorf("DecodeSession: expected no error, got %v", err)
	}
	if decodedSession.ID != session.ID {
		t.Errorf("DecodeSession: expected decoded session ID to be equal to original session ID")
	}
	if decodedSession.GenerateTime.Sub(session.GenerateTime).Seconds() > 0 {
		t.Errorf("DecodeSession: expected decoded session GenerateTime to be equal to original session GenerateTime %s %s", decodedSession.GenerateTime.UTC().String(), session.GenerateTime.UTC().String())
	}

	if decodedSession.GenerateFrom != session.GenerateFrom {
		t.Errorf("DecodeSession: expected decoded session GenerateFrom to be equal to original session GenerateFrom")
	}
	if decodedSession.FirstTime.Sub(session.FirstTime).Seconds() > 0 {
		t.Errorf("DecodeSession: expected decoded session FirstTime to be equal to original session FirstTime")
	}

}

// Test client signature in session
func TestClientSignatureInSessionRequest(t *testing.T) {
	userAgentStr := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "localhost")
	r.Header.Set("User-Agent", userAgentStr)
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")

	w := httptest.NewRecorder()
	createdSession := setNewRequestSession(w, GetRealIPFromRequest(r), GetClientSignature(r))

	r.AddCookie(w.Result().Cookies()[0])
	returnedSession, err := GetAndVerifySession(r)
	if err != nil {
		t.Errorf("Expected no error but got %s", err)
	}

	if returnedSession.ID != createdSession.ID {
		t.Errorf("Expected returned session ID to be equal to created session ID")
	}

	if returnedSession.ClientHash != createdSession.ClientHash {
		t.Errorf("Expected returned session ClientHash to be equal to created session ClientHash.  Got: %s Expected: %s", returnedSession.ClientHash, createdSession.ClientHash)
	}

	if returnedSession.ClientSig != userAgentStr {
		t.Errorf("Expected returned session ClientSig to be equal to created session ClientSig.  Got: %s Expected: %s", returnedSession.ClientSig, userAgentStr)
	}

	if returnedSession.GenerateFrom != createdSession.GenerateFrom {
		t.Errorf("Expected returned session GenerateFrom to be equal to created session GenerateFrom")
	}

	badRequest, _ := http.NewRequest("GET", "/", nil)
	badRequest.Header.Set("X-Forwarded-For", "1.2.3.4")
	badRequest.Header.Set("X-Real-IP", "localhost")
	badRequest.Header.Set("User-Agent", "badUserAgent")
	badRequest.Header.Set("Accept-Language", "en-US,en;q=0.9")
	badRequest.AddCookie(w.Result().Cookies()[0])

	returnedSessionFromBadUserAgent, err := GetAndVerifySession(badRequest)
	if err == nil {
		t.Errorf("Expected error but got none")
	}

	sessionError, ok := err.(*WebSessionError)
	if !ok {
		t.Errorf("Expected WebSessionError but got %T", err)
	}

	if !sessionError.ClientMismatch() {
		t.Errorf("Expected client mismatch error but got %s", sessionError.Error())
	}

	if returnedSessionFromBadUserAgent.ClientHash != createdSession.ClientHash {
		t.Errorf("Expected returned session ClientHash to be equal to created session ClientHash.  Got: %s Expected: %s", returnedSession.ClientHash, createdSession.ClientHash)
	}

	if returnedSessionFromBadUserAgent.ClientSig != "" {
		t.Errorf("Expected returned session ClientSig to be empty but got %s", returnedSessionFromBadUserAgent.ClientSig)
	}

}

func TestSetNewRequestSession(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "localhost")

	createdSession := setNewRequestSession(w, GetRealIPFromRequest(r), GetClientSignature(r))

	// Check that the cookie was set
	cookies := w.Header().Get("Set-Cookie")
	if cookies == "" {
		t.Errorf("setNewRequestSession: expected cookie to be set")
	}

	// Check that the cookie value is valid
	parts := strings.Split(cookies, ";")
	if len(parts) <= 2 {
		t.Errorf("setNewRequestSession: expected cookie to have more than 2 parts")
	}
	cookieValue := strings.TrimPrefix(parts[0], "session=")

	if cookieValue == "" {
		t.Errorf("setNewRequestSession: expected cookie value to be non-empty")
	}

	// Decode the cookie value
	session, err := DecodeSession(cookieValue)
	if err != nil {
		t.Errorf("setNewRequestSession: expected no error when decoding cookie value, got %v", err)
	}

	if session != nil {
		// Check that the session is valid
		if session.ID == primitive.NilObjectID {
			t.Errorf("setNewRequestSession: expected session ID to be non-nil")
		}
		if session.GenerateTime.IsZero() {
			t.Errorf("setNewRequestSession: expected session GenerateTime to be non-zero")
		}

		if session.GenerateFrom != primitive.NilObjectID {
			t.Errorf("setNewRequestSession: expected session GenerateFrom to be nil")
		}
		if session.FirstTime.IsZero() {
			t.Errorf("setNewRequestSession: expected session FirstTime to be non zero")
		}

		if createdSession.ID != session.ID {
			t.Errorf("setNewRequestSession: expected created session ID to be equal to decoded session ID")
		}

		if createdSession.GenerateTime.Sub(session.GenerateTime).Seconds() > 1 {
			t.Errorf("setNewRequestSession: expected created session GenerateTime to be equal to decoded session GenerateTime diff: %f", session.GenerateTime.Sub(session.GenerateTime).Seconds())
		}

		if createdSession.GenerateFrom != session.GenerateFrom {
			t.Errorf("GenerateFrom not the same")
		}
	}
}
