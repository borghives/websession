package websession

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyGoodSession(t *testing.T) {
	manager := getTestManager()
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:80"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "localhost")

	manager.NewRequestSession(w, r)
	r.AddCookie(w.Result().Cookies()[0])
	_, err := manager.GetAndVerifySession(r)
	if err != nil {
		t.Errorf("Expected no error but got %s", err)
	}
}

func TestVerifyMissMatchIPSession(t *testing.T) {
	manager := getTestManager()
	w := httptest.NewRecorder()
	
	// Original Request
	r1, _ := http.NewRequest("GET", "/", nil)
	r1.RemoteAddr = "127.0.0.1:80"
	r1.Header.Set("X-Forwarded-For", "1.2.3.4")
	r1.Header.Set("X-Real-IP", "localhost")
	
	manager.NewRequestSession(w, r1)
	
	// Malicious/Mismatched Request
	r2, _ := http.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "127.0.0.1:80"
	r2.Header.Set("X-Forwarded-For", "5.6.7.8")
	r2.Header.Set("X-Real-IP", "localhost")
	r2.AddCookie(w.Result().Cookies()[0])

	_, err := manager.GetAndVerifySession(r2)
	if err == nil {
		t.Errorf("Expected error but got none")
	}

	var sessionError *WebSessionError
	if !errors.As(err, &sessionError) {
		t.Fatalf("Expected WebSessionError but got %T: %v", err, err)
	}
	if sessionError == nil {
		t.Fatalf("sessionError is nil")
	}
	
	if sessionError.Code&SESSION_ERROR_IP_MISMATCH == 0 {
		t.Errorf("Expected ip mismatch status code %x but got %x", SESSION_ERROR_IP_MISMATCH, sessionError.Code)
	}

	// Test the new errors.Is logic
	if !errors.Is(err, &WebSessionError{Code: SESSION_ERROR_IP_MISMATCH}) {
		t.Errorf("Expected errors.Is to match IP mismatched error")
	}
}
