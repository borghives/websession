package websession

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyGoodSession(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "localhost")

	setNewRequestSession(w, GetRealIPFromRequest(r), GetClientSignature(r))
	r.AddCookie(w.Result().Cookies()[0])
	_, err := GetAndVerifySession(r)
	if err != nil {
		t.Errorf("Expected no error but got %s", err)
	}

}

func TestVerifyMissMatchIPSession(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "localhost")

	setNewRequestSession(w, "1234", GetClientSignature(r))
	r.AddCookie(w.Result().Cookies()[0])
	_, err := GetAndVerifySession(r)
	if err == nil {
		t.Errorf("Expected error but got none")
	}

	var sessionError *WebSessionError
	errors.As(err, &sessionError)
	if sessionError.Code&SESSION_ERROR_IP_MISMATCH == 0 {
		t.Errorf("Expected ip mismatch status code %x but got %x", SESSION_ERROR_IP_MISMATCH, sessionError.Code)
	}
}
