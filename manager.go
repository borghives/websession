package websession

import (
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var WEB_SESSION_TTL = time.Hour * 12

// SessionManager centralizes configuration and behavior for websessions
type SessionManager struct {
	Secret         string
	Domain         string
	CookieName     string
	TTL            time.Duration
	TrustedProxies []string
	SkipClientHash bool // Allows disabling strict User-Agent validation
}

// Session Manager creates a new session manager
func Manager() *SessionManager {
	constants := CollapseConstants()
	secret := constants.SecretSession
	domain := constants.SiteDomain
	if secret == "" {
		log.Fatal("missing secret for SessionManager")
	}
	if domain == "" {
		log.Fatal("missing domain for SessionManager")
	}

	proxies := []string{"127.0.0.1", "::1", "localhost"}
	if os.Getenv("K_SERVICE") != "" {
		// Automatically trust the environment if running securely inside Cloud Run
		proxies = append(proxies, "*")
	}

	return &SessionManager{
		Secret:         secret,
		Domain:         domain,
		CookieName:     "session",
		TTL:            WEB_SESSION_TTL,
		TrustedProxies: proxies,
	}
}

func (m *SessionManager) CreateSession(r *http.Request) *Session {
	return NewWebSession(m.GetRealIPFromRequest(r), GetClientSignature(r))
}

func (m *SessionManager) EncodeSession(session Session) (string, error) {
	encodedBytes, err := bson.Marshal(session)
	if err != nil {
		return "", err
	}
	return EncryptMessage(m.Secret, encodedBytes)
}

func (m *SessionManager) DecodeSession(encodedSession string) (*Session, error) {
	decodedBytes, err := DecryptMessage(m.Secret, encodedSession)
	if err != nil {
		return nil, err
	}
	var session Session
	err = bson.Unmarshal(decodedBytes, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// isTrustedProxy checks if an IP is in the proxy trusted list (or wildcard)
func (m *SessionManager) isTrustedProxy(ip string) bool {
	for _, proxy := range m.TrustedProxies {
		if proxy == "*" || proxy == ip {
			return true
		}
	}
	return false
}

func (m *SessionManager) GetRealIPFromRequest(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr // fallback
	}

	if m.isTrustedProxy(remoteIP) {
		xForwardedFor := r.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			parts := strings.Split(xForwardedFor, ",")
			// In GCP Cloud Run, the Google Front End (GFE) appends the true client IP
			// securely to the end. Therefore, we should extract the right-most element
			// rather than parts[0], which could be maliciously spoofed by headers.
			return strings.TrimSpace(parts[len(parts)-1])
		}

		xRealIP := r.Header.Get("X-Real-IP")
		if xRealIP != "" {
			return strings.TrimSpace(xRealIP)
		}
	}
	return remoteIP
}

func GetClientSignature(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

func (m *SessionManager) NewRequestSession(w http.ResponseWriter, r *http.Request) *Session {
	session := m.CreateSession(r)
	m.SetSessionCookie(w, session)
	return session
}

func (m *SessionManager) RefreshStaleRequestSession(w http.ResponseWriter, r *http.Request) *Session {
	session, err := m.GetAndVerifySession(r)

	if err != nil {
		return m.RefreshRequestSessionFrom(w, r, session)
	}
	return session
}

func (m *SessionManager) RefreshNewRequestSession(w http.ResponseWriter, r *http.Request) *Session {
	session, _ := m.GetAndVerifySession(r)
	return m.RefreshRequestSessionFrom(w, r, session)
}

func (m *SessionManager) RefreshRequestSessionFrom(w http.ResponseWriter, r *http.Request, oldSession *Session) *Session {
	if oldSession == nil {
		return m.NewRequestSession(w, r)
	}

	session := RefreshWebSession(m.GetRealIPFromRequest(r), GetClientSignature(r), oldSession)
	m.SetSessionCookie(w, session)
	return session
}

func (m *SessionManager) ClearRequestSession(w http.ResponseWriter, r *http.Request) *Session {
	return m.RefreshRequestSessionFrom(w, r, nil)
}

func (m *SessionManager) SetSessionCookie(w http.ResponseWriter, session *Session) error {
	encodedSess, err := m.EncodeSession(*session)
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:     m.CookieName,
		Value:    encodedSess,
		Path:     "/",
		Domain:   m.Domain,
		MaxAge:   int(m.TTL.Seconds()),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	return nil
}

func (m *SessionManager) GetRequestSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil {
		return nil, &WebSessionError{
			Message: "no session found; ",
			Code:    SESSION_ERROR_NO_SESSION,
		}
	}

	session, err := m.DecodeSession(cookie.Value)
	if err != nil {
		return nil, &WebSessionError{
			Message: "failed to decode session; ",
			Code:    SESSION_ERROR_DECODING_FAILED,
		}
	}

	clientSignature := GetClientSignature(r)
	clientHash := HashToIdHexString(clientSignature)

	if !m.SkipClientHash {
		if clientHash == session.ClientHash {
			session.ClientSig = clientSignature
		} else {
			err = &WebSessionError{
				Message: "failed to assign client with hash mismatch; ",
				Code:    SESSION_ERROR_CLIENT_MISMATCH,
			}
		}
	} else {
		session.ClientSig = clientSignature
	}

	return session, err
}

func (m *SessionManager) GetAndVerifySession(r *http.Request) (*Session, error) {
	var sessionError *WebSessionError
	session, err := m.GetRequestSession(r)

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

	if session.GetAge() > m.TTL {
		sessionError.Message += "Session expired; "
		sessionError.Code |= SESSION_ERROR_SESSION_EXPIRED
	}

	realip := m.GetRealIPFromRequest(r)
	if realip != string(session.FromIp) {
		sessionError.Message += "IP mismatch; "
		sessionError.Code |= SESSION_ERROR_IP_MISMATCH
	}

	if sessionError.Code == 0 {
		return session, nil
	}

	return session, sessionError
}

// Below are standard export aliases that keep global compatibility.
// These exist so older code doesn't break, they construct/use the DefaultManager().

// func GetRealIPFromRequest(r *http.Request) string {
// 	return Manager().GetRealIPFromRequest(r)
// }
// func EncodeSession(session Session) (string, error) {
// 	return Manager().EncodeSession(session)
// }
// func DecodeSession(encoded string) (*Session, error) {
// 	return Manager().DecodeSession(encoded)
// }
// func GetAndVerifySession(r *http.Request) (*Session, error) {
// 	return Manager().GetAndVerifySession(r)
// }
