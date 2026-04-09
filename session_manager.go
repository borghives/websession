package websession

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/borghives/kosmos-go"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var WEB_SESSION_TTL = time.Hour * 12

type Session struct {
	kosmos.BaseModel `bson:",inline" kosmos:"session_info"`
	FromIp           string        `xml:"-" json:"-" bson:"ip"`
	GenerateTime     time.Time     `xml:"-" json:"-" bson:"gen_tm"`
	GenerateFrom     bson.ObjectID `xml:"-" json:"-" bson:"gen_frm"`
	FirstID          bson.ObjectID `xml:"-" json:"-" bson:"frst_id"`
	FirstTime        time.Time     `xml:"-" json:"-" bson:"frst_tm"`
	UserId           bson.ObjectID `xml:"-" json:"-" bson:"user_id,omitempty"`
	UserName         string        `xml:"-" json:"-" bson:"user_name,omitempty"`
	SecretToken      string        `xml:"-" json:"-" bson:"secret_token"`
	ClientHash       string        `xml:"-" json:"-" bson:"client_hash"`
	ClientSig        string        `xml:"-" json:"-" bson:"-"` // Not encoded in BSON due to tag
}

// SessionManager centralizes configuration and behavior for websessions
type SessionManager struct {
	Secret         string
	Domain         string
	CookieName     string
	TTL            time.Duration
	TrustedProxies []string
	SkipClientHash bool // Allows disabling strict User-Agent validation
}

// DefaultManager creates a standard SessionManager using env variables,
// provided for backward compatibility.
func DefaultManager() *SessionManager {
	secret := os.Getenv("SECRET_SESSION")
	if secret == "" {
		log.Fatal("FATAL: CANNOT FIND SECRET_SESSION")
	}
	domain := os.Getenv("SITE_DOMAIN")
	if domain == "" {
		domain = "localhost"
	}
	manager, _ := NewSessionManager(secret, domain)
	return manager
}

// NewSessionManager creates a new session manager
func NewSessionManager(secret string, domain string) (*SessionManager, error) {
	if secret == "" {
		return nil, errors.New("missing secret for SessionManager")
	}
	if domain == "" {
		domain = "localhost"
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
	}, nil
}

func (m *SessionManager) NewWebSession(realIP string, clientSignature string) *Session {
	currentTime := time.Now()
	id := SecureObjectID()
	clientHash := HashToIdHexString(clientSignature)
	return &Session{
		BaseModel: kosmos.BaseModel{
			ID: id,
		},
		FromIp:       realIP,
		GenerateTime: currentTime,
		FirstID:      id,
		FirstTime:    currentTime,
		ClientHash:   clientHash,
		SecretToken:  GetRandomHexString(),
	}
}

func (m *SessionManager) RefreshWebSession(realIP string, clientSignature string, oldSession *Session) *Session {
	clientHash := HashToIdHexString(clientSignature)
	return &Session{
		BaseModel: kosmos.BaseModel{
			ID: SecureObjectID(),
		},
		FromIp:       realIP,
		GenerateTime: time.Now(),
		GenerateFrom: oldSession.ID,
		FirstID:      oldSession.FirstID,
		FirstTime:    oldSession.FirstTime,
		ClientHash:   clientHash,
		SecretToken:  GetRandomHexString(),
	}
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

func (m *SessionManager) SetNewRequestSession(w http.ResponseWriter, realIP string, clientSignature string) *Session {
	session := m.NewWebSession(realIP, clientSignature)
	m.SetSessionCookie(w, session)
	return session
}

func (m *SessionManager) RefreshNewRequestSession(w http.ResponseWriter, realIP string, clientSignature string, oldSession *Session) *Session {
	if oldSession == nil {
		return m.SetNewRequestSession(w, realIP, clientSignature)
	}
	session := m.RefreshWebSession(realIP, clientSignature, oldSession)
	m.SetSessionCookie(w, session)
	return session
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

func (m *SessionManager) RefreshRequestSession(w http.ResponseWriter, r *http.Request) *Session {
	session, err := m.GetAndVerifySession(r)
	if err != nil {
		return m.RefreshNewRequestSession(w, m.GetRealIPFromRequest(r), GetClientSignature(r), session)
	}
	return session
}

func (m *SessionManager) RefreshRequestSessionFromContext(w http.ResponseWriter, r *http.Request) *Session {
	session, _ := m.GetAndVerifySession(r)
	return m.RefreshNewRequestSession(w, m.GetRealIPFromRequest(r), GetClientSignature(r), session)
}

func (m *SessionManager) ClearRequestSession(w http.ResponseWriter, r *http.Request) *Session {
	return m.RefreshNewRequestSession(w, m.GetRealIPFromRequest(r), GetClientSignature(r), nil)
}

func (sess Session) GetAge() time.Duration {
	return time.Since(sess.GenerateTime)
}

func HashToIdHexString(message string) string {
	if message == "" {
		return bson.NilObjectID.Hex()
	}
	idbytes := sha256.Sum256([]byte(message))
	return hex.EncodeToString(idbytes[:12])
}

// GenerateHMACBytes creates a cryptographic map utilizing HMAC to prevent length extension attacks.
func (sess *Session) GenerateHMACBytes(message string) []byte {
	if message == "" {
		message = "0"
	}
	mac := hmac.New(sha256.New, []byte(sess.SecretToken))
	mac.Write([]byte(sess.ID.Hex() + sess.GenerateFrom.Hex() + message))
	return mac.Sum(nil)
}

func (sess *Session) GenerateHexID(message string) string {
	if sess == nil {
		return bson.NilObjectID.Hex()
	}
	idbytes := sess.GenerateHMACBytes(message)
	return string(hex.EncodeToString(idbytes[:12]))
}

func (sess *Session) GenerateSessionToken() string {
	return sess.GenerateHexID("session_token")
}

func (sess *Session) GenerateTokenFromSalt(salt string) string {
	sessToken := sess.GenerateSessionToken()
	return GenerateTokenFromSalt(sessToken, salt)
}

func GenerateSalt(saltSeed string, message string) string {
	return HashToIdHexString(saltSeed + "_-_" + message)
}

func GenerateTokenFromSeed(sessToken string, saltSeed string, message string) string {
	salt := GenerateSalt(saltSeed, message)
	return GenerateTokenFromSalt(sessToken, salt)
}

func GenerateTokenFromSalt(sessToken string, salt string) string {
	// Standard hash is fine here due to fixed size strings
	return HashToIdHexString(sessToken + "-_" + salt)
}

func SecureObjectID() bson.ObjectID {
	var randomBytes [12]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	return bson.ObjectID(randomBytes)
}

// Below are standard export aliases that keep global compatibility.
// These exist so older code doesn't break, they construct/use the DefaultManager().

func GetRealIPFromRequest(r *http.Request) string {
	return DefaultManager().GetRealIPFromRequest(r)
}
func EncodeSession(session Session) (string, error) {
	return DefaultManager().EncodeSession(session)
}
func DecodeSession(encoded string) (*Session, error) {
	return DefaultManager().DecodeSession(encoded)
}
func GetAndVerifySession(r *http.Request) (*Session, error) {
	return DefaultManager().GetAndVerifySession(r)
}
