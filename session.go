package websession

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var WEB_SESSION_TTL = time.Hour * 12

type WebSession struct {
	ID           primitive.ObjectID `xml:"-" json:"-" bson:"_id,omitempty"`
	FromIp       string             `xml:"-" json:"-" bson:"ip"`
	GenerateTime time.Time          `xml:"-" json:"-" bson:"gen_tm"`
	GenerateFrom primitive.ObjectID `xml:"-" json:"-" bson:"gen_frm"`
	FirstID      primitive.ObjectID `xml:"-" json:"-" bson:"frst_id"`
	FirstTime    time.Time          `xml:"-" json:"-" bson:"frst_tm"`
	UserId       primitive.ObjectID `xml:"-" json:"-" bson:"user_id,omitempty"`
	UserName     string             `xml:"-" json:"-" bson:"user_name,omitempty"`
	SecretToken  string             `xml:"-" json:"-" bson:"secret_token"`
	ClientHash   string             `xml:"-" json:"-" bson:"client_hash"`
	ClientSig    string             `xml:"-" json:"-" bson:"-"`
}

func newWebSession(realIP string, clientSignature string) *WebSession {
	currentTime := time.Now()
	id := primitive.NewObjectIDFromTimestamp(currentTime)
	clientHash := HashToIdHexString(clientSignature)
	return &WebSession{
		ID:           id,
		FromIp:       realIP,
		GenerateTime: currentTime,
		FirstID:      id,
		FirstTime:    currentTime,
		ClientHash:   clientHash,
		SecretToken:  GetRandomHexString(),
	}
}

func refreshWebSession(realIP string, clientSignature string, oldSession *WebSession) *WebSession {
	clientHash := HashToIdHexString(clientSignature)
	return &WebSession{
		ID:           primitive.NewObjectID(),
		FromIp:       realIP,
		GenerateTime: time.Now(),
		GenerateFrom: oldSession.ID,
		FirstID:      oldSession.FirstID,
		FirstTime:    oldSession.FirstTime,
		ClientHash:   clientHash,
		SecretToken:  GetRandomHexString(),
	}
}

func getSessionSecret() string {
	secret := os.Getenv("SECRET_SESSION")
	if secret == "" {
		log.Fatal("FATAL: CANNOT FIND SECRET_SESSION")
	}
	return secret
}

// fatal if cannot secure session
func SessionInitCheck() {
	if getSessionSecret() == "" {
		log.Fatal("FATAL: CANNOT FIND SECRET_SESSION")
	}
}

func EncodeSession(session WebSession) (string, error) {
	//empty client sig only encrypting client hash
	session.ClientSig = ""

	encodedBytes, err := bson.Marshal(session)
	if err != nil {
		return "", err
	}
	return EncryptMessage(getSessionSecret(), encodedBytes)
}

func DecodeSession(encodedSession string) (*WebSession, error) {
	decodedBytes, err := DecryptMessage(getSessionSecret(), encodedSession)
	if err != nil {
		return nil, err
	}
	var session WebSession
	err = bson.Unmarshal(decodedBytes, &session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// getRealIPFromRequest extracts the client's real IP address from http.Request
func GetRealIPFromRequest(r *http.Request) string {
	// Check the X-Forwarded-For header first
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// This header can contain multiple IPs separated by comma
		// The first one in the list is the original client IP
		parts := strings.Split(xForwardedFor, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}
		// log.Printf("X-Forwarded-For: %v", parts)
		return parts[0]
	}

	// If X-Forwarded-For is empty, check the X-Real-IP header
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		ip := strings.TrimSpace(xRealIP)
		log.Printf("X-Real-IP: %v", ip)
		return ip
	}

	// If neither header is present, use the remote address from the request
	// This might be the IP of a proxy or load balancer
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// getClientSignature extracts the client's browser signature from http.Request
func GetClientSignature(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

func GetDomain() string {
	domain := os.Getenv("SITE_DOMAIN")
	if domain == "" {
		domain = "localhost"
	}
	return domain
}

func setNewRequestSession(w http.ResponseWriter, realIP string, clientSignature string) *WebSession {

	// Create a new session
	session := newWebSession(realIP, clientSignature)
	SetSessionCookie(w, session)
	return session
}

func refreshNewRequestSession(w http.ResponseWriter, realIP string, clientSignature string, oldSession *WebSession) *WebSession {
	// Create a new session
	if oldSession == nil {
		return setNewRequestSession(w, realIP, clientSignature)
	}

	session := refreshWebSession(realIP, clientSignature, oldSession)
	SetSessionCookie(w, session)
	return session
}

func SetSessionCookie(w http.ResponseWriter, session *WebSession) error {
	domain := GetDomain()

	// Create a new session
	encodedSess, err := EncodeSession(*session)
	if err != nil {
		return err
	}
	// Create a new cookie
	cookie := http.Cookie{
		Name:     "session",
		Value:    encodedSess,
		Path:     "/",     // The cookie is accessible on all paths
		Domain:   domain,  // Accessible by mypierian.com and all its subdomains
		MaxAge:   1469000, // Expires after ~17 days
		HttpOnly: true,    // Not accessible via JavaScript
	}

	// Set the cookie in the response header
	http.SetCookie(w, &cookie)
	return nil
}

func GetRequestSession(r *http.Request) (*WebSession, error) {
	// Get the cookie from the request
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, &WebSessionError{
			Message: "no session found; ",
			Code:    SESSION_ERROR_NO_SESSION,
		}
	}

	// Decode the cookie value
	session, err := DecodeSession(cookie.Value)
	if err != nil {
		return nil, &WebSessionError{
			Message: "failed to decode session; ",
			Code:    SESSION_ERROR_DECODING_FAILED,
		}
	}

	clientSignature := GetClientSignature(r)
	clientHash := HashToIdHexString(clientSignature)

	if clientHash == session.ClientHash {
		session.ClientSig = clientSignature
	} else {
		err = &WebSessionError{
			Message: "failed to assign client with hash mismatch; ",
			Code:    SESSION_ERROR_CLIENT_MISMATCH,
		}
	}

	// Return the decoded session
	return session, nil
}

func RefreshRequestSession(w http.ResponseWriter, r *http.Request) *WebSession {
	// Get the session from the request
	session, err := GetAndVerifySession(r)
	if err != nil {
		return refreshNewRequestSession(w, GetRealIPFromRequest(r), GetClientSignature(r), session)
	}

	return session

}

func RefreshNewRequestSession(w http.ResponseWriter, r *http.Request) *WebSession {
	session, _ := GetAndVerifySession(r)
	return refreshNewRequestSession(w, GetRealIPFromRequest(r), GetClientSignature(r), session)
}

func ClearRequestSession(w http.ResponseWriter, r *http.Request) *WebSession {
	return refreshNewRequestSession(w, GetRealIPFromRequest(r), GetClientSignature(r), nil)
}

func (sess WebSession) GetAge() time.Duration {
	return time.Since(sess.GenerateTime)
}

func HashToIdHexString(message string) string {
	if message == "" {
		return primitive.NilObjectID.Hex()
	}

	//convert string to bytes
	idbytes := sha256.Sum256([]byte(message))
	//convert bytes to hex string
	return string(hex.EncodeToString(idbytes[:12]))
}

func (sess *WebSession) GenerateHashBytes(message string) [32]byte {
	if message == "" {
		message = "0"
	}

	//convert string to bytes
	return sha256.Sum256([]byte(sess.ID.Hex() + sess.SecretToken + sess.GenerateFrom.Hex() + message))
}

func (sess *WebSession) GenerateHexID(message string) string {
	if sess == nil {
		return primitive.NilObjectID.Hex()
	}
	idbytes := sess.GenerateHashBytes(message)
	return string(hex.EncodeToString(idbytes[:12]))
}

func (sess *WebSession) GenerateSessionToken() string {
	return sess.GenerateHexID("session_token")
}

func (sess *WebSession) GenerateTokenFromSalt(salt string) string {
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
	return HashToIdHexString(sessToken + "-_" + salt)
}
