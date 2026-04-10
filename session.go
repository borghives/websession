package websession

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/borghives/kosmos-go"
	"go.mongodb.org/mongo-driver/v2/bson"
)

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

func NewWebSession(realIP string, clientSignature string) *Session {
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

func RefreshWebSession(realIP string, clientSignature string, oldSession *Session) *Session {
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

func (sess Session) GetAge() time.Duration {
	return time.Since(sess.GenerateTime)
}
func SecureObjectID() bson.ObjectID {
	var randomBytes [12]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	return bson.ObjectID(randomBytes)
}

func HashToIdHexString(message string) string {
	if message == "" {
		return bson.NilObjectID.Hex()
	}
	idbytes := sha256.Sum256([]byte(message))
	return hex.EncodeToString(idbytes[:12])
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
