package websession

import (
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
