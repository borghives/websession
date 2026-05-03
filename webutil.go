package websession

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
)

func MakeUniqueURL(readable string, token []byte, hiddenStrs ...string) string {
	mac := hmac.New(sha256.New, token)
	mac.Write([]byte(readable))
	for _, hidden := range hiddenStrs {
		mac.Write([]byte(hidden))
	}
	hash := mac.Sum(nil)
	hashStr := MakeUrlSafe(base64.RawURLEncoding.EncodeToString(hash[:]))
	return MakeUrlSafe(readable + "-" + hashStr[:5])

}

func MakeUrlSafe(str string) string {
	// Convert to lowercase
	str = strings.ToLower(str)

	// Replace spaces with hyphens
	str = strings.ReplaceAll(str, " ", "-")

	// Remove all non-alphanumeric characters except hyphens
	safeStr := make([]byte, 0, len(str))
	for _, r := range str {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			safeStr = append(safeStr, byte(r))
		}
	}

	// Handle URL-reserved characters using url.PathEscape
	return url.PathEscape(string(safeStr))
}
