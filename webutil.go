package websession

import (
	"net/url"
	"strings"
)

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
