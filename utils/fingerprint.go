package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"m3u-stream-merger/logger"
	"net/http"
	"sort"
	"strings"
)

func normalizeHeaderValue(value string) string {
	if value == "" {
		return ""
	}

	parts := strings.Split(value, ",")
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(strings.ToLower(part))
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}

	if len(normalized) == 0 {
		return ""
	}

	sort.Strings(normalized)
	return strings.Join(normalized, ",")
}

func GenerateFingerprint(r *http.Request) string {
	// Collect relevant attributes
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = xff
	}
	userAgent := r.Header.Get("User-Agent")
	accept := normalizeHeaderValue(r.Header.Get("Accept"))
	acceptLang := normalizeHeaderValue(r.Header.Get("Accept-Language"))
	path := r.URL.Path

	// Combine into a single string
	data := fmt.Sprintf("%s|%s|%s|%s|%s", ip, userAgent, accept, acceptLang, path)
	logger.Default.Debugf("Generating fingerprint from: %s", data)

	// Hash the string for a compact, fixed-length identifier
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
