package utils

import (
	"net/http/httptest"
	"testing"
)

func TestGenerateFingerprintNormalizesAcceptHeader(t *testing.T) {
	reqA := httptest.NewRequest("GET", "http://example.com/playlist", nil)
	reqA.RemoteAddr = "203.0.113.10:12345"
	reqA.Header.Set("User-Agent", "TestAgent/1.0")
	reqA.Header.Set("Accept", "application/vnd.apple.mpegurl, application/x-mpegurl;q=0.9, */*;q=0.8")
	reqA.Header.Set("Accept-Language", "en-US, es-ES;q=0.8")

	reqB := httptest.NewRequest("GET", "http://example.com/playlist", nil)
	reqB.RemoteAddr = "203.0.113.10:12345"
	reqB.Header.Set("User-Agent", "TestAgent/1.0")
	reqB.Header.Set("Accept", " */*;q=0.8 ,APPLICATION/X-MPEGURL;Q=0.9, application/vnd.apple.mpegurl ")
	reqB.Header.Set("Accept-Language", "es-ES;q=0.8, en-US")

	fpA := GenerateFingerprint(reqA)
	fpB := GenerateFingerprint(reqB)

	if fpA != fpB {
		t.Fatalf("fingerprints should match when accept headers contain same values in different order: %s vs %s", fpA, fpB)
	}
}
