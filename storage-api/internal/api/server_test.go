package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthenticateRequiresSignedUnexpiredBearerTokenAndDerivesTenant(t *testing.T) {
	key := []byte("test-signing-key-with-at-least-32-bytes")
	server := &server{signingKey: key}
	handler := server.authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.Context().Value(tenantKey{}).(string)))
	}))

	request := httptest.NewRequest(http.MethodGet, "/v1/assets", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing credentials: status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/assets?tenantId=tenant-b", nil)
	request.Header.Set("Authorization", "Bearer "+testToken(t, key, "tenant-a", time.Now().Add(time.Hour).Unix()))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid credentials: status = %d", response.Code)
	}
	firstTenant := response.Body.String()
	if firstTenant != "tenant-a" {
		t.Fatalf("tenant from verified claims = %q, want tenant-a", firstTenant)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/assets", nil)
	request.Header.Set("Authorization", "Bearer "+testToken(t, key, "tenant-b", time.Now().Add(time.Hour).Unix()))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if secondTenant := response.Body.String(); firstTenant == secondTenant {
		t.Fatal("different signed tenant claims resolved to the same tenant")
	}

	for name, token := range map[string]string{
		"tampered":       testToken(t, key, "tenant-a", time.Now().Add(time.Hour).Unix()) + "x",
		"expired":        testToken(t, key, "tenant-a", time.Now().Add(-time.Hour).Unix()),
		"unsigned":       "01234567890123456789012345678901",
		"invalid tenant": testToken(t, key, "tenant/a", time.Now().Add(time.Hour).Unix()),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/assets", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("invalid credentials: status = %d", response.Code)
			}
		})
	}
}

func testToken(t *testing.T, key []byte, tenant string, expires int64) string {
	t.Helper()
	payload, err := json.Marshal(tokenClaims{TenantID: tenant, Expires: expires})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := "v1." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
