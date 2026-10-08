package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateRequiresBearerTokenAndDerivesTenant(t *testing.T) {
	server := &server{}
	handler := server.authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		_, _ = w.Write([]byte(r.Context().Value(tenantKey{}).(string)))
	}))

	request := httptest.NewRequest(http.MethodGet, "/v1/assets", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing credentials: status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/assets", nil)
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("valid credentials: status = %d", response.Code)
	}
	firstTenant := response.Body.String()

	request = httptest.NewRequest(http.MethodGet, "/v1/assets", nil)
	request.Header.Set("Authorization", "Bearer 11234567890123456789012345678901")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if secondTenant := response.Body.String(); firstTenant == secondTenant {
		t.Fatal("different tokens resolved to the same tenant")
	}
}
