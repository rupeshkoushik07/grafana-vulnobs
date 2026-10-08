package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxRequestBytes = 25 << 20

type posture struct {
	Asset       string         `json:"asset"`
	Source      string         `json:"source"`
	Namespaces  []string       `json:"namespaces,omitempty"`
	Format      string         `json:"format"`
	LastScanned time.Time      `json:"lastScanned"`
	Counts      map[string]int `json:"counts"`
	KEV         int            `json:"kev"`
	Total       int            `json:"total"`
	Rows        []finding      `json:"rows,omitempty"`
}

type finding struct {
	Package       string  `json:"package"`
	Ecosystem     string  `json:"ecosystem"`
	Version       string  `json:"version"`
	ID            string  `json:"id"`
	CVE           string  `json:"cve"`
	Severity      string  `json:"severity"`
	SeverityScore int     `json:"severityScore"`
	FixedVersion  string  `json:"fixedVersion"`
	Summary       string  `json:"summary"`
	URL           string  `json:"url"`
	EPSS          float64 `json:"epss"`
	KEV           bool    `json:"kev"`
	Priority      int     `json:"priority"`
	Action        string  `json:"action"`
}

type server struct {
	db         *pgxpool.Pool
	signingKey []byte
}

func New(db *pgxpool.Pool, signingKey []byte) (http.Handler, error) {
	if len(signingKey) < 32 {
		return nil, errors.New("storage token signing key must be at least 32 bytes")
	}
	if _, err := db.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS vulnobs_assets (
			tenant_id TEXT NOT NULL,
			asset TEXT NOT NULL,
			source TEXT NOT NULL,
			last_scanned TIMESTAMPTZ NOT NULL,
			posture JSONB NOT NULL,
			PRIMARY KEY (tenant_id, asset)
		)
	`); err != nil {
		return nil, err
	}
	for _, query := range []string{
		`ALTER TABLE vulnobs_assets ADD COLUMN IF NOT EXISTS last_scanned TIMESTAMPTZ`,
		`UPDATE vulnobs_assets SET last_scanned = COALESCE(NULLIF(posture->>'lastScanned', '')::timestamptz, NOW()) WHERE last_scanned IS NULL`,
		`ALTER TABLE vulnobs_assets ALTER COLUMN last_scanned SET NOT NULL`,
	} {
		if _, err := db.Exec(context.Background(), query); err != nil {
			return nil, err
		}
	}
	s := &server{db: db, signingKey: signingKey}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /v1/health", s.authenticate(http.HandlerFunc(s.health)))
	mux.Handle("/v1/assets", s.authenticate(http.HandlerFunc(s.assets)))
	mux.Handle("POST /v1/assets/prune", s.authenticate(http.HandlerFunc(s.pruneAssets)))
	mux.Handle("POST /v1/assets/get", s.authenticate(http.HandlerFunc(s.asset)))
	return mux, nil
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Ping(r.Context()); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type tenantKey struct{}

func (s *server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tenant, err := verifyToken(strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")), s.signingKey)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(contextWithTenant(r, tenant)))
	})
}

type tokenClaims struct {
	TenantID string `json:"tenant"`
	Expires  int64  `json:"exp"`
}

func verifyToken(token string, signingKey []byte) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return "", errors.New("invalid token format")
	}
	unsigned := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("invalid token signature")
	}
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte(unsigned))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", errors.New("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid token payload")
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || !validTenantID(claims.TenantID) {
		return "", errors.New("invalid token claims")
	}
	if claims.Expires <= time.Now().Unix() {
		return "", errors.New("token expired")
	}
	return claims.TenantID, nil
}

func validTenantID(tenantID string) bool {
	if len(tenantID) == 0 || len(tenantID) > 128 {
		return false
	}
	for i, char := range tenantID {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if i == 0 {
			if !valid {
				return false
			}
			continue
		}
		if !valid && char != '.' && char != '_' && char != ':' && char != '-' {
			return false
		}
	}
	return true
}

func PurgeExpired(ctx context.Context, db *pgxpool.Pool, retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, errors.New("retention must be positive")
	}
	result, err := db.Exec(ctx, `DELETE FROM vulnobs_assets WHERE last_scanned < $1`, time.Now().UTC().Add(-retention))
	if err != nil {
		return 0, fmt.Errorf("delete expired assets: %w", err)
	}
	return result.RowsAffected(), nil
}

func (s *server) assets(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(tenantKey{}).(string)
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query(r.Context(), `SELECT posture FROM vulnobs_assets WHERE tenant_id=$1`, tenant)
		if err != nil {
			http.Error(w, "storage query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		assets := make([]json.RawMessage, 0)
		for rows.Next() {
			var item []byte
			if err := rows.Scan(&item); err != nil {
				http.Error(w, "storage query failed", http.StatusInternalServerError)
				return
			}
			assets = append(assets, append(json.RawMessage(nil), item...))
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "storage query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"assets": assets})
	case http.MethodPut:
		var p posture
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&p); err != nil {
			http.Error(w, "invalid asset posture", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(p.Asset) == "" {
			http.Error(w, "asset is required", http.StatusBadRequest)
			return
		}
		if p.LastScanned.IsZero() || p.LastScanned.After(time.Now().UTC().Add(5*time.Minute)) {
			http.Error(w, "lastScanned must be a valid timestamp no more than 5 minutes in the future", http.StatusBadRequest)
			return
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			http.Error(w, "invalid asset posture", http.StatusBadRequest)
			return
		}
		_, err = s.db.Exec(r.Context(), `
			INSERT INTO vulnobs_assets (tenant_id, asset, source, last_scanned, posture)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, asset) DO UPDATE
			SET source=EXCLUDED.source, last_scanned=EXCLUDED.last_scanned, posture=EXCLUDED.posture
		`, tenant, p.Asset, p.Source, p.LastScanned, encoded)
		if err != nil {
			http.Error(w, "storage write failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, p)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) pruneAssets(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Source string   `json:"source"`
		Keep   []string `json:"keep"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Source) == "" {
		http.Error(w, "source and keep are required", http.StatusBadRequest)
		return
	}
	tenant := r.Context().Value(tenantKey{}).(string)
	removed, err := s.prune(r, tenant, body.Source, body.Keep)
	if err != nil {
		http.Error(w, "storage prune failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"removed": removed})
}

func (s *server) asset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Asset string `json:"asset"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Asset) == "" {
		http.Error(w, "asset is required", http.StatusBadRequest)
		return
	}
	tenant := r.Context().Value(tenantKey{}).(string)
	var p []byte
	err := s.db.QueryRow(r.Context(), `SELECT posture FROM vulnobs_assets WHERE tenant_id=$1 AND asset=$2`, tenant, body.Asset).Scan(&p)
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "storage query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(p)
}

func (s *server) prune(r *http.Request, tenant, source string, keep []string) ([]string, error) {
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	rows, err := tx.Query(r.Context(), `SELECT asset FROM vulnobs_assets WHERE tenant_id=$1 AND source=$2`, tenant, source)
	if err != nil {
		return nil, err
	}
	keepSet := make(map[string]struct{}, len(keep))
	for _, item := range keep {
		keepSet[item] = struct{}{}
	}
	removed := make([]string, 0)
	for rows.Next() {
		var asset string
		if err := rows.Scan(&asset); err != nil {
			rows.Close()
			return nil, err
		}
		if _, ok := keepSet[asset]; !ok {
			removed = append(removed, asset)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for _, asset := range removed {
		if _, err := tx.Exec(r.Context(), `DELETE FROM vulnobs_assets WHERE tenant_id=$1 AND source=$2 AND asset=$3`, tenant, source, asset); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		return nil, err
	}
	return removed, nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
	}
}

func contextWithTenant(r *http.Request, tenant string) context.Context {
	return context.WithValue(r.Context(), tenantKey{}, tenant)
}
