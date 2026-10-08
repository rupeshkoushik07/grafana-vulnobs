package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxRequestBytes = 25 << 20

type posture struct {
	Asset       string          `json:"asset"`
	Source      string          `json:"source"`
	Namespaces  []string        `json:"namespaces,omitempty"`
	Format      string          `json:"format"`
	LastScanned time.Time       `json:"lastScanned"`
	Counts      map[string]int  `json:"counts"`
	KEV         int             `json:"kev"`
	Total       int             `json:"total"`
	Rows        json.RawMessage `json:"rows,omitempty"`
}

type server struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) (http.Handler, error) {
	if _, err := db.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS vulnobs_assets (
			tenant_id TEXT NOT NULL,
			asset TEXT NOT NULL,
			source TEXT NOT NULL,
			posture JSONB NOT NULL,
			PRIMARY KEY (tenant_id, asset)
		)
	`); err != nil {
		return nil, err
	}
	s := &server{db: db}
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
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if len(token) < 32 || token == r.Header.Get("Authorization") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		hash := sha256.Sum256([]byte(token))
		next.ServeHTTP(w, r.WithContext(contextWithTenant(r, hex.EncodeToString(hash[:]))))
	})
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
		if p.LastScanned.IsZero() {
			p.LastScanned = time.Now().UTC()
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			http.Error(w, "invalid asset posture", http.StatusBadRequest)
			return
		}
		_, err = s.db.Exec(r.Context(), `
			INSERT INTO vulnobs_assets (tenant_id, asset, source, posture)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, asset) DO UPDATE
			SET source=EXCLUDED.source, posture=EXCLUDED.posture
		`, tenant, p.Asset, p.Source, encoded)
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
