package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rupeshkoushik07/grafana-vulnobs/storage-api/internal/api"
)

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	signingKey := os.Getenv("VULNOBS_TOKEN_SIGNING_KEY")
	if len(signingKey) < 32 {
		log.Fatal("VULNOBS_TOKEN_SIGNING_KEY must contain at least 32 bytes")
	}
	retentionDays, err := retentionDaysFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	retention := time.Duration(retentionDays) * 24 * time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("connect to storage database: %v", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		log.Fatalf("ping storage database: %v", err)
	}

	server, err := api.New(db, []byte(signingKey))
	if err != nil {
		log.Fatalf("initialize storage API: %v", err)
	}
	if removed, err := api.PurgeExpired(context.Background(), db, retention); err != nil {
		log.Fatal("purge expired asset records failed")
	} else if removed > 0 {
		log.Print("purged expired asset records")
	}
	go purgeExpiredPeriodically(db, retention)

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve storage API: %v", err)
	}
}

func retentionDaysFromEnv() (int, error) {
	raw := os.Getenv("VULNOBS_RETENTION_DAYS")
	if raw == "" {
		return 90, nil
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 1 || days > 3650 {
		return 0, errors.New("VULNOBS_RETENTION_DAYS must be an integer from 1 to 3650")
	}
	return days, nil
}

func purgeExpiredPeriodically(db *pgxpool.Pool, retention time.Duration) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		removed, err := api.PurgeExpired(ctx, db, retention)
		cancel()
		if err != nil {
			log.Print("purge expired asset records failed")
			continue
		}
		if removed > 0 {
			log.Print("purged expired asset records")
		}
	}
}
