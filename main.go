// Tekkoh's server: accounts, encrypted entries and photos, and PIN-limited
// key recovery. The phone encrypts everything before it arrives here.
package main

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("TEKKOH_SECRET"))
	if err != nil || len(secret) < 32 {
		slog.Error("TEKKOH_SECRET must be at least 32 random bytes, base64: berth config:set tekkoh TEKKOH_SECRET=$(openssl rand -base64 32)")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var store Store
	if url := os.Getenv("DATABASE_URL"); url != "" {
		pg, err := openPG(ctx, url)
		if err != nil {
			slog.Error("postgres", "err", err)
			os.Exit(1)
		}
		store = pg
		slog.Info("store: postgres")
	} else {
		store = newMemStore()
		slog.Warn("store: memory (no DATABASE_URL); nothing survives a restart")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{Addr: "0.0.0.0:" + port, Handler: NewServer(store, secret).Routes(),
		// A slow client can't hold a connection (and a photo's buffer) for long.
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	slog.Info("tekkoh listening", "port", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
