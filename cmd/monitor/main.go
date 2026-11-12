// Command monitor runs the uptime-security-monitor service: it loads a JSON
// config, seeds the configured monitors into SQLite, then probes them on
// schedule and serves the REST API (and the React dashboard build, if any).
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/tahiryounas604/uptime-security-monitor/internal/alert"
	"github.com/tahiryounas604/uptime-security-monitor/internal/api"
	"github.com/tahiryounas604/uptime-security-monitor/internal/config"
	"github.com/tahiryounas604/uptime-security-monitor/internal/store"
)

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config file")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		logger.Fatalf("store: %v", err)
	}
	defer st.Close()

	// Seed monitors from the config file (skips ones already present).
	for _, m := range cfg.Monitors {
		if _, err := st.AddMonitor(store.Monitor{
			Name: m.Name, URL: m.URL, IntervalSeconds: m.IntervalSeconds,
			Keyword: m.Keyword, ExpectedStatus: m.ExpectedStatus,
			CheckPort: m.CheckPort, TimeoutSeconds: m.TimeoutSeconds,
			SSLWarnDays: m.SSLWarnDays,
		}); err != nil {
			logger.Printf("seed monitor %q (%s): %v", m.Name, m.URL, err)
		} else {
			logger.Printf("seeded monitor %q (%s)", m.Name, m.URL)
		}
	}

	alerter := alert.New(cfg.WebhookURL, logger)
	srv := api.New(st, alerter, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.StartScheduler(ctx)

	logger.Printf("uptime-security-monitor listening on %s (db=%s)", cfg.Listen, cfg.DBPath)
	httpSrv := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(cfg.StaticDir)}
	go func() {
		<-ctx.Done()
		_ = httpSrv.Shutdown(context.Background())
	}()
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("http server: %v", err)
	}
	logger.Println("shutting down")
}
