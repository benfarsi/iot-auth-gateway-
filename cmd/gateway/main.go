package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/benfarsi/iot-auth-gateway/internal/auth"
	"github.com/benfarsi/iot-auth-gateway/internal/config"
	"github.com/benfarsi/iot-auth-gateway/internal/gateway"
	"github.com/benfarsi/iot-auth-gateway/internal/logging"
)

func main() {
	configPath := flag.String("config", "configs/gateway.yaml", "path to gateway config file")
	genKey := flag.Bool("gen-key", false, "generate a new JWT signing key and exit")
	keyPath := flag.String("key-out", "pki/jwt-signing.key", "output path for generated key")
	flag.Parse()

	if *genKey {
		if err := auth.GenerateKeyFile(*keyPath); err != nil {
			log.Fatalf("generate key: %v", err)
		}
		log.Printf("JWT signing key written to %s", *keyPath)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Set up audit logger — write to file if configured, otherwise stdout.
	var audit *logging.Logger
	if cfg.Logging.Output != "" && cfg.Logging.Output != "stdout" {
		audit, err = logging.NewFile(cfg.Logging.Output)
		if err != nil {
			log.Fatalf("open audit log: %v", err)
		}
	} else {
		audit = logging.New(os.Stdout)
	}

	srv, err := gateway.New(cfg, audit)
	if err != nil {
		log.Fatalf("create gateway: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("IoT Auth Gateway starting on %s", cfg.Gateway.ListenAddr)
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("gateway error: %v", err)
	}
}
