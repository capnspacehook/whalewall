package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	debugLogs bool
	logPath   string
)

func init() {
	flag.BoolVar(&debugLogs, "d", false, "enable debug logging")
	flag.StringVar(&logPath, "l", "stdout", "path to log to")
}

func main() {
	logCfg := zap.NewProductionConfig()
	logCfg.OutputPaths = []string{logPath}
	if debugLogs {
		logCfg.Level.SetLevel(zap.DebugLevel)
	}
	logCfg.EncoderConfig.TimeKey = "time"
	logCfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	logCfg.DisableCaller = true

	logger, err := logCfg.Build()
	if err != nil {
		log.Fatalf("error creating logger: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	r := newRuleManager(logger)
	logger.Info("starting whalewall")
	if err = r.start(ctx, "db.sqlite"); err != nil {
		logger.Fatal("error starting", zap.Error(err))
	}

	<-ctx.Done()
	logger.Info("shutting down")
	r.stop()
}
