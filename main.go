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
	dataDir   string
	debugLogs bool
	logPath   string
)

func init() {
	flag.StringVar(&dataDir, "d", ".", "directory to store state in")
	flag.BoolVar(&debugLogs, "debug", false, "enable debug logging")
	flag.StringVar(&logPath, "l", "stdout", "path to log to")
}

func main() {
	flag.Parse()

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
	if err = r.start(ctx, dataDir); err != nil {
		logger.Fatal("error starting", zap.Error(err))
	}

	<-ctx.Done()
	logger.Info("shutting down")
	r.stop()
}
