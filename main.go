package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	dataDir        string
	debugLogs      bool
	logPath        string
	displayVersion bool
)

func init() {
	flag.StringVar(&dataDir, "d", ".", "directory to store state in")
	flag.BoolVar(&debugLogs, "debug", false, "enable debug logging")
	flag.StringVar(&logPath, "l", "stdout", "path to log to")
	flag.BoolVar(&displayVersion, "version", false, "print version and build information and exit")
}

func main() {
	flag.Parse()

	if version == "" {
		version = "devel"
	}
	if displayVersion {
		printVersionInfo()
		os.Exit(0)
	}

	// build logger
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

	// log current version/commit
	info, ok := debug.ReadBuildInfo()
	if !ok {
		logger.Fatal("build information not found")
	}
	versionFields := []zap.Field{
		zap.String("version", version),
	}
	for _, buildSetting := range info.Settings {
		if buildSetting.Key == "vcs.revision" {
			versionFields = append(versionFields, zap.String("commit", buildSetting.Value))
			break
		}
	}
	logger.Info("starting whalewall", versionFields...)

	// start managing firewall rules
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	r := newRuleManager(logger)
	if err = r.start(ctx, dataDir); err != nil {
		logger.Fatal("error starting", zap.Error(err))
	}

	<-ctx.Done()
	logger.Info("shutting down")
	r.stop()
}
