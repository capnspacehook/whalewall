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
	clear          bool
	dataDir        string
	debugLogs      bool
	logPath        string
	displayVersion bool
)

func init() {
	flag.BoolVar(&clear, "clear", false, "remove all firewall rules created by whalewall")
	flag.StringVar(&dataDir, "d", ".", "directory to store state in")
	flag.BoolVar(&debugLogs, "debug", false, "enable debug logging")
	flag.StringVar(&logPath, "l", "stdout", "path to log to")
	flag.BoolVar(&displayVersion, "version", false, "print version and build information and exit")
}
func main() {
	os.Exit(mainRet())
}

func mainRet() int {
	flag.Parse()

	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatal("build information not found")
	}

	if version == "" {
		version = "devel"
	}
	if displayVersion {
		printVersionInfo(info)
		return 0
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
		log.Printf("error creating logger: %v", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	r := newRuleManager(logger)

	// remove all created firewall rules if the use asked to clear
	if clear {
		logger.Info("clearing rules")
		if err := r.clear(ctx, dataDir); err != nil {
			logger.Error("error clearing rules", zap.Error(err))
			return 1
		}
		return 0
	}

	// log current version/commit
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
	if err = r.start(ctx, dataDir); err != nil {
		logger.Error("error starting", zap.Error(err))
		return 1
	}

	<-ctx.Done()
	logger.Info("shutting down")
	r.stop()
	return 0
}
