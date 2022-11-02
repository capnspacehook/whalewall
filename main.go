package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const defaultTimeout = 10 * time.Second

func main() {
	os.Exit(mainRetCode())
}

func mainRetCode() int {
	clear := flag.Bool("clear", false, "remove all firewall rules created by whalewall")
	dataDir := flag.String("d", ".", "directory to store state in")
	debugLogs := flag.Bool("debug", false, "enable debug logging")
	logPath := flag.String("l", "stdout", "path to log to")
	timeout := flag.Duration("t", defaultTimeout, "timeout for Docker API requests")
	displayVersion := flag.Bool("version", false, "print version and build information and exit")
	flag.Parse()

	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Println("build information not found")
		return 1
	}

	if *displayVersion {
		printVersionInfo(info)
		return 0
	}

	// build logger
	logCfg := zap.NewProductionConfig()
	logCfg.OutputPaths = []string{*logPath}
	if *debugLogs {
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

	dockerCreator := func() (dockerClient, error) {
		return client.NewClientWithOpts(client.FromEnv)
	}
	firewallCreator := func() (firewallClient, error) {
		return nftables.New()
	}
	r := newRuleManager(logger, *timeout, dockerCreator, firewallCreator)

	// remove all created firewall rules if the user asked to clear
	if *clear {
		logger.Info("clearing rules")
		if err := r.clear(ctx, *dataDir); err != nil {
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
	if err = r.start(ctx, *dataDir); err != nil {
		logger.Error("error starting", zap.Error(err))
		return 1
	}

	<-ctx.Done()
	logger.Info("shutting down")
	r.stop()

	return 0
}
