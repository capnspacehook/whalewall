package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
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

	// create rule manager and drop unneeded privileges
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dockerCreator := func() (dockerClient, error) {
		return client.NewClientWithOpts(client.FromEnv)
	}
	firewallCreator := func() (firewallClient, error) {
		return nftables.New()
	}
	r, err := newRuleManager(ctx, logger, *dataDir, *timeout, dockerCreator, firewallCreator)
	if err != nil {
		logger.Error("error initializing", zap.Error(err))
	}

	if !restrictPrivileges(logger, *dataDir, *logPath) {
		return 1
	}

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
		}
		if buildSetting.Key == "CGO_ENABLED" && buildSetting.Value != "0" {
			logger.Fatal("this binary was built with cgo and will not function as intended; rebuild with cgo disabled")
		}
	}
	logger.Info("starting whalewall", versionFields...)

	// start managing firewall rules
	if err = r.start(ctx); err != nil {
		logger.Error("error starting", zap.Error(err))
		return 1
	}

	<-ctx.Done()
	logger.Info("shutting down")
	r.stop()

	return 0
}

func restrictPrivileges(logger *zap.Logger, dataDir, logPath string) bool {
	// only allow needed files to be read/written to
	dataDirAbs, err := filepath.Abs(dataDir)
	if err != nil {
		logger.Error("error getting absolute path", zap.String("path", dataDir), zap.Error(err))
		return false
	}
	sqliteFile := filepath.Join(dataDirAbs, dbFilename)
	// TODO: test with docker with TLS
	allowedPaths := []landlock.PathOpt{
		landlock.RODirs(dataDir),
		landlock.RWFiles(
			sqliteFile,
			sqliteFile+"-wal",
			sqliteFile+"-shm",
		),
	}
	if logPath != "stdout" && logPath != "stderr" {
		allowedPaths = append(allowedPaths,
			landlock.PathAccess(llsyscall.AccessFSWriteFile, logPath),
		)
	}
	roFiles := []string{
		"/etc/protocols",
		"/etc/services",
		"/etc/localtime",
		"/etc/nsswitch.conf",
		"/etc/resolv.conf",
		"/etc/hosts",
	}
	for _, file := range roFiles {
		if _, err := os.Stat(file); err == nil {
			allowedPaths = append(allowedPaths,
				landlock.PathAccess(llsyscall.AccessFSReadFile, file),
			)
		}
	}

	err = landlock.V1.RestrictPaths(
		allowedPaths...,
	)
	if err != nil {
		if strings.HasPrefix(err.Error(), "missing kernel Landlock support") {
			logger.Info("unable to apply landlock rules, missing kernel support")
		} else {
			logger.Fatal("error creating landlock rules", zap.NamedError("error", err))
		}
	} else {
		logger.Info("applied landlock rules")
	}

	// block unneeded syscalls
	numAllowedSyscalls, err := installSeccompFilters()
	if err != nil {
		logger.Error("error setting seccomp rules", zap.Error(err))
		return false
	}
	logger.Info("applied seccomp filters", zap.Int("syscalls.allowed", numAllowedSyscalls))

	return true
}
