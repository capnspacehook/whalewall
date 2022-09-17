package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"text/tabwriter"
)

var version string

func printVersionInfo() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatal("build information not found")
	}

	if version == "" {
		version = "devel"
	}
	fmt.Printf("Whalewall %s\n\n", version)

	fmt.Print("Build Information:\n\n")
	buildtw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(buildtw, "Go version:\t%s\n", info.GoVersion)
	for _, setting := range info.Settings {
		key := setting.Key
		value := setting.Value

		switch setting.Key {
		case "-compiler":
			key = "Compiler"
		case "-ldflags":
			key = "Link Flags"
		case "vcs", "vcs.modified":
			continue
		case "vcs.revision":
			key = "Commit"
		case "vcs.time":
			key = "Commit Time"
		}

		fmt.Fprintf(buildtw, "%s:\t%s\n", key, value)
	}
	buildtw.Flush()

	fmt.Print("\nDependencies:\n\n")
	deptw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprint(deptw, "Name\tVersion\tHash\n")
	for _, dep := range info.Deps {
		fmt.Fprintf(deptw, "%s\t%s\t%s\n", dep.Path, dep.Version, dep.Sum)
	}
	deptw.Flush()
}
