package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cherryswlo/vulconcern/internal/baseline"
	"github.com/cherryswlo/vulconcern/internal/finding"
	"github.com/cherryswlo/vulconcern/internal/scan"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "baseline":
		os.Exit(runBaseline(os.Args[2:]))
	case "rules":
		os.Exit(runRules(os.Args[2:]))
	case "version":
		fmt.Println(version)
		os.Exit(0)
	default:
		usage()
		os.Exit(2)
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	project := fs.String("project", "", "project directory to scan")
	home := fs.String("home", "", "home directory to scan")
	jsonOut := fs.Bool("json", false, "emit JSON report")
	baselinePath := fs.String("baseline", "", "baseline path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	report, err := scan.Run(scan.Options{Project: *project, Home: *home, BaselinePath: *baselinePath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 2
	}
	if *jsonOut {
		if err := finding.WriteJSON(os.Stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "render failed: %v\n", err)
			return 2
		}
	} else {
		if err := finding.WriteText(os.Stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "render failed: %v\n", err)
			return 2
		}
	}
	if finding.HasAtLeast(report.Findings, finding.High) {
		return 1
	}
	return 0
}

func runBaseline(args []string) int {
	if len(args) < 1 || args[0] != "accept" {
		fmt.Fprintln(os.Stderr, "usage: vulconcern baseline accept [--project DIR] [--home DIR] [--baseline PATH]")
		return 2
	}
	fs := flag.NewFlagSet("baseline accept", flag.ContinueOnError)
	project := fs.String("project", "", "project directory to snapshot")
	home := fs.String("home", "", "home directory to snapshot")
	baselinePath := fs.String("baseline", "", "baseline path")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	path, count, err := scan.AcceptBaseline(scan.Options{Project: *project, Home: *home, BaselinePath: *baselinePath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline accept failed: %v\n", err)
		return 2
	}
	fmt.Printf("Accepted baseline: %s (%d artifacts)\n", path, count)
	return 0
}

func runRules(args []string) int {
	if len(args) != 1 || args[0] != "list" {
		fmt.Fprintln(os.Stderr, "usage: vulconcern rules list")
		return 2
	}
	for _, rule := range ruleCatalog {
		fmt.Printf("%s %s\n", rule.ID, rule.Summary)
	}
	return 0
}

func usage() {
	home, _ := os.UserHomeDir()
	defaultBaseline := baseline.DefaultPath(home)
	fmt.Fprintf(os.Stderr, "vulconcern %s\n", version)
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  vulconcern scan [--project DIR] [--home DIR] [--json] [--baseline PATH]\n")
	fmt.Fprintf(os.Stderr, "  vulconcern baseline accept [--project DIR] [--home DIR] [--baseline PATH]\n")
	fmt.Fprintf(os.Stderr, "  vulconcern rules list\n")
	fmt.Fprintf(os.Stderr, "  vulconcern version\n")
	fmt.Fprintf(os.Stderr, "default baseline: %s\n", defaultBaseline)
}
