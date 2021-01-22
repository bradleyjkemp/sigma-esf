package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"text/tabwriter"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/bradleyjkemp/sigma-go/evaluator/aggregators"
	"golang.org/x/sync/errgroup"
)

var output = tabwriter.NewWriter(os.Stdout, 12, 2, 1, ' ', tabwriter.TabIndent)

var (
	monitorProcesses = flag.Bool("monitor_processes", true, "Whether to monitor process creation events")
	monitorFiles     = flag.Bool("monitor_files", true, "Whether to monitor file events")
	sigmaRulesRoot   = flag.String("sigma_rules", ".", "Path to a directory containing the Sigma rules to run")
)

func main() {
	flag.Parse()

	rules, err := collectSigmaRules(*sigmaRulesRoot)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Collected", len(rules), "rules")

	g, ctx := errgroup.WithContext(context.Background())

	if *monitorProcesses {
		procMon := exec.CommandContext(ctx, "/Applications/ProcessMonitor.app/Contents/MacOS/ProcessMonitor", "-pretty")
		procMon.Stderr = os.Stderr
		procMonOutput, err := procMon.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}
		g.Go(func() error {
			if err := procMon.Run(); err != nil {
				return fmt.Errorf("error running ProcessMonitor: %w", err)
			}
			if !procMon.ProcessState.Success() {
				return fmt.Errorf("ProcessMonitor didn't exit successfully: exit code %d", procMon.ProcessState.ExitCode())
			}
			return nil
		})
		g.Go(func() error { return consumeEndpointSecurityFrameworkStream(ctx, procMonOutput, rules) })
		log.Println("Started process event monitoring")
	}

	if *monitorFiles {
		fileMon := exec.CommandContext(ctx, "/Applications/FileMonitor.app/Contents/MacOS/FileMonitor", "-pretty")
		fileMon.Stderr = os.Stderr
		fileMonOutput, err := fileMon.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}
		g.Go(func() error {
			if err := fileMon.Run(); err != nil {
				out, _ := ioutil.ReadAll(fileMonOutput)
				return fmt.Errorf("error running FileMonitor: %w %s", err, string(out))
			}
			if !fileMon.ProcessState.Success() {
				return fmt.Errorf("FileMonitor didn't exit successfully: exit code %d", fileMon.ProcessState.ExitCode())
			}
			return nil
		})
		g.Go(func() error { return consumeEndpointSecurityFrameworkStream(ctx, fileMonOutput, rules) })
		log.Println("Started file event monitoring")
	}
	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

//go:generate go run github.com/bradleyjkemp/sigma-go/sigmac .
func collectSigmaRules(root string) (map[string][]*evaluator.RuleEvaluator, error) {
	rules := map[string][]*evaluator.RuleEvaluator{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		switch {
		case info.IsDir():
			return nil
		case filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml":
			return nil
		}

		contents, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("error reading %s: %w", path, err)
		}

		rule, err := sigma.ParseRule(contents)
		if err != nil {
			return fmt.Errorf("error parsing %s: %w", path, err)
		}

		options := aggregators.InMemory(rule.Detection.Timeframe)
		// add the compiled sigma-esf.config.yaml config file
		options = append(options, evaluator.WithConfig(Configs...))
		e := evaluator.ForRule(rule, options...)
		for _, index := range e.Indexes() {
			rules[index] = append(rules[index], e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func consumeEndpointSecurityFrameworkStream(ctx context.Context, stream io.Reader, rules map[string][]*evaluator.RuleEvaluator) error {
	messages := json.NewDecoder(stream)
	for {
		if ctx.Err() != nil {
			return nil
		}

		var message map[string]interface{}
		err := messages.Decode(&message)
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		}

		index, ok := message["event"].(string)
		if !ok {
			fmt.Println("invalid message?", message)
		}
		for _, rule := range rules[index] {
			result, err := rule.Matches(context.Background(), message)
			if err != nil {
				log.Println("Error running rule: ", err)
			}
			if result.Match {
				log.Println("Rule Match!", rule.Title, message)
			}
		}
	}
}
