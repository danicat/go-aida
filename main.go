// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command go-aida launches the AIDA (AI Diagnostic Agent) Web Cockpit by default,
// or executes a single diagnostic turn in headless CLI mode when -prompt is provided.
package main

//go:generate npm --prefix web run build

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/danicat/go-aida/internal/agent"
	"github.com/danicat/go-aida/internal/server"
)

type cliConfig struct {
	Addr          string
	AllowRemote   bool
	Prompt        string
	Model         string
	ProjectID     string
	Location      string
	AssetsDir     string
	WebDir        string
	PromptsDir    string
	SkillsDir     string
	OS            string
	OsqueryBinary string
	Stdout        io.Writer
	Stderr        io.Writer
}

func setupFlags(fs *flag.FlagSet) *cliConfig {
	cfg := &cliConfig{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	fs.StringVar(&cfg.Addr, "addr", server.DefaultAddr, "HTTP listen address for the AIDA Web Cockpit (loopback by default)")
	fs.BoolVar(&cfg.AllowRemote, "allow-remote", false, "Allow binding the HTTP server to non-loopback network interfaces")
	fs.StringVar(&cfg.Prompt, "prompt", "", "Execute a single diagnostic prompt in headless CLI mode and exit")
	fs.StringVar(&cfg.Model, "model", "", "Model identifier (e.g. vertexai/gemini-3.8-flash or googleai/gemini-3.8-flash; overrides AIDA_MODEL)")
	fs.StringVar(&cfg.ProjectID, "project", "", "Google Cloud Project ID for Vertex AI (overrides GOOGLE_CLOUD_PROJECT)")
	fs.StringVar(&cfg.Location, "location", agent.DefaultLocation, "Google Cloud / Vertex AI location")
	fs.StringVar(&cfg.AssetsDir, "assets", server.DefaultAssetsDir, "Directory containing static avatar assets")
	fs.StringVar(&cfg.WebDir, "web-dir", server.DefaultWebDir, "Directory containing compiled frontend static assets")
	fs.StringVar(&cfg.PromptsDir, "prompts", agent.DefaultPromptDir, "Directory containing Dotprompt (.prompt) files")
	fs.StringVar(&cfg.SkillsDir, "skills", agent.DefaultSkillsDir, "Directory containing OS-specific osquery skill files")
	return cfg
}

func main() {
	cfg := setupFlags(flag.CommandLine)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\n╔══════════════════════════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(os.Stderr, "║ 🚨 AIDA FATAL STARTUP / EXECUTION ERROR (FAIL-FAST)                          ║\n")
		fmt.Fprintf(os.Stderr, "╚══════════════════════════════════════════════════════════════════════════════╝\n")
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg cliConfig) error {
	out := cfg.Stdout
	if out == nil {
		out = os.Stdout
	}
	errOut := cfg.Stderr
	if errOut == nil {
		errOut = os.Stderr
	}

	aidaAgent, err := agent.New(ctx, agent.Config{
		ProjectID:     cfg.ProjectID,
		Location:      cfg.Location,
		Model:         cfg.Model,
		PromptDir:     cfg.PromptsDir,
		SkillsDir:     cfg.SkillsDir,
		OS:            cfg.OS,
		OsqueryBinary: cfg.OsqueryBinary,
	})
	if err != nil {
		return fmt.Errorf("AIDA initialization failed: %w", err)
	}

	if promptText := strings.TrimSpace(cfg.Prompt); promptText != "" {
		_, err := aidaAgent.StreamTurn(
			ctx,
			promptText,
			func(chunk string) {
				_, _ = fmt.Fprint(out, chunk)
			},
			func(name, input, _ string, running bool, toolErr error) {
				if running {
					_, _ = fmt.Fprintf(errOut, "[AIDA tool] ▶ %s %s\n", name, input)
					return
				}
				if toolErr != nil {
					_, _ = fmt.Fprintf(errOut, "[AIDA tool] ✖ %s failed: %v\n", name, toolErr)
					return
				}
				_, _ = fmt.Fprintf(errOut, "[AIDA tool] ✔ %s completed\n", name)
			},
		)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(out)
		return nil
	}

	osqueryVersion, err := aidaAgent.OsqueryVersion(ctx)
	if err != nil {
		return fmt.Errorf("osqueryi version check failed: %w", err)
	}

	srv, err := server.New(server.Config{
		Agent:       aidaAgent,
		AssetsDir:   cfg.AssetsDir,
		WebDir:      cfg.WebDir,
		AllowRemote: cfg.AllowRemote,
	})
	if err != nil {
		return fmt.Errorf("HTTP server initialization failed: %w", err)
	}

	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		addr = server.DefaultAddr
	}

	_, _ = fmt.Fprintf(
		out,
		"[AIDA] Cyber-Diagnostic Cockpit HTTP + A2UI Server listening on %s (os=%s, osquery=%s, model=%s)\n",
		addr,
		aidaAgent.OS(),
		osqueryVersion,
		aidaAgent.Model(),
	)
	return srv.ListenAndServe(ctx, addr)
}
