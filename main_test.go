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

package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func createTestWebDir(t *testing.T) string {
	t.Helper()
	webDir := t.TempDir()
	indexHTML := "<!doctype html><html><body><aida-cockpit></aida-cockpit></body></html>"
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte(indexHTML), 0o600); err != nil {
		t.Fatalf("failed to write test index.html: %v", err)
	}
	return webDir
}

type cancelOnListeningWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	once   sync.Once
	cancel context.CancelFunc
}

func (w *cancelOnListeningWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	text := w.buf.String()
	w.mu.Unlock()

	if strings.Contains(text, "listening on") {
		w.once.Do(func() {
			go func() {
				time.Sleep(30 * time.Millisecond)
				w.cancel()
			}()
		})
	}
	return n, err
}

func TestRun_FailFastOnInvalidOS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := run(ctx, cliConfig{
		Prompt:    "check memory",
		ProjectID: "test-gcp-project",
		Location:  "global",
		OS:        "unsupported-os-xyz",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported operating system") {
		t.Fatalf("expected run() to fail fast with 'unsupported operating system', got: %v", err)
	}
}

func TestRun_FailFastOnMissingOsqueryBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := run(ctx, cliConfig{
		Prompt:        "check memory",
		ProjectID:     "test-gcp-project",
		Location:      "global",
		OsqueryBinary: "osqueryi-nonexistent-binary-xyz",
	})
	if err == nil || !strings.Contains(err.Error(), "osquery") {
		t.Fatalf("expected run() to fail fast when osqueryi binary is missing, got: %v", err)
	}
}

func TestRun_WebServerFailFastAndLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	webDir := createTestWebDir(t)

	if err := run(ctx, cliConfig{
		Addr:      "127.0.0.1:0",
		AssetsDir: "assets",
		WebDir:    webDir,
		ProjectID: "test-gcp-project",
		Location:  "global",
		OS:        "unsupported-os-xyz",
	}); err == nil || !strings.Contains(err.Error(), "unsupported operating system") {
		t.Fatalf("expected run() to fail fast on unsupported OS, got: %v", err)
	}

	if err := run(ctx, cliConfig{
		Addr:      "127.0.0.1:0",
		AssetsDir: "nonexistent-assets-dir-xyz",
		WebDir:    webDir,
		ProjectID: "test-gcp-project",
		Location:  "global",
	}); err == nil || !strings.Contains(err.Error(), "assets directory") {
		t.Fatalf("expected run() to fail fast when assets directory is missing, got: %v", err)
	}

	if err := run(ctx, cliConfig{
		Addr:      "127.0.0.1:0",
		AssetsDir: "assets",
		WebDir:    filepath.Join(t.TempDir(), "missing-web-dist"),
		ProjectID: "test-gcp-project",
		Location:  "global",
	}); err == nil || !strings.Contains(err.Error(), "compiled web cockpit not found at") {
		t.Fatalf("expected run() to fail fast when webDir is missing, got: %v", err)
	}

	if err := run(ctx, cliConfig{
		Addr:        ":8080",
		AllowRemote: false,
		AssetsDir:   "assets",
		WebDir:      webDir,
		ProjectID:   "test-gcp-project",
		Location:    "global",
	}); err == nil || !strings.Contains(err.Error(), "refusing to bind to non-loopback address") {
		t.Fatalf("expected run() to fail fast when binding to :8080 without AllowRemote, got: %v", err)
	}

	srvCtx, srvCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer srvCancel()

	outWriter := &cancelOnListeningWriter{cancel: srvCancel}
	if err := run(srvCtx, cliConfig{
		Addr:      "127.0.0.1:0",
		AssetsDir: "assets",
		WebDir:    webDir,
		ProjectID: "test-gcp-project",
		Location:  "global",
		Stdout:    outWriter,
	}); err != nil {
		t.Fatalf("expected run() to start and shut down cleanly on context cancellation, got: %v", err)
	}
}

func TestCLI_Flags_DefaultsAndRemoval(t *testing.T) {
	fs := flag.NewFlagSet("go-aida", flag.ContinueOnError)
	fs.SetOutput(bytes.NewBuffer(nil))
	_ = setupFlags(fs)

	// Verify -serve and -web flags were removed.
	if fs.Lookup("serve") != nil {
		t.Fatal("expected -serve flag to be removed, but it is defined")
	}
	if fs.Lookup("web") != nil {
		t.Fatal("expected -web flag to be removed, but it is defined")
	}

	// Verify -addr defaults to 127.0.0.1:8080.
	addrFlag := fs.Lookup("addr")
	if addrFlag == nil {
		t.Fatal("expected -addr flag to be defined")
	}
	if addrFlag.DefValue != "127.0.0.1:8080" {
		t.Fatalf("expected -addr default to be %q, got %q", "127.0.0.1:8080", addrFlag.DefValue)
	}

	// Verify -prompt is defined and empty by default.
	promptFlag := fs.Lookup("prompt")
	if promptFlag == nil {
		t.Fatal("expected -prompt flag to be defined")
	}
	if promptFlag.DefValue != "" {
		t.Fatalf("expected -prompt default to be empty, got %q", promptFlag.DefValue)
	}

	// Verify that passing -web or -serve produces an unknown flag error.
	if err := fs.Parse([]string{"-web"}); err == nil || !strings.Contains(err.Error(), "provided but not defined") {
		t.Fatalf("expected parsing -web to fail with unknown flag error, got: %v", err)
	}
	if err := fs.Parse([]string{"-serve"}); err == nil || !strings.Contains(err.Error(), "provided but not defined") {
		t.Fatalf("expected parsing -serve to fail with unknown flag error, got: %v", err)
	}

	// Verify valid flags parse correctly into cliConfig.
	fs2 := flag.NewFlagSet("go-aida", flag.ContinueOnError)
	cfg2 := setupFlags(fs2)
	if err := fs2.Parse([]string{"-addr", "127.0.0.1:9090", "-prompt", "check disk space"}); err != nil {
		t.Fatalf("failed to parse valid flags: %v", err)
	}
	if cfg2.Addr != "127.0.0.1:9090" {
		t.Fatalf("expected cfg.Addr to be %q, got %q", "127.0.0.1:9090", cfg2.Addr)
	}
	if cfg2.Prompt != "check disk space" {
		t.Fatalf("expected cfg.Prompt to be %q, got %q", "check disk space", cfg2.Prompt)
	}
}
