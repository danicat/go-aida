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
		Addr:        ":8090",
		AllowRemote: false,
		AssetsDir:   "assets",
		WebDir:      webDir,
		ProjectID:   "test-gcp-project",
		Location:    "global",
	}); err == nil || !strings.Contains(err.Error(), "refusing to bind to non-loopback address") {
		t.Fatalf("expected run() to fail fast when binding to :8090 without AllowRemote, got: %v", err)
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
