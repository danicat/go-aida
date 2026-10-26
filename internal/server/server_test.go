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

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danicat/go-aida/internal/agent"
)

func newTestAgent(t *testing.T) *agent.AIDA {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	aida, err := agent.New(ctx, agent.Config{
		ProjectID: "test-gcp-project",
		Location:  "global",
		PromptDir: filepath.Join("..", "..", "prompts"),
		SkillsDir: filepath.Join("..", "..", "skills"),
	})
	if err != nil {
		t.Fatalf("failed to initialize AIDA agent: %v", err)
	}
	return aida
}

func newTestWebDir(t *testing.T) string {
	t.Helper()
	webDir := t.TempDir()
	indexHTML := "<!doctype html><html><body><aida-cockpit></aida-cockpit></body></html>"
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte(indexHTML), 0o600); err != nil {
		t.Fatalf("failed to write test index.html: %v", err)
	}
	return webDir
}

func TestServer_SystemStatus_LiveOsquery(t *testing.T) {
	aida := newTestAgent(t)
	webDir := newTestWebDir(t)
	srv, err := New(Config{
		Agent:     aida,
		AssetsDir: filepath.Join("..", "..", "assets"),
		WebDir:    webDir,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/system-status", nil)
	if err != nil {
		t.Fatalf("NewRequest GET /api/system-status failed: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:5173")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/system-status failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("GET /api/system-status status = %d, want 200; body=%s", resp.StatusCode, string(body))
	}

	// Verify legacy alias GET /api/status is not registered and returns 404
	statusReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/status", nil)
	if err != nil {
		t.Fatalf("NewRequest GET /api/status failed: %v", err)
	}
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatalf("GET /api/status failed: %v", err)
	}
	_ = statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /api/status status = %d, want 404", statusResp.StatusCode)
	}

	endpoint := "/api/system-status"

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("GET %s Access-Control-Allow-Origin = %q, want %q", endpoint, got, "http://localhost:5173")
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("GET %s X-Content-Type-Options = %q, want %q", endpoint, got, "nosniff")
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("GET %s X-Frame-Options = %q, want %q", endpoint, got, "DENY")
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("GET %s Content-Security-Policy = %q, want %q", endpoint, got, "frame-ancestors 'none'")
	}

	var status SystemStatus
	decodeErr := json.NewDecoder(resp.Body).Decode(&status)
	_ = resp.Body.Close()
	if decodeErr != nil {
		t.Fatalf("failed to decode SystemStatus from %s: %v", endpoint, decodeErr)
	}

	if status.Hostname == "" {
		t.Errorf("expected non-empty Hostname from live osquery")
	}
	if status.OS == "" {
		t.Errorf("expected non-empty OS")
	}
	if status.Arch == "" {
		t.Errorf("expected non-empty Arch")
	}
	if status.OSSkill != aida.OS() {
		t.Errorf("OSSkill = %q, want %q", status.OSSkill, aida.OS())
	}
	if status.Kernel == "" {
		t.Errorf("expected non-empty Kernel from live osquery")
	}
	if status.Uptime == "" {
		t.Errorf("expected non-empty Uptime from live osquery")
	}
	if status.OsqueryVersion == "" {
		t.Errorf("expected non-empty OsqueryVersion from live osquery")
	}
	if status.Model != aida.Model() {
		t.Errorf("Model = %q, want %q", status.Model, aida.Model())
	}
	if status.ThinkingLevel != aida.ThinkingLevel() {
		t.Errorf("ThinkingLevel = %q, want %q", status.ThinkingLevel, aida.ThinkingLevel())
	}
	if status.CPU < 0 || status.CPU > 100 {
		t.Errorf("CPU = %v, want in [0, 100]", status.CPU)
	}
	if status.Memory <= 0 || status.Memory > 100 {
		t.Errorf("Memory = %v, want in (0, 100]", status.Memory)
	}
	wantHealth := ComputeHealth(status.CPU, status.Memory)
	if status.Health != wantHealth {
		t.Errorf("Health = %q, want %q (cpu=%v, memory=%v)", status.Health, wantHealth, status.CPU, status.Memory)
	}
}

func TestServer_CORSLoopbackAndRejection(t *testing.T) {
	aida := newTestAgent(t)
	webDir := newTestWebDir(t)
	srv, err := New(Config{
		Agent:     aida,
		AssetsDir: filepath.Join("..", "..", "assets"),
		WebDir:    webDir,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	allowedOrigins := []string{
		"http://localhost:5173",
		"http://127.0.0.1:8080",
		"http://[::1]:5173",
		"http://localhost",
	}

	for _, origin := range allowedOrigins {
		for _, path := range []string{"/agents/aida", "/api/system-status"} {
			req, err := http.NewRequest(http.MethodOptions, ts.URL+path, nil)
			if err != nil {
				t.Fatalf("NewRequest OPTIONS %s failed: %v", path, err)
			}
			req.Header.Set("Origin", origin)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("OPTIONS %s failed: %v", path, err)
			}
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("OPTIONS %s (origin=%s) status = %d, want %d", path, origin, resp.StatusCode, http.StatusNoContent)
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
				t.Errorf("OPTIONS %s Access-Control-Allow-Origin = %q, want %q", path, got, origin)
			}
			if got := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") || !strings.Contains(got, "OPTIONS") {
				t.Errorf("OPTIONS %s Access-Control-Allow-Methods = %q, want GET, POST, OPTIONS", path, got)
			}
			if got := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Content-Type") {
				t.Errorf("OPTIONS %s Access-Control-Allow-Headers = %q, want Content-Type", path, got)
			}
		}
	}

	rejectedOrigins := []string{
		"https://evil.example.com",
		"http://evil.example.com",
		"http://192.168.1.50:8080",
		"null",
	}
	for _, badOrigin := range rejectedOrigins {
		for _, method := range []string{http.MethodGet, http.MethodOptions, http.MethodPost} {
			req, err := http.NewRequest(method, ts.URL+"/api/system-status", nil)
			if err != nil {
				t.Fatalf("NewRequest %s failed: %v", method, err)
			}
			req.Header.Set("Origin", badOrigin)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s with origin %q failed: %v", method, badOrigin, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s with Origin %q returned status %d, want %d (403 Forbidden); body=%s", method, badOrigin, resp.StatusCode, http.StatusForbidden, string(body))
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("%s with Origin %q set Access-Control-Allow-Origin = %q, want empty", method, badOrigin, got)
			}
		}
	}
}

func TestServer_AssetsServingAndDirectoryListingRejection(t *testing.T) {
	aida := newTestAgent(t)
	webDir := newTestWebDir(t)
	if err := os.MkdirAll(filepath.Join(webDir, "assets"), 0o755); err != nil {
		t.Fatalf("failed to create webDir/assets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "assets", "fallback-only.png"), []byte("should-not-serve"), 0o600); err != nil {
		t.Fatalf("failed to write fallback-only.png: %v", err)
	}

	srv, err := New(Config{
		Agent:     aida,
		AssetsDir: filepath.Join("..", "..", "assets"),
		WebDir:    webDir,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/assets/idle.png")
	if err != nil {
		t.Fatalf("GET /assets/idle.png failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /assets/idle.png status = %d, want 200", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /assets/idle.png body failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty PNG payload from /assets/idle.png")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "image/png") {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}

	// Directory listing on /assets/ must be rejected with 404 Not Found
	dirResp, err := http.Get(ts.URL + "/assets/")
	if err != nil {
		t.Fatalf("GET /assets/ failed: %v", err)
	}
	_ = dirResp.Body.Close()
	if dirResp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /assets/ status = %d, want 404 Not Found", dirResp.StatusCode)
	}

	// Fallback to webDir/assets must not happen
	fallbackResp, err := http.Get(ts.URL + "/assets/fallback-only.png")
	if err != nil {
		t.Fatalf("GET /assets/fallback-only.png failed: %v", err)
	}
	_ = fallbackResp.Body.Close()
	if fallbackResp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /assets/fallback-only.png status = %d, want 404 Not Found (no silent fallback to webDir)", fallbackResp.StatusCode)
	}
}

func TestServer_AgentRoutesAndWebDir(t *testing.T) {
	aida := newTestAgent(t)
	webDir := newTestWebDir(t)

	srv, err := New(Config{
		Agent:     aida,
		AssetsDir: filepath.Join("..", "..", "assets"),
		WebDir:    webDir,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Verify static web root serving
	rootResp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer func() { _ = rootResp.Body.Close() }()
	if rootResp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rootResp.StatusCode)
	}
	rootBody, _ := io.ReadAll(rootResp.Body)
	if !strings.Contains(string(rootBody), "<aida-cockpit>") {
		t.Errorf("GET / body = %q, want <aida-cockpit>", string(rootBody))
	}

	registered := srv.Routes()
	hasPrimary := false
	hasAlias := false
	for _, r := range registered {
		if r == "POST /agents/aida" {
			hasPrimary = true
		}
		if r == "POST /api/agents/aida" {
			hasAlias = true
		}
	}
	if !hasPrimary {
		t.Errorf("expected srv.Routes() to include \"POST /agents/aida\", got %v", registered)
	}
	if hasAlias {
		t.Errorf("expected srv.Routes() to NOT include \"POST /api/agents/aida\", got %v", registered)
	}

	// Verify POST /agents/aida is routed to Genkit handler
	resp, err := http.Post(ts.URL+"/agents/aida", "application/json", strings.NewReader("{invalid-json"))
	if err != nil {
		t.Fatalf("POST /agents/aida failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		t.Errorf("POST /agents/aida returned %d; expected Genkit handler to be mounted and handle POST", resp.StatusCode)
	}

	// Verify POST /api/agents/aida returns 404
	respAlias, err := http.Post(ts.URL+"/api/agents/aida", "application/json", strings.NewReader("{invalid-json"))
	if err != nil {
		t.Fatalf("POST /api/agents/aida failed: %v", err)
	}
	_ = respAlias.Body.Close()
	if respAlias.StatusCode != http.StatusNotFound {
		t.Errorf("POST /api/agents/aida returned %d, want 404", respAlias.StatusCode)
	}
}

func TestServer_FailFastAndHelpers(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected New() with nil Agent to fail fast")
	}

	aida := newTestAgent(t)
	webDir := newTestWebDir(t)

	if _, err := New(Config{
		Agent:     aida,
		AssetsDir: filepath.Join(t.TempDir(), "nonexistent-assets"),
		WebDir:    webDir,
	}); err == nil || !strings.Contains(err.Error(), "assets directory") {
		t.Fatalf("expected New() with nonexistent AssetsDir to fail fast with 'assets directory', got: %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "not-a-dir.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := New(Config{
		Agent:     aida,
		AssetsDir: filePath,
		WebDir:    webDir,
	}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected New() with file as AssetsDir to fail fast with 'not a directory', got: %v", err)
	}

	// Missing webDir or missing webDir/index.html must fail fast with actionable build instructions
	if _, err := New(Config{
		Agent:     aida,
		AssetsDir: filepath.Join("..", "..", "assets"),
		WebDir:    filepath.Join(t.TempDir(), "missing-web-dist"),
	}); err == nil || !strings.Contains(err.Error(), "compiled web cockpit not found at") || !strings.Contains(err.Error(), "make build-web") {
		t.Fatalf("expected New() with missing WebDir to fail fast with build instructions, got: %v", err)
	}

	emptyWebDir := t.TempDir()
	if _, err := New(Config{
		Agent:     aida,
		AssetsDir: filepath.Join("..", "..", "assets"),
		WebDir:    emptyWebDir,
	}); err == nil || !strings.Contains(err.Error(), "compiled web cockpit not found at") || !strings.Contains(err.Error(), "index.html") {
		t.Fatalf("expected New() with WebDir missing index.html to fail fast, got: %v", err)
	}

	var nilCtx context.Context
	if _, err := CollectSystemStatus(nilCtx, aida); err == nil {
		t.Fatal("expected CollectSystemStatus with nil context to fail fast")
	}
	if _, err := CollectSystemStatus(context.Background(), nil); err == nil {
		t.Fatal("expected CollectSystemStatus with nil agent to fail fast")
	}

	if got := ComputeHealth(20, 40); got != HealthNominal {
		t.Errorf("ComputeHealth(20, 40) = %q, want %q", got, HealthNominal)
	}
	if got := ComputeHealth(80, 40); got != HealthWarning {
		t.Errorf("ComputeHealth(80, 40) = %q, want %q", got, HealthWarning)
	}
	if got := ComputeHealth(20, 95); got != HealthCritical {
		t.Errorf("ComputeHealth(20, 95) = %q, want %q", got, HealthCritical)
	}

	srv, err := New(Config{
		Agent:     aida,
		AssetsDir: filepath.Join("..", "..", "assets"),
		WebDir:    webDir,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if err := srv.ListenAndServe(context.Background(), ""); err == nil {
		t.Fatal("expected ListenAndServe with empty addr to fail fast")
	}

	// Non-loopback bind must be rejected when AllowRemote is false
	for _, nonLoopback := range []string{":8080", "0.0.0.0:8080", "192.168.1.10:8080"} {
		err := srv.ListenAndServe(context.Background(), nonLoopback)
		if err == nil || !strings.Contains(err.Error(), "refusing to bind to non-loopback address") {
			t.Fatalf("expected ListenAndServe(%q) with AllowRemote=false to fail fast refusing non-loopback bind, got: %v", nonLoopback, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := srv.ListenAndServe(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("ListenAndServe with context cancellation returned error: %v", err)
	}
}

func TestServer_CPUSamplingAndOriginValidation(t *testing.T) {
	var (
		mu   sync.Mutex
		prev *cpuSample
	)
	t0 := time.Now()

	// Initial Unix sample uses load1m / numCPU * 100 => 2.0 / 4 * 100 = 50%
	initial := computeCPUPercent(10_000, 100, 2.0, true, 4, t0, &mu, &prev)
	if initial != 50.0 {
		t.Errorf("initial computeCPUPercent = %v, want 50.0", initial)
	}
	if prev == nil || prev.totalCPUMs != 10_000 {
		t.Fatalf("expected prev sample to be recorded with totalCPUMs=10000, got %+v", prev)
	}

	// Second sample 1000ms later with +1000ms CPU across 4 cores => 1000 / (1000 * 4) * 100 = 25%
	second := computeCPUPercent(11_000, 101, 2.0, true, 4, t0.Add(1*time.Second), &mu, &prev)
	if second != 25.0 {
		t.Errorf("delta computeCPUPercent = %v, want 25.0", second)
	}

	// Origin validation checks
	validOrigins := []string{
		"http://127.0.0.1",
		"http://127.0.0.1:8080",
		"http://localhost",
		"http://localhost:5173",
		"http://[::1]",
		"http://[::1]:8080",
	}
	for _, o := range validOrigins {
		if !isAllowedLoopbackOrigin(o) {
			t.Errorf("expected isAllowedLoopbackOrigin(%q) = true, got false", o)
		}
	}

	invalidOrigins := []string{
		"",
		"null",
		"https://localhost:5173",
		"http://evil.com",
		"http://localhost.evil.com",
		"http://127.0.0.1:99999",
		"http://user@localhost:5173",
		"http://localhost:5173/path",
		"http://localhost:5173?query=1",
	}
	for _, o := range invalidOrigins {
		if isAllowedLoopbackOrigin(o) {
			t.Errorf("expected isAllowedLoopbackOrigin(%q) = false, got true", o)
		}
	}
}
