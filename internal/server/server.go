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
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	genkitx "github.com/firebase/genkit/go/genkit/exp"

	"github.com/danicat/go-aida/internal/agent"
)

const (
	// DefaultAddr is the default loopback HTTP listen address for the AIDA Web Cockpit.
	DefaultAddr = "127.0.0.1:8080"

	// DefaultAssetsDir is the default directory containing PC-98 avatar sprite PNGs.
	DefaultAssetsDir = "assets"

	// DefaultWebDir is the default directory containing compiled frontend static assets.
	DefaultWebDir = "web/dist"

	// HealthNominal indicates normal CPU and memory utilization (<= 75%).
	HealthNominal = "NOMINAL"

	// HealthWarning indicates elevated CPU or memory utilization (> 75% and <= 90%).
	HealthWarning = "WARNING"

	// HealthCritical indicates critical CPU or memory utilization (> 90%).
	HealthCritical = "CRITICAL"

	// maxRequestBodyBytes caps incoming POST request payloads at 1 MiB.
	maxRequestBodyBytes = 1 << 20

	// maxCPUSampleAge is the maximum age of a previous CPU sample used for delta calculation.
	maxCPUSampleAge = 5 * time.Minute

	queryCombinedStatus = `SELECT
  s.hostname,
  s.cpu_brand,
  s.physical_memory,
  o.name AS os_name,
  o.version AS os_version,
  o.build AS os_build,
  i.version AS osquery_version,
  u.days,
  u.hours,
  u.minutes,
  u.seconds,
  u.total_seconds,
  (SELECT COALESCE(SUM(resident_size), 0) FROM processes WHERE resident_size > 0) AS total_rss,
  (SELECT COALESCE(SUM(user_time + system_time), 0) FROM processes WHERE user_time >= 0 AND system_time >= 0) AS total_cpu_ms,
  (SELECT average FROM load_average WHERE period = '1m' LIMIT 1) AS load_1m
FROM system_info s
CROSS JOIN os_version o
CROSS JOIN osquery_info i
CROSS JOIN uptime u
LIMIT 1;`

	queryCombinedStatusWindows = `SELECT
  s.hostname,
  s.cpu_brand,
  s.physical_memory,
  o.name AS os_name,
  o.version AS os_version,
  o.build AS os_build,
  i.version AS osquery_version,
  u.days,
  u.hours,
  u.minutes,
  u.seconds,
  u.total_seconds,
  (SELECT COALESCE(SUM(resident_size), 0) FROM processes WHERE resident_size > 0) AS total_rss,
  (SELECT COALESCE(SUM(user_time + system_time), 0) FROM processes WHERE user_time >= 0 AND system_time >= 0) AS total_cpu_ms
FROM system_info s
CROSS JOIN os_version o
CROSS JOIN osquery_info i
CROSS JOIN uptime u
LIMIT 1;`
)

// Config holds initialization settings for the AIDA HTTP and A2UI server.
type Config struct {
	Agent       *agent.AIDA
	AssetsDir   string // defaults to "assets"
	WebDir      string // defaults to "web/dist"
	AllowRemote bool   // allow binding to non-loopback network interfaces
}

// SystemStatus represents the live host telemetry payload returned by GET /api/system-status.
type SystemStatus struct {
	Hostname       string  `json:"hostname"`
	OS             string  `json:"os"`
	Arch           string  `json:"arch"`
	OSSkill        string  `json:"osSkill"`
	Kernel         string  `json:"kernel"`
	Uptime         string  `json:"uptime"`
	OsqueryVersion string  `json:"osqueryVersion"`
	Model          string  `json:"model"`
	ThinkingLevel  string  `json:"thinkingLevel"`
	Health         string  `json:"health"` // "NOMINAL", "WARNING", or "CRITICAL"
	CPU            float64 `json:"cpu"`
	Memory         float64 `json:"memory"`
}

type cpuSample struct {
	totalCPUMs int64
	sampledAt  time.Time
}

// Server wraps an initialized *agent.AIDA and exposes Genkit agent streaming endpoints,
// live osqueryi system telemetry, avatar assets, and static web cockpit files over HTTP.
type Server struct {
	agent       *agent.AIDA
	assetsDir   string
	webDir      string
	allowRemote bool
	mux         *http.ServeMux
	handler     http.Handler
	routes      []string

	cpuMu         sync.Mutex
	prevCPUSample *cpuSample
}

// New initializes a new AIDA HTTP server, mounts all Genkit agent routes, telemetry endpoints,
// and static asset handlers, and wraps the server in strict loopback CORS and security middleware.
// It fails fast if the agent, assets directory, or compiled web cockpit is missing or invalid.
func New(cfg Config) (*Server, error) {
	if cfg.Agent == nil {
		return nil, errors.New("cannot initialize server: AIDA agent is nil")
	}
	if cfg.Agent.Genkit() == nil {
		return nil, errors.New("cannot initialize server: AIDA Genkit instance is nil")
	}
	if cfg.Agent.Agent() == nil {
		return nil, errors.New("cannot initialize server: underlying Genkit agent is nil")
	}
	if cfg.Agent.OsqueryRunner() == nil {
		return nil, errors.New("cannot initialize server: AIDA osquery runner is nil")
	}

	assetsDir := strings.TrimSpace(cfg.AssetsDir)
	if assetsDir == "" {
		assetsDir = DefaultAssetsDir
	}
	assetsInfo, err := os.Stat(assetsDir)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize server: assets directory %q is missing or inaccessible: %w", assetsDir, err)
	}
	if !assetsInfo.IsDir() {
		return nil, fmt.Errorf("cannot initialize server: assets path %q is not a directory", assetsDir)
	}

	webDir := strings.TrimSpace(cfg.WebDir)
	if webDir == "" {
		webDir = DefaultWebDir
	}
	webInfo, err := os.Stat(webDir)
	if err != nil || !webInfo.IsDir() {
		return nil, fmt.Errorf(
			"cannot initialize server: compiled web cockpit not found at %q (run \"make build-web\" or \"cd web && npm install && npm run build\" first)",
			webDir,
		)
	}
	indexPath := filepath.Join(webDir, "index.html")
	indexInfo, err := os.Stat(indexPath)
	if err != nil || !indexInfo.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"cannot initialize server: compiled web cockpit not found at %q (run \"make build-web\" or \"cd web && npm install && npm run build\" first)",
			indexPath,
		)
	}

	mux := http.NewServeMux()
	srv := &Server{
		agent:       cfg.Agent,
		assetsDir:   assetsDir,
		webDir:      webDir,
		allowRemote: cfg.AllowRemote,
		mux:         mux,
	}

	routes := genkitx.AllAgentRoutes(cfg.Agent.Genkit())
	if len(routes) == 0 {
		return nil, errors.New("cannot initialize server: genkitx.AllAgentRoutes returned zero routes")
	}
	for _, route := range routes {
		handler := route.Handler()
		pattern := route.Pattern()
		mux.HandleFunc(pattern, handler)
		srv.routes = append(srv.routes, pattern)
	}

	mux.HandleFunc("GET /api/system-status", srv.handleSystemStatus)

	assetsFS := http.StripPrefix("/assets/", http.FileServer(http.Dir(assetsDir)))
	webFS := http.FileServer(http.Dir(webDir))
	mux.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/assets/")
		if rel == "" || strings.Contains(rel, "..") {
			http.NotFound(w, r)
			return
		}
		info, statErr := os.Stat(filepath.Join(assetsDir, filepath.FromSlash(rel)))
		if statErr != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		assetsFS.ServeHTTP(w, r)
	})

	mux.Handle("/", webFS)

	srv.handler = WithCORS(mux)
	return srv, nil
}

// Handler returns the root HTTP handler (wrapped with CORS and security middleware).
func (s *Server) Handler() http.Handler {
	if s == nil {
		return nil
	}
	return s.handler
}

// Routes returns a copy of the registered Genkit agent HTTP route patterns.
func (s *Server) Routes() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.routes))
	copy(out, s.routes)
	return out
}

// ListenAndServe binds to addr and serves HTTP requests until ctx is canceled.
// Unless AllowRemote is enabled on the Server, addr must specify a loopback host
// ("127.0.0.1", "::1", or "localhost").
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	if s == nil || s.handler == nil {
		return errors.New("cannot start server: Server is not initialized")
	}
	if ctx == nil {
		return errors.New("cannot start server: context is nil")
	}
	trimmedAddr := strings.TrimSpace(addr)
	if trimmedAddr == "" {
		return errors.New("cannot start server: listen address must not be empty")
	}

	host, _, err := net.SplitHostPort(trimmedAddr)
	if err != nil {
		return fmt.Errorf("cannot start server: invalid listen address %q: %w", trimmedAddr, err)
	}
	if !s.allowRemote && !isLoopbackHost(host) {
		return fmt.Errorf(
			"cannot start server: refusing to bind to non-loopback address %q without AllowRemote=true (-allow-remote); use 127.0.0.1, ::1, or localhost",
			trimmedAddr,
		)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", trimmedAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %q: %w", trimmedAddr, err)
	}

	httpServer := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           s.handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    maxRequestBodyBytes,
	}

	errCh := make(chan error, 1)
	go func() {
		if serveErr := httpServer.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
			return fmt.Errorf("server shutdown failed: %w", shutdownErr)
		}
		return nil
	case serveErr := <-errCh:
		return serveErr
	}
}

// WithCORS wraps next with strict loopback CORS validation, standard security headers,
// and a 1 MiB body limit on POST requests. Non-empty Origin headers that do not match
// an allowed loopback origin are rejected immediately with 403 Forbidden.
func WithCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")

		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if !isAllowedLoopbackOrigin(origin) {
				writeJSONError(w, http.StatusForbidden, fmt.Errorf("origin %q is not an allowed loopback origin", origin))
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, X-Requested-With")
		} else if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, X-Requested-With")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method == http.MethodPost && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}

		if next != nil {
			next.ServeHTTP(w, r)
		}
	})
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

func isAllowedLoopbackOrigin(origin string) bool {
	trimmed := strings.TrimSpace(origin)
	if trimmed == "" {
		return false
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if port := u.Port(); port != "" {
		p, portErr := strconv.Atoi(port)
		if portErr != nil || p < 1 || p > 65535 {
			return false
		}
	}
	return isLoopbackHost(u.Hostname())
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.CollectSystemStatus(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	payload, err := json.Marshal(status)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal system status: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(payload, '\n'))
}

func writeJSONError(w http.ResponseWriter, statusCode int, err error) {
	payload, marshalErr := json.Marshal(map[string]string{
		"error": err.Error(),
	})
	if marshalErr != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = w.Write(append(payload, '\n'))
}

// CollectSystemStatus executes a single live osqueryi diagnostic query via the server's AIDA agent
// and computes host CPU load (using delta sampling across consecutive polls), memory usage, and health status.
func (s *Server) CollectSystemStatus(ctx context.Context) (SystemStatus, error) {
	if s == nil || s.agent == nil {
		return SystemStatus{}, errors.New("cannot collect system status: server or AIDA agent is nil")
	}
	return collectSystemStatusWithSampler(ctx, s.agent, &s.cpuMu, &s.prevCPUSample)
}

// CollectSystemStatus executes a single combined osqueryi query against system_info, os_version,
// osquery_info, uptime, processes, and (on Unix) load_average via aida.OsqueryRunner()
// and returns a populated SystemStatus.
// It fails fast with a descriptive error if the osqueryi call fails or returns malformed data.
func CollectSystemStatus(ctx context.Context, aida *agent.AIDA) (SystemStatus, error) {
	return collectSystemStatusWithSampler(ctx, aida, nil, nil)
}

func collectSystemStatusWithSampler(
	ctx context.Context,
	aida *agent.AIDA,
	cpuMu *sync.Mutex,
	prevSample **cpuSample,
) (SystemStatus, error) {
	if ctx == nil {
		return SystemStatus{}, errors.New("cannot collect system status: context is nil")
	}
	if aida == nil {
		return SystemStatus{}, errors.New("cannot collect system status: AIDA agent is nil")
	}
	runner := aida.OsqueryRunner()
	if runner == nil {
		return SystemStatus{}, errors.New("cannot collect system status: osquery runner is nil")
	}

	osSkill := aida.OS()
	includeLoadAvg := osSkill != "windows"

	query := queryCombinedStatus
	if !includeLoadAvg {
		query = queryCombinedStatusWindows
	}

	rows, err := runner.Query(ctx, query)
	if err != nil {
		return SystemStatus{}, fmt.Errorf("combined system status query failed: %w", err)
	}
	if len(rows) == 0 {
		return SystemStatus{}, errors.New("combined system status query returned zero rows")
	}

	sampledAt := time.Now()
	row := rows[0]

	hostname, err := parseRequiredString(row, "hostname")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid system_info.hostname: %w", err)
	}
	cpuBrand := parseOptionalString(row, "cpu_brand")

	physicalMemory, err := parseInt64(row, "physical_memory")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid system_info.physical_memory: %w", err)
	}
	if physicalMemory <= 0 {
		return SystemStatus{}, fmt.Errorf("invalid system_info.physical_memory: must be > 0, got %d", physicalMemory)
	}

	osName, err := parseRequiredString(row, "os_name")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid os_version.name: %w", err)
	}
	osVer, err := parseRequiredString(row, "os_version")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid os_version.version: %w", err)
	}
	osBuild := parseOptionalString(row, "os_build")

	osqueryVersion, err := parseRequiredString(row, "osquery_version")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid osquery_info.version: %w", err)
	}

	days, err := parseInt64(row, "days")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid uptime.days: %w", err)
	}
	hours, err := parseInt64(row, "hours")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid uptime.hours: %w", err)
	}
	minutes, err := parseInt64(row, "minutes")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid uptime.minutes: %w", err)
	}
	seconds, err := parseInt64(row, "seconds")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid uptime.seconds: %w", err)
	}
	totalSeconds, err := parseInt64(row, "total_seconds")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid uptime.total_seconds: %w", err)
	}
	if totalSeconds <= 0 {
		return SystemStatus{}, fmt.Errorf("invalid uptime.total_seconds: must be > 0, got %d", totalSeconds)
	}

	totalRSS, err := parseInt64(row, "total_rss")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid processes.total_rss: %w", err)
	}
	if totalRSS < 0 {
		return SystemStatus{}, fmt.Errorf("invalid processes.total_rss: must be >= 0, got %d", totalRSS)
	}

	totalCPUMs, err := parseInt64(row, "total_cpu_ms")
	if err != nil {
		return SystemStatus{}, fmt.Errorf("invalid processes.total_cpu_ms: %w", err)
	}
	if totalCPUMs < 0 {
		return SystemStatus{}, fmt.Errorf("invalid processes.total_cpu_ms: must be >= 0, got %d", totalCPUMs)
	}

	var load1m float64
	if includeLoadAvg {
		load1m, err = parseFloat64(row, "load_1m")
		if err != nil {
			return SystemStatus{}, fmt.Errorf("invalid load_average.average: %w", err)
		}
		if load1m < 0 {
			return SystemStatus{}, fmt.Errorf("invalid load_average.average: must be >= 0, got %v", load1m)
		}
	}

	memoryPct := clampPercent((float64(totalRSS) / float64(physicalMemory)) * 100.0)

	numCPU := runtime.NumCPU()
	if numCPU < 1 {
		numCPU = 1
	}

	cpuPct := computeCPUPercent(
		totalCPUMs,
		totalSeconds,
		load1m,
		includeLoadAvg,
		numCPU,
		sampledAt,
		cpuMu,
		prevSample,
	)

	arch := runtime.GOARCH
	return SystemStatus{
		Hostname:       hostname,
		OS:             fmt.Sprintf("%s (%s)", osSkill, arch),
		Arch:           arch,
		OSSkill:        osSkill,
		Kernel:         formatKernel(osName, osVer, osBuild, cpuBrand),
		Uptime:         formatUptime(days, hours, minutes, seconds),
		OsqueryVersion: cleanOsqueryVersion(osqueryVersion),
		Model:          aida.Model(),
		ThinkingLevel:  aida.ThinkingLevel(),
		Health:         ComputeHealth(cpuPct, memoryPct),
		CPU:            cpuPct,
		Memory:         memoryPct,
	}, nil
}

func computeCPUPercent(
	totalCPUMs int64,
	totalSeconds int64,
	load1m float64,
	includeLoadAvg bool,
	numCPU int,
	sampledAt time.Time,
	cpuMu *sync.Mutex,
	prevSample **cpuSample,
) float64 {
	if cpuMu != nil && prevSample != nil {
		cpuMu.Lock()
		prev := *prevSample
		*prevSample = &cpuSample{
			totalCPUMs: totalCPUMs,
			sampledAt:  sampledAt,
		}
		cpuMu.Unlock()

		if prev != nil {
			elapsed := sampledAt.Sub(prev.sampledAt)
			deltaWallMs := float64(elapsed) / float64(time.Millisecond)
			deltaCPUMs := totalCPUMs - prev.totalCPUMs
			if elapsed > 0 && elapsed <= maxCPUSampleAge && deltaWallMs > 0 && deltaCPUMs >= 0 {
				return clampPercent((float64(deltaCPUMs) / (deltaWallMs * float64(numCPU))) * 100.0)
			}
		}
	}

	if includeLoadAvg {
		return clampPercent((load1m / float64(numCPU)) * 100.0)
	}
	cpuSeconds := float64(totalCPUMs) / 1000.0
	capacitySeconds := float64(totalSeconds) * float64(numCPU)
	return clampPercent((cpuSeconds / capacitySeconds) * 100.0)
}

// ComputeHealth evaluates host CPU and memory percentages and returns
// "CRITICAL" (> 90%), "WARNING" (> 75%), or "NOMINAL".
func ComputeHealth(cpu, memory float64) string {
	if cpu > 90 || memory > 90 {
		return HealthCritical
	}
	if cpu > 75 || memory > 75 {
		return HealthWarning
	}
	return HealthNominal
}

func clampPercent(val float64) float64 {
	if math.IsNaN(val) || math.IsInf(val, 0) || val < 0 {
		return 0
	}
	if val > 100 {
		val = 100
	}
	return math.Round(val*10) / 10
}

func formatKernel(name, version, build, cpuBrand string) string {
	base := strings.TrimSpace(name + " " + version)
	if build != "" {
		base = fmt.Sprintf("%s (%s)", base, build)
	}
	if cpuBrand != "" {
		return fmt.Sprintf("%s • %s", base, cpuBrand)
	}
	return base
}

func formatUptime(days, hours, minutes, seconds int64) string {
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	return fmt.Sprintf("%dm %ds", minutes, seconds)
}

func cleanOsqueryVersion(raw string) string {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "osqueryi version ")
	trimmed = strings.TrimPrefix(trimmed, "osqueryd version ")
	return strings.TrimSpace(trimmed)
}

func parseRequiredString(row map[string]any, key string) (string, error) {
	val, exists := row[key]
	if !exists || val == nil {
		return "", fmt.Errorf("missing column %q", key)
	}
	str := strings.TrimSpace(fmt.Sprintf("%v", val))
	if str == "" {
		return "", fmt.Errorf("column %q is empty", key)
	}
	return str, nil
}

func parseOptionalString(row map[string]any, key string) string {
	val, exists := row[key]
	if !exists || val == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", val))
}

func parseInt64(row map[string]any, key string) (int64, error) {
	val, exists := row[key]
	if !exists || val == nil {
		return 0, fmt.Errorf("missing column %q", key)
	}
	switch v := val.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case json.Number:
		return v.Int64()
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, fmt.Errorf("column %q is empty", key)
		}
		if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			return parsed, nil
		}
		fParsed, fErr := strconv.ParseFloat(trimmed, 64)
		if fErr != nil {
			return 0, fmt.Errorf("cannot parse %q as int64: %w", trimmed, fErr)
		}
		return int64(fParsed), nil
	default:
		return 0, fmt.Errorf("unexpected type %T for column %q", val, key)
	}
}

func parseFloat64(row map[string]any, key string) (float64, error) {
	val, exists := row[key]
	if !exists || val == nil {
		return 0, fmt.Errorf("missing column %q", key)
	}
	switch v := val.(type) {
	case float64:
		return v, nil
	case int64:
		return float64(v), nil
	case int:
		return float64(v), nil
	case json.Number:
		return v.Float64()
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, fmt.Errorf("column %q is empty", key)
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse %q as float64: %w", trimmed, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("unexpected type %T for column %q", val, key)
	}
}
