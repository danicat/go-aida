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

package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

const (
	// ToolName is the canonical Genkit tool name used by the AIDA prompt and agent.
	ToolName = "run_osquery"

	// DefaultBinary is the required osquery interactive shell executable name.
	DefaultBinary = "osqueryi"

	// DefaultQueryTimeout bounds any individual osqueryi command execution.
	DefaultQueryTimeout = 15 * time.Second

	// maxOutputBytes caps osqueryi stdout and stderr buffers at 4 MiB to prevent OOM crashes.
	maxOutputBytes = 4 << 20
)

var forbiddenSQLTokens = map[string]struct{}{
	"ATTACH":         {},
	"DETACH":         {},
	"INSERT":         {},
	"UPDATE":         {},
	"DELETE":         {},
	"DROP":           {},
	"CREATE":         {},
	"ALTER":          {},
	"REPLACE":        {},
	"LOAD_EXTENSION": {},
	"CURL":           {},
	"CARVES":         {},
}

// QueryInput defines the schema for the run_osquery Genkit tool input.
type QueryInput struct {
	Query string `json:"query" jsonschema:"description=The SQL SELECT query to execute against the local host via osqueryi --json"`
}

// QueryOutput defines the structured output returned by the run_osquery Genkit tool.
type QueryOutput struct {
	Query      string           `json:"query"`
	BinaryPath string           `json:"binaryPath"`
	RowCount   int              `json:"rowCount"`
	Rows       []map[string]any `json:"rows"`
}

// Runner executes SQL diagnostic queries against the local system using osqueryi.
type Runner struct {
	binaryPath string
}

func verifyBinaryByName(binary string) (string, error) {
	trimmed := strings.TrimSpace(binary)
	if trimmed == "" {
		return "", errors.New("osquery binary check failed: binary name or path is empty")
	}

	resolvedPath, err := exec.LookPath(trimmed)
	if err != nil {
		return "", fmt.Errorf(
			"osquery binary %q is not installed or not found in PATH: %w",
			trimmed,
			err,
		)
	}

	info, statErr := os.Stat(resolvedPath)
	if statErr != nil {
		return "", fmt.Errorf(
			"osquery binary %q resolved to %q but stat failed: %w",
			trimmed,
			resolvedPath,
			statErr,
		)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf(
			"osquery binary %q resolved to non-regular file %q (mode=%s)",
			trimmed,
			resolvedPath,
			info.Mode(),
		)
	}

	return resolvedPath, nil
}

// NewRunner creates an osquery Runner using the default "osqueryi" binary in PATH.
// It fails immediately if osqueryi is not installed.
func NewRunner() (*Runner, error) {
	return NewRunnerWithBinary(DefaultBinary)
}

// NewRunnerWithBinary creates an osquery Runner using the provided binary name or path.
// It fails immediately if the binary cannot be located or is not a valid regular file.
func NewRunnerWithBinary(binary string) (*Runner, error) {
	resolvedPath, err := verifyBinaryByName(binary)
	if err != nil {
		return nil, err
	}
	return &Runner{binaryPath: resolvedPath}, nil
}

// Version runs `osqueryi --version` and returns the trimmed version output.
func (r *Runner) Version(ctx context.Context) (string, error) {
	if err := r.validate(); err != nil {
		return "", err
	}
	if ctx == nil {
		return "", errors.New("osquery version check failed: context is nil")
	}

	execCtx, cancel := context.WithTimeout(ctx, DefaultQueryTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(execCtx, r.binaryPath, "--version")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf(
			"osquery version command %q --version failed (stdout=%q, stderr=%q): %w",
			r.binaryPath,
			strings.TrimSpace(stdout.String()),
			strings.TrimSpace(stderr.String()),
			err,
		)
	}

	version := strings.TrimSpace(stdout.String())
	if version == "" {
		version = strings.TrimSpace(stderr.String())
	}
	if version == "" {
		return "", fmt.Errorf("osquery version command %q --version returned empty output", r.binaryPath)
	}
	return version, nil
}

// Query validates that sql is a single read-only query, executes `osqueryi` with
// hardening flags, and parses the JSON array output into rows.
// It fails fast with rich context if the binary is invalid, the SQL is empty or
// violates read-only policy, output exceeds 4 MiB, osqueryi reports an error,
// or the output is not valid JSON.
func (r *Runner) Query(ctx context.Context, sql string) ([]map[string]any, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("osquery execution failed: context is nil")
	}

	trimmedSQL := strings.TrimSpace(sql)
	if err := validateReadOnlySQL(trimmedSQL); err != nil {
		return nil, err
	}

	execCtx, cancel := context.WithTimeout(ctx, DefaultQueryTimeout)
	defer cancel()

	stdout := &limitedBuffer{maxBytes: maxOutputBytes}
	stderr := &limitedBuffer{maxBytes: maxOutputBytes}
	cmd := exec.CommandContext(
		execCtx,
		r.binaryPath,
		"--disable_extensions=true",
		"--disable_carver=true",
		"--ephemeral=true",
		"--json",
		trimmedSQL,
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf(
			"osqueryi output exceeded %d-byte buffer limit (binary=%q, query=%q)",
			maxOutputBytes,
			r.binaryPath,
			trimmedSQL,
		)
	}

	rawStdout := strings.TrimSpace(stdout.String())
	rawStderr := strings.TrimSpace(stderr.String())

	if runErr != nil {
		return nil, fmt.Errorf(
			"osqueryi execution failed (binary=%q, query=%q, stderr=%q, stdout=%q): %w",
			r.binaryPath,
			trimmedSQL,
			rawStderr,
			rawStdout,
			runErr,
		)
	}

	if containsOsqueryError(rawStderr) {
		return nil, fmt.Errorf(
			"osqueryi reported SQL error (binary=%q, query=%q, stderr=%q, stdout=%q)",
			r.binaryPath,
			trimmedSQL,
			rawStderr,
			rawStdout,
		)
	}

	if rawStdout == "" {
		return nil, fmt.Errorf(
			"osqueryi returned empty JSON output (binary=%q, query=%q, stderr=%q)",
			r.binaryPath,
			trimmedSQL,
			rawStderr,
		)
	}

	var rows []map[string]any
	if err := json.Unmarshal([]byte(rawStdout), &rows); err != nil {
		return nil, fmt.Errorf(
			"failed to parse osqueryi JSON output (binary=%q, query=%q, stderr=%q, stdout=%q): %w",
			r.binaryPath,
			trimmedSQL,
			rawStderr,
			rawStdout,
			err,
		)
	}

	if rows == nil {
		rows = []map[string]any{}
	}
	return rows, nil
}

// Execute runs the structured QueryInput and returns a structured QueryOutput.
func (r *Runner) Execute(ctx context.Context, input QueryInput) (QueryOutput, error) {
	rows, err := r.Query(ctx, input.Query)
	if err != nil {
		return QueryOutput{}, err
	}
	return QueryOutput{
		Query:      strings.TrimSpace(input.Query),
		BinaryPath: r.binaryPath,
		RowCount:   len(rows),
		Rows:       rows,
	}, nil
}

// RegisterTool defines and registers the `run_osquery` tool on the given Genkit instance.
// If runner is nil, RegisterTool initializes a new default Runner and fails immediately if osqueryi is missing.
func RegisterTool(g *genkit.Genkit, runner *Runner) (ai.Tool, error) {
	if g == nil {
		return nil, errors.New("cannot register run_osquery tool: genkit instance is nil")
	}
	if runner == nil {
		var err error
		runner, err = NewRunner()
		if err != nil {
			return nil, fmt.Errorf("cannot register %s tool: %w", ToolName, err)
		}
	}
	if err := runner.validate(); err != nil {
		return nil, fmt.Errorf("cannot register %s tool: %w", ToolName, err)
	}

	tool := genkit.DefineTool(
		g,
		ToolName,
		"Execute a diagnostic SQL query on the local machine using osqueryi --json and return the parsed rows.",
		func(tc *ai.ToolContext, input QueryInput) (QueryOutput, error) {
			return runner.Execute(tc.Context, input)
		},
	)
	return tool, nil
}

func validateReadOnlySQL(trimmedSQL string) error {
	if trimmedSQL == "" {
		return errors.New("osquery execution failed: SQL query must not be empty")
	}
	if strings.HasPrefix(trimmedSQL, "-") || strings.HasPrefix(trimmedSQL, ".") {
		return fmt.Errorf(
			"osquery execution rejected: CLI flags and SQLite dot-commands are forbidden in query %q",
			trimmedSQL,
		)
	}

	withoutTrailing := strings.TrimSpace(strings.TrimSuffix(trimmedSQL, ";"))
	if withoutTrailing == "" {
		return errors.New("osquery execution failed: SQL query must not be empty")
	}
	if strings.Contains(withoutTrailing, ";") {
		return fmt.Errorf(
			"osquery execution rejected: multi-statement SQL queries are forbidden in %q",
			trimmedSQL,
		)
	}

	upper := strings.ToUpper(withoutTrailing)
	if !hasAllowedStatementPrefix(upper) {
		return fmt.Errorf(
			"osquery execution rejected: query must start with SELECT, WITH, or PRAGMA in %q",
			trimmedSQL,
		)
	}

	tokens := strings.FieldsFunc(upper, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_'
	})
	for _, tok := range tokens {
		if _, forbidden := forbiddenSQLTokens[tok]; forbidden {
			return fmt.Errorf(
				"osquery execution rejected: forbidden SQL keyword or table %q in query %q",
				tok,
				trimmedSQL,
			)
		}
	}
	return nil
}

func hasAllowedStatementPrefix(upperSQL string) bool {
	for _, prefix := range []string{"SELECT", "WITH", "PRAGMA"} {
		if strings.HasPrefix(upperSQL, prefix) && len(upperSQL) > len(prefix) {
			next := upperSQL[len(prefix)]
			if next == ' ' || next == '\t' || next == '\n' || next == '\r' {
				return true
			}
		}
	}
	return false
}

func (r *Runner) validate() error {
	if r == nil {
		return errors.New("osquery runner is nil")
	}
	if strings.TrimSpace(r.binaryPath) == "" {
		return errors.New("osquery runner binaryPath is empty")
	}
	return nil
}

func containsOsqueryError(stderr string) bool {
	if stderr == "" {
		return false
	}
	for line := range strings.SplitSeq(stderr, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Error:") || strings.Contains(trimmed, "Error: near") || strings.Contains(trimmed, "no such table") {
			return true
		}
	}
	return false
}

type limitedBuffer struct {
	buf      bytes.Buffer
	maxBytes int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.maxBytes > 0 && b.buf.Len()+len(p) > b.maxBytes {
		remaining := b.maxBytes - b.buf.Len()
		if remaining > 0 {
			_, _ = b.buf.Write(p[:remaining])
		}
		b.exceeded = true
		return 0, fmt.Errorf("output exceeded maximum buffer size (%d bytes)", b.maxBytes)
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
