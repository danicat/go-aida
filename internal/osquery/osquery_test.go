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
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/genkit"
)

func TestNewRunnerAndVersion(t *testing.T) {
	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner() failed unexpectedly: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ver, err := runner.Version(ctx)
	if err != nil {
		t.Fatalf("runner.Version() failed: %v", err)
	}
	if !strings.Contains(strings.ToLower(ver), "osquery") && ver == "" {
		t.Fatalf("runner.Version() returned unexpected version output: %q", ver)
	}
}

func TestNewRunnerWithBinary_FailFast(t *testing.T) {
	if _, err := NewRunnerWithBinary(""); err == nil {
		t.Fatal("expected error for empty binary name, got nil")
	}

	missingBinary := "osqueryi-definitely-not-installed-aida-test-binary"
	_, err := NewRunnerWithBinary(missingBinary)
	if err == nil {
		t.Fatalf("expected error for missing binary %q, got nil", missingBinary)
	}
	if !strings.Contains(err.Error(), missingBinary) {
		t.Fatalf("expected error %q to mention binary name %q", err.Error(), missingBinary)
	}
	if hostPath := os.Getenv("PATH"); hostPath != "" && strings.Contains(err.Error(), hostPath) {
		t.Fatalf("expected error %q not to leak full host PATH", err.Error())
	}

	tempDir := t.TempDir()
	_, err = NewRunnerWithBinary(tempDir)
	if err == nil {
		t.Fatalf("expected error when binary path is a directory (%q), got nil", tempDir)
	}
}

func TestRunnerQueryAndExecute(t *testing.T) {
	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rows, err := runner.Query(ctx, "SELECT version, build_platform FROM osquery_info;")
	if err != nil {
		t.Fatalf("runner.Query() failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0]["version"] == nil || rows[0]["version"] == "" {
		t.Fatalf("expected non-empty osquery_info.version in row: %#v", rows[0])
	}

	// Verify WITH CTE and PRAGMA queries are allowed.
	cteRows, err := runner.Query(ctx, "WITH info AS (SELECT version AS created_at, build_platform AS update_time FROM osquery_info) SELECT created_at, update_time FROM info;")
	if err != nil {
		t.Fatalf("runner.Query(WITH CTE) failed: %v", err)
	}
	if len(cteRows) != 1 {
		t.Fatalf("len(cteRows) = %d, want 1", len(cteRows))
	}

	pragmaRows, err := runner.Query(ctx, "PRAGMA table_info(osquery_info);")
	if err != nil {
		t.Fatalf("runner.Query(PRAGMA) failed: %v", err)
	}
	if len(pragmaRows) == 0 {
		t.Fatal("expected non-empty rows from PRAGMA table_info(osquery_info)")
	}

	out, err := runner.Execute(ctx, QueryInput{
		Query: "SELECT version FROM osquery_info;",
	})
	if err != nil {
		t.Fatalf("runner.Execute() failed: %v", err)
	}
	if out.RowCount != 1 || len(out.Rows) != 1 {
		t.Fatalf("unexpected QueryOutput row count: %#v", out)
	}
	if out.BinaryPath == "" {
		t.Fatalf("expected non-empty BinaryPath in QueryOutput: %#v", out)
	}
}

func TestRunnerQuery_FailFastOnInvalidAndForbiddenSQL(t *testing.T) {
	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rejectedQueries := []struct {
		name  string
		query string
	}{
		{name: "empty", query: "   "},
		{name: "only semicolon", query: " ; "},
		{name: "flag injection --flagfile", query: "--flagfile=/etc/passwd"},
		{name: "flag injection -version", query: "-version"},
		{name: "dot command .shell", query: ".shell id"},
		{name: "dot command .tables", query: ".tables"},
		{name: "multi-statement", query: "SELECT 1; SELECT 2;"},
		{name: "non-select prefix", query: "EXPLAIN QUERY PLAN SELECT 1;"},
		{name: "ATTACH keyword", query: "SELECT 1 WHERE 'a' = ATTACH;"},
		{name: "DETACH keyword", query: "SELECT DETACH FROM osquery_info;"},
		{name: "INSERT keyword", query: "INSERT INTO osquery_info VALUES (1);"},
		{name: "UPDATE keyword", query: "UPDATE osquery_info SET version = 'x';"},
		{name: "DELETE keyword", query: "DELETE FROM osquery_info;"},
		{name: "DROP keyword", query: "SELECT 1 FROM DROP;"},
		{name: "CREATE keyword", query: "CREATE TABLE t (x INT);"},
		{name: "ALTER keyword", query: "SELECT ALTER FROM osquery_info;"},
		{name: "REPLACE keyword", query: "REPLACE INTO osquery_info VALUES (1);"},
		{name: "LOAD_EXTENSION keyword", query: "SELECT load_extension('/tmp/evil.dylib');"},
		{name: "CURL table", query: "SELECT * FROM curl WHERE url = 'https://example.com';"},
		{name: "CARVES table", query: "SELECT * FROM carves;"},
	}

	for _, tc := range rejectedQueries {
		if _, err := runner.Query(ctx, tc.query); err == nil {
			t.Fatalf("case %q: expected query %q to be rejected, got nil", tc.name, tc.query)
		}
	}

	badSQL := "SELECT * FROM table_that_does_not_exist_in_osquery_xyz;"
	_, err = runner.Query(ctx, badSQL)
	if err == nil {
		t.Fatalf("expected error for invalid table query %q, got nil", badSQL)
	}
	if !strings.Contains(err.Error(), "table_that_does_not_exist_in_osquery_xyz") {
		t.Fatalf("expected error %q to include failing SQL query", err.Error())
	}
}

func TestLimitedBuffer_ExceedsLimit(t *testing.T) {
	lb := &limitedBuffer{maxBytes: 8}
	if _, err := lb.Write([]byte("12345")); err != nil {
		t.Fatalf("unexpected error within limit: %v", err)
	}
	if _, err := lb.Write([]byte("67890")); err == nil {
		t.Fatal("expected error when writing past maxBytes, got nil")
	}
	if !lb.exceeded {
		t.Fatal("expected lb.exceeded == true")
	}
	if lb.String() != "12345678" {
		t.Fatalf("lb.String() = %q, want %q", lb.String(), "12345678")
	}
}

func TestRegisterTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	g := genkit.Init(ctx)
	runner, err := NewRunner()
	if err != nil {
		t.Fatalf("NewRunner() failed: %v", err)
	}

	tool, err := RegisterTool(g, runner)
	if err != nil {
		t.Fatalf("RegisterTool() failed: %v", err)
	}
	if tool.Name() != ToolName {
		t.Fatalf("tool.Name() = %q, want %q", tool.Name(), ToolName)
	}

	lookedUp := genkit.LookupTool(g, ToolName)
	if lookedUp == nil {
		t.Fatalf("genkit.LookupTool(g, %q) returned nil", ToolName)
	}

	rawResult, err := tool.RunRaw(ctx, map[string]any{
		"query": "SELECT version, build_platform FROM osquery_info;",
	})
	if err != nil {
		t.Fatalf("tool.RunRaw() failed: %v", err)
	}

	resultMap, ok := rawResult.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any from tool.RunRaw(), got %T (%#v)", rawResult, rawResult)
	}
	rowCount, ok := resultMap["rowCount"].(float64)
	if !ok || int(rowCount) != 1 {
		t.Fatalf("expected rowCount == 1 in tool output, got %#v", resultMap)
	}
}
