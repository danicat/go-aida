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

package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/ai/exp/tool"
	"github.com/firebase/genkit/go/genkit"
	genkitx "github.com/firebase/genkit/go/genkit/exp"
	a2uix "github.com/firebase/genkit/go/plugins/a2ui/exp"
	"github.com/firebase/genkit/go/plugins/middleware"
	"google.golang.org/genai"
)

func chdirRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() failed: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("os.Chdir(%q) failed: %v", repoRoot, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origWD)
	})
	return repoRoot
}

func TestDetectOSAndValidateOS(t *testing.T) {
	detected, err := DetectOS()
	if err != nil {
		t.Fatalf("DetectOS() failed: %v", err)
	}
	if detected != runtime.GOOS {
		t.Fatalf("DetectOS() = %q, want %q", detected, runtime.GOOS)
	}

	for _, valid := range []string{"darwin", "LINUX", " windows "} {
		got, err := ValidateOS(valid)
		if err != nil {
			t.Fatalf("ValidateOS(%q) failed unexpectedly: %v", valid, err)
		}
		if got != strings.ToLower(strings.TrimSpace(valid)) {
			t.Fatalf("ValidateOS(%q) = %q", valid, got)
		}
	}

	for _, invalid := range []string{"", "   ", "freebsd", "solaris", "plan9"} {
		if _, err := ValidateOS(invalid); err == nil {
			t.Fatalf("ValidateOS(%q) succeeded, expected fail-fast error", invalid)
		}
	}
}

func TestResolveProjectIDLocationAndModel(t *testing.T) {
	gotProj, err := ResolveProjectID("explicit-project-123")
	if err != nil {
		t.Fatalf("ResolveProjectID(explicit) failed: %v", err)
	}
	if gotProj != "explicit-project-123" {
		t.Fatalf("ResolveProjectID() = %q, want %q", gotProj, "explicit-project-123")
	}

	if gotLoc := ResolveLocation("us-central1"); gotLoc != "us-central1" {
		t.Fatalf("ResolveLocation(explicit) = %q, want %q", gotLoc, "us-central1")
	}
	if gotDefaultLoc := ResolveLocation(""); gotDefaultLoc == "" {
		t.Fatal("ResolveLocation(\"\") returned empty string")
	}

	t.Setenv("AIDA_MODEL", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("GCLOUD_PROJECT", "")

	// Default when no env vars are set -> Vertex AI model.
	gotModel, err := ResolveModel(Config{})
	if err != nil {
		t.Fatalf("ResolveModel(default) failed: %v", err)
	}
	if gotModel != ModelName {
		t.Fatalf("ResolveModel(default) = %q, want %q", gotModel, ModelName)
	}

	// Default when GEMINI_API_KEY is set and no GCP project is set -> Google AI model.
	t.Setenv("GEMINI_API_KEY", "test-key-xyz")
	gotGoogleModel, err := ResolveModel(Config{})
	if err != nil {
		t.Fatalf("ResolveModel(GEMINI_API_KEY) failed: %v", err)
	}
	if gotGoogleModel != GoogleAIModelName {
		t.Fatalf("ResolveModel(GEMINI_API_KEY) = %q, want %q", gotGoogleModel, GoogleAIModelName)
	}

	// Explicit ProjectID overrides GoogleAI auto-default back to Vertex AI.
	gotVertexWithProj, err := ResolveModel(Config{ProjectID: "test-gcp-project"})
	if err != nil {
		t.Fatalf("ResolveModel(with ProjectID) failed: %v", err)
	}
	if gotVertexWithProj != ModelName {
		t.Fatalf("ResolveModel(with ProjectID) = %q, want %q", gotVertexWithProj, ModelName)
	}

	// Explicit AIDA_MODEL env var.
	t.Setenv("AIDA_MODEL", "googleai/gemini-3.8-pro")
	gotEnvModel, err := ResolveModel(Config{ProjectID: "test-gcp-project"})
	if err != nil {
		t.Fatalf("ResolveModel(AIDA_MODEL) failed: %v", err)
	}
	if gotEnvModel != "googleai/gemini-3.8-pro" {
		t.Fatalf("ResolveModel(AIDA_MODEL) = %q, want %q", gotEnvModel, "googleai/gemini-3.8-pro")
	}

	// Explicit Config.Model takes highest precedence.
	gotCfgModel, err := ResolveModel(Config{Model: "vertexai/gemini-3.8-pro"})
	if err != nil {
		t.Fatalf("ResolveModel(Config.Model) failed: %v", err)
	}
	if gotCfgModel != "vertexai/gemini-3.8-pro" {
		t.Fatalf("ResolveModel(Config.Model) = %q, want %q", gotCfgModel, "vertexai/gemini-3.8-pro")
	}

	// Invalid model prefixes fail fast.
	for _, invalidModel := range []string{"openai/gpt-4o", "vertexai/", "googleai/", "gemini-3.8-flash"} {
		if _, err := ResolveModel(Config{Model: invalidModel}); err == nil {
			t.Fatalf("expected ResolveModel(%q) to fail fast, got nil", invalidModel)
		}
	}
}

func TestAidaCatalogAndPromptDocumentation(t *testing.T) {
	chdirRepoRoot(t)

	if CatalogID != "aida" {
		t.Fatalf("CatalogID = %q, want %q", CatalogID, "aida")
	}

	cat := AidaCatalog()
	if cat == nil {
		t.Fatal("AidaCatalog() returned nil")
	}
	if cat.ID != CatalogID {
		t.Fatalf("cat.ID = %q, want %q", cat.ID, CatalogID)
	}

	expectedComponents := []string{
		"Panel",
		"Scene3D",
		"CyberChart",
		"HudGauge",
		"DataMatrix",
		"TextBlock",
		"ActionButton",
	}
	if len(cat.Components) != len(expectedComponents) {
		t.Fatalf("len(cat.Components) = %d, want %d", len(cat.Components), len(expectedComponents))
	}
	for i, want := range expectedComponents {
		got := cat.Components[i].Name
		if got != want {
			t.Fatalf("cat.Components[%d].Name = %q, want %q", i, got, want)
		}
		if strings.TrimSpace(cat.Components[i].Description) == "" {
			t.Fatalf("cat.Components[%d] (%s) has empty Description", i, got)
		}
		if strings.TrimSpace(cat.Components[i].Props) == "" {
			t.Fatalf("cat.Components[%d] (%s) has empty Props", i, got)
		}
	}

	if _, err := RegisterCatalog(nil); err == nil {
		t.Fatal("expected RegisterCatalog(nil) to fail fast, got nil")
	}

	promptBytes, err := os.ReadFile(filepath.Join("prompts", "aida.prompt"))
	if err != nil {
		t.Fatalf("failed to read prompts/aida.prompt: %v", err)
	}
	promptDoc := string(promptBytes)
	for _, comp := range cat.Components {
		if !strings.Contains(promptDoc, comp.Name) {
			t.Fatalf("expected prompts/aida.prompt to document component %q", comp.Name)
		}
	}
}

func TestRunCommandTool_InterruptApproveRejectAndExecute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	g := genkit.Init(ctx, genkit.WithExperimental())
	cmdTool := RegisterCommandTool(g)
	if cmdTool == nil {
		t.Fatal("RegisterCommandTool() returned nil")
	}

	// 1. Empty command, empty reason, and invalid risk all fail fast.
	invalidInputs := []map[string]any{
		{"command": "   ", "reason": "valid reason", "risk": "LOW"},
		{"command": "echo ok", "reason": "   ", "risk": "LOW"},
		{"command": "echo ok", "reason": "valid reason", "risk": ""},
		{"command": "echo ok", "reason": "valid reason", "risk": "UNKNOWN_RISK"},
	}
	for _, input := range invalidInputs {
		if _, err := cmdTool.RunRaw(ctx, input); err == nil {
			t.Fatalf("expected invalid runCommand input %#v to fail fast, got nil", input)
		}
	}

	// 2. Initial invocation (res == nil) triggers a typed CommandInterrupt.
	_, err := cmdTool.RunRaw(ctx, map[string]any{
		"command": "echo aida-hitl-verified",
		"reason":  "Verify HITL remediation execution",
		"risk":    "critical",
	})
	isIntr, intrMeta := ai.IsToolInterruptError(err)
	if !isIntr {
		t.Fatalf("expected ai.IsToolInterruptError(err) == true on initial invocation, got false (err=%v)", err)
	}
	if intrMeta == nil {
		t.Fatal("expected non-nil interrupt metadata map from ai.IsToolInterruptError")
	}

	// 3. Full Genkit Generate interrupt -> Resume (rejected + approved) flow.
	t.Setenv("GEMINI_API_KEY", "super-secret-api-key-should-not-leak")
	testModel := genkit.DefineModelAction[any](g, "test/hitl-model", &ai.ModelOptions{
		Supports: &ai.ModelSupports{
			Multiturn: true,
			Tools:     true,
		},
	}, func(_ context.Context, req *ai.ModelRequest, _ any, _ ai.ModelStreamCallback) (*ai.ModelResponse, error) {
		for _, m := range req.Messages {
			for _, p := range m.Content {
				if p != nil && p.IsToolResponse() && p.ToolResponse != nil {
					b, _ := json.Marshal(p.ToolResponse.Output)
					return &ai.ModelResponse{
						FinishReason: ai.FinishReasonStop,
						Message:      ai.NewModelTextMessage(string(b)),
					}, nil
				}
			}
		}
		return &ai.ModelResponse{
			FinishReason: ai.FinishReasonStop,
			Message: &ai.Message{
				Role: ai.RoleModel,
				Content: []*ai.Part{
					ai.NewToolRequestPart(&ai.ToolRequest{
						Ref:  "call-1",
						Name: CommandToolName,
						Input: map[string]any{
							"command": "printf '%s' \"${GEMINI_API_KEY:-aida-hitl-verified}\"",
							"reason":  "Verify HITL execution and env sanitization",
							"risk":    "LOW",
						},
					}),
				},
			},
		}, nil
	})

	resp1, err := genkit.Generate(ctx, g,
		ai.WithModel(testModel),
		ai.WithPrompt("Run diagnostic echo"),
		ai.WithTools(cmdTool),
	)
	if err != nil {
		t.Fatalf("genkit.Generate (initial interrupt) failed: %v", err)
	}
	if resp1.FinishReason != ai.FinishReasonInterrupted {
		t.Fatalf("resp1.FinishReason = %q, want %q", resp1.FinishReason, ai.FinishReasonInterrupted)
	}
	interrupts := resp1.Interrupts()
	if len(interrupts) != 1 {
		t.Fatalf("len(resp1.Interrupts()) = %d, want 1", len(interrupts))
	}
	extractedIntr, ok := tool.InterruptAs[CommandInterrupt](interrupts[0])
	if !ok {
		t.Fatalf("tool.InterruptAs[CommandInterrupt] failed on %#v", interrupts[0])
	}
	if extractedIntr.Risk != "LOW" {
		t.Fatalf("extractedIntr.Risk = %q, want %q", extractedIntr.Risk, "LOW")
	}

	// 3a. Resume with rejection (`Approved: false`).
	rejectRestart, err := cmdTool.Resume(interrupts[0], CommandConfirmation{
		Approved: false,
		Feedback: "Denied by test operator",
	})
	if err != nil {
		t.Fatalf("cmdTool.Resume(rejected) failed: %v", err)
	}
	respRejected, err := genkit.Generate(ctx, g,
		ai.WithModel(testModel),
		ai.WithMessages(resp1.History()...),
		ai.WithTools(cmdTool),
		ai.WithToolRestarts(rejectRestart),
	)
	if err != nil {
		t.Fatalf("genkit.Generate (resume rejected) failed: %v", err)
	}
	var rejectedOut CommandOutput
	if err := json.Unmarshal([]byte(respRejected.Text()), &rejectedOut); err != nil {
		t.Fatalf("failed to unmarshal rejected output %q: %v", respRejected.Text(), err)
	}
	if rejectedOut.Status != "rejected" || rejectedOut.ExitCode != -1 {
		t.Fatalf("unexpected rejected output: %+v", rejectedOut)
	}
	if !strings.Contains(rejectedOut.Stderr, "Denied by test operator") {
		t.Fatalf("expected rejection feedback in Stderr, got %q", rejectedOut.Stderr)
	}

	// 3b. Resume with approval (`Approved: true`), verifying GEMINI_API_KEY is stripped from child env.
	approveRestart, err := cmdTool.Resume(interrupts[0], CommandConfirmation{
		Approved: true,
	})
	if err != nil {
		t.Fatalf("cmdTool.Resume(approved) failed: %v", err)
	}
	respApproved, err := genkit.Generate(ctx, g,
		ai.WithModel(testModel),
		ai.WithMessages(resp1.History()...),
		ai.WithTools(cmdTool),
		ai.WithToolRestarts(approveRestart),
	)
	if err != nil {
		t.Fatalf("genkit.Generate (resume approved) failed: %v", err)
	}
	var approvedOut CommandOutput
	if err := json.Unmarshal([]byte(respApproved.Text()), &approvedOut); err != nil {
		t.Fatalf("failed to unmarshal approved output %q: %v", respApproved.Text(), err)
	}
	if approvedOut.Status != "executed" || approvedOut.ExitCode != 0 {
		t.Fatalf("unexpected approved output: %+v", approvedOut)
	}
	if approvedOut.Stdout != "aida-hitl-verified" {
		t.Fatalf("approvedOut.Stdout = %q, want %q (secret env must not leak)", approvedOut.Stdout, "aida-hitl-verified")
	}
}

func TestNewAgent_InitializationAndPromptRender(t *testing.T) {
	chdirRepoRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	aida, err := New(ctx, Config{
		ProjectID: "test-gcp-project",
		Location:  "global",
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if aida.OS() != runtime.GOOS {
		t.Fatalf("aida.OS() = %q, want %q", aida.OS(), runtime.GOOS)
	}
	if aida.OSSkill() != runtime.GOOS {
		t.Fatalf("aida.OSSkill() = %q, want %q", aida.OSSkill(), runtime.GOOS)
	}
	if aida.Model() != ModelName {
		t.Fatalf("aida.Model() = %q, want %q", aida.Model(), ModelName)
	}
	if aida.ThinkingLevel() != ThinkingLevel {
		t.Fatalf("aida.ThinkingLevel() = %q, want %q", aida.ThinkingLevel(), ThinkingLevel)
	}
	if aida.Genkit() == nil {
		t.Fatal("aida.Genkit() is nil")
	}
	if aida.Agent() == nil {
		t.Fatal("aida.Agent() is nil")
	}
	if aida.OsqueryRunner() == nil {
		t.Fatal("aida.OsqueryRunner() is nil")
	}

	ver, err := aida.OsqueryVersion(ctx)
	if err != nil {
		t.Fatalf("aida.OsqueryVersion() failed: %v", err)
	}
	if ver == "" {
		t.Fatal("aida.OsqueryVersion() returned empty string")
	}

	model := genkit.LookupModel(aida.Genkit(), ModelName)
	if model == nil {
		t.Fatalf("genkit.LookupModel(g, %q) returned nil", ModelName)
	}

	if handle := genkitx.LookupAgent(aida.Genkit(), AgentName); handle == nil {
		t.Fatalf("genkitx.LookupAgent(g, %q) returned nil", AgentName)
	}

	for _, toolName := range []string{"run_osquery", CommandToolName} {
		if registeredTool := genkit.LookupTool(aida.Genkit(), toolName); registeredTool == nil {
			t.Fatalf("genkit.LookupTool(g, %q) returned nil", toolName)
		}
	}

	// Verify rendered prompt from prompts/aida.prompt and RenderSystemPrompt helper.
	sysText, err := aida.RenderSystemPrompt(ctx)
	if err != nil {
		t.Fatalf("aida.RenderSystemPrompt() failed: %v", err)
	}
	for _, expectedToken := range []string{
		aida.OS(),
		"use_skill",
		"run_osquery",
		"runCommand",
		"Scene3D",
		"CyberChart",
		"HudGauge",
		"DataMatrix",
		"`path`, `directory`, `pid`, `uid`, `url`, `hostname`, `data_type`, `query`, `channel`, `key`",
	} {
		if !strings.Contains(sysText, expectedToken) {
			t.Fatalf("expected rendered system prompt to contain %q", expectedToken)
		}
	}

	prompt := genkit.LookupPrompt(aida.Genkit(), PromptName)
	if prompt == nil {
		t.Fatalf("genkit.LookupPrompt(g, %q) returned nil", PromptName)
	}
	actionOpts, err := prompt.Render(ctx, PromptInput{OS: aida.OS()})
	if err != nil {
		t.Fatalf("prompt.Render() failed: %v", err)
	}

	cfgBytes, err := json.Marshal(actionOpts.Config)
	if err != nil {
		t.Fatalf("json.Marshal(actionOpts.Config) failed: %v", err)
	}
	var genCfg genai.GenerateContentConfig
	if err := json.Unmarshal(cfgBytes, &genCfg); err != nil {
		t.Fatalf("json.Unmarshal into genai.GenerateContentConfig failed: %v", err)
	}
	if genCfg.ThinkingConfig == nil || genCfg.ThinkingConfig.ThinkingLevel != genai.ThinkingLevelLow {
		t.Fatalf("expected ThinkingLevelLow in GenerateContentConfig, got %#v", genCfg.ThinkingConfig)
	}
	if len(genCfg.Tools) == 0 || genCfg.Tools[0].GoogleSearch == nil {
		t.Fatalf("expected GoogleSearch tool in GenerateContentConfig.Tools, got %#v", genCfg.Tools)
	}

	for _, wantTool := range []string{"run_osquery", CommandToolName} {
		found := false
		for _, toolName := range actionOpts.Tools {
			if strings.HasSuffix(toolName, wantTool) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected %q in rendered prompt tools, got %v", wantTool, actionOpts.Tools)
		}
	}

	wantMiddlewares := []string{
		"genkit-middleware/skills",
		"genkit-middleware/retry",
		"a2ui",
	}
	if len(actionOpts.Use) != len(wantMiddlewares) {
		t.Fatalf("len(actionOpts.Use) = %d, want %d (%#v)", len(actionOpts.Use), len(wantMiddlewares), actionOpts.Use)
	}
	for i, wantMW := range wantMiddlewares {
		if actionOpts.Use[i] == nil || actionOpts.Use[i].Name != wantMW {
			t.Fatalf("actionOpts.Use[%d] = %#v, want Name=%q", i, actionOpts.Use[i], wantMW)
		}
	}

	// Verify A2UI Surfaces strict validation against the registered "aida" catalog.
	a2uiModel := genkit.DefineModelAction[any](aida.Genkit(), "test/a2ui-strict-model", &ai.ModelOptions{
		Supports: &ai.ModelSupports{Multiturn: true},
	}, func(_ context.Context, req *ai.ModelRequest, _ any, _ ai.ModelStreamCallback) (*ai.ModelResponse, error) {
		userText := req.Messages[len(req.Messages)-1].Text()
		if strings.Contains(userText, "invalid") {
			return &ai.ModelResponse{
				FinishReason: ai.FinishReasonStop,
				Message:      ai.NewModelTextMessage("Invalid component test:\n```a2ui\n[\n  {\"createSurface\": {\"surfaceId\": \"SURFACE_ID\", \"catalogId\": \"aida\"}},\n  {\"updateComponents\": {\"surfaceId\": \"SURFACE_ID\", \"components\": [{\"id\": \"root\", \"component\": \"Card\", \"children\": []}]}}\n]\n```"),
			}, nil
		}
		return &ai.ModelResponse{
			FinishReason: ai.FinishReasonStop,
			Message:      ai.NewModelTextMessage("Telemetry nominal.\n```a2ui\n[\n  {\"createSurface\": {\"surfaceId\": \"SURFACE_ID\", \"catalogId\": \"aida\"}},\n  {\"updateComponents\": {\"surfaceId\": \"SURFACE_ID\", \"components\": [\n    {\"id\": \"root\", \"component\": \"Panel\", \"title\": \"TELEMETRY\", \"children\": [\"holo\", \"gauge\"]},\n    {\"id\": \"holo\", \"component\": \"Scene3D\", \"mode\": \"topology\", \"nodes\": [{\"id\": \"n1\", \"label\": \"kernel\", \"value\": 12}]},\n    {\"id\": \"gauge\", \"component\": \"HudGauge\", \"items\": [{\"label\": \"CPU\", \"value\": 12, \"unit\": \"%\"}]}\n  ]}}\n]\n```"),
		}, nil
	})

	validResp, err := genkit.Generate(ctx, aida.Genkit(),
		ai.WithModel(a2uiModel),
		ai.WithPrompt("render valid aida surface"),
		ai.WithUse(
			&middleware.Retry{MaxRetries: 3},
			&a2uix.Surfaces{
				CatalogID:    CatalogID,
				Instructions: a2uix.InstructionsNone,
				Validate:     a2uix.ValidateStrict,
			},
		),
	)
	if err != nil {
		t.Fatalf("expected valid AIDA surface to pass ValidateStrict, got error: %v", err)
	}
	envelopes := a2uix.EnvelopesFromParts(validResp.Message.Content)
	if len(envelopes) != 2 {
		t.Fatalf("len(envelopes) = %d, want 2 (%#v)", len(envelopes), envelopes)
	}

	if _, err := genkit.Generate(ctx, aida.Genkit(),
		ai.WithModel(a2uiModel),
		ai.WithPrompt("render invalid basic catalog component"),
		ai.WithUse(
			&a2uix.Surfaces{
				CatalogID:    CatalogID,
				Instructions: a2uix.InstructionsNone,
				Validate:     a2uix.ValidateStrict,
			},
		),
	); err == nil {
		t.Fatal("expected unknown component 'Card' to fail ValidateStrict against 'aida' catalog, got nil")
	}
}

func TestNewAgent_GoogleAIProviderInitialization(t *testing.T) {
	chdirRepoRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")

	// Must fail fast when googleai/ model is selected without GEMINI_API_KEY or GOOGLE_API_KEY.
	if _, err := New(ctx, Config{
		Model: GoogleAIModelName,
	}); err == nil {
		t.Fatal("expected New() with googleai/ model and no API key to fail fast, got nil")
	}

	// Must initialize with GoogleAI plugin without requiring a GCP ProjectID when GEMINI_API_KEY is set.
	t.Setenv("GEMINI_API_KEY", "test-gemini-api-key")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("GCLOUD_PROJECT", "")

	aida, err := New(ctx, Config{
		Model: GoogleAIModelName,
	})
	if err != nil {
		t.Fatalf("New(googleai) failed: %v", err)
	}
	if aida.Model() != GoogleAIModelName {
		t.Fatalf("aida.Model() = %q, want %q", aida.Model(), GoogleAIModelName)
	}
	if model := genkit.LookupModel(aida.Genkit(), GoogleAIModelName); model == nil {
		t.Fatalf("genkit.LookupModel(g, %q) returned nil", GoogleAIModelName)
	}
}

func TestNewAgent_FailFastOnMissingPrerequisites(t *testing.T) {
	chdirRepoRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var nilCtx context.Context
	if _, err := New(nilCtx, Config{
		ProjectID: "test-gcp-project",
		Location:  "global",
	}); err == nil {
		t.Fatal("expected New(nil, ...) to fail fast on nil context, got nil")
	}

	if _, err := New(ctx, Config{
		ProjectID: "test-gcp-project",
		Location:  "global",
		OS:        "unsupported-os-xyz",
	}); err == nil {
		t.Fatal("expected New() to fail fast on unsupported OS, got nil")
	}

	if _, err := New(ctx, Config{
		ProjectID:     "test-gcp-project",
		Location:      "global",
		OsqueryBinary: "osqueryi-missing-binary-xyz",
	}); err == nil {
		t.Fatal("expected New() to fail fast when osqueryi binary is missing, got nil")
	}

	if _, err := New(ctx, Config{
		ProjectID: "test-gcp-project",
		Location:  "global",
		PromptDir: t.TempDir(),
	}); err == nil {
		t.Fatal("expected New() to fail fast when aida.prompt is missing, got nil")
	}

	if _, err := New(ctx, Config{
		ProjectID: "test-gcp-project",
		Location:  "global",
		SkillsDir: t.TempDir(),
	}); err == nil {
		t.Fatal("expected New() to fail fast when skills/<os>/SKILL.md is missing, got nil")
	}
}
