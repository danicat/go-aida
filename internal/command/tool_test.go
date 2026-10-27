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

package command

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/ai/exp/tool"
	"github.com/firebase/genkit/go/genkit"
)

func TestRegisterTool_InterruptApproveRejectAndExecute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	g := genkit.Init(ctx, genkit.WithExperimental())
	cmdTool := RegisterTool(g)
	if cmdTool == nil {
		t.Fatal("RegisterTool() returned nil")
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
		"reason":  "Verify HITL execution",
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
						Name: ToolName,
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
	if rejectedOut.Status != "rejected" || rejectedOut.ExitCode != -1 || rejectedOut.Executed {
		t.Fatalf("unexpected rejected output: %+v", rejectedOut)
	}
	if !strings.Contains(rejectedOut.Stderr, "Operator denied execution: Denied by test operator") {
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
	if approvedOut.Status != "executed" || approvedOut.ExitCode != 0 || !approvedOut.Executed {
		t.Fatalf("unexpected approved output: %+v", approvedOut)
	}
	if approvedOut.Stdout != "aida-hitl-verified" {
		t.Fatalf("approvedOut.Stdout = %q, want %q (secret env must not leak)", approvedOut.Stdout, "aida-hitl-verified")
	}
}
