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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/firebase/genkit/go/ai"
	aix "github.com/firebase/genkit/go/ai/exp"
	"github.com/firebase/genkit/go/ai/exp/localstore"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/genkit"
	genkitx "github.com/firebase/genkit/go/genkit/exp"
	a2uix "github.com/firebase/genkit/go/plugins/a2ui/exp"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/firebase/genkit/go/plugins/middleware"

	"github.com/danicat/go-aida/internal/command"
	"github.com/danicat/go-aida/internal/osquery"
)

const (
	// AgentName is the registered Genkit experimental agent name.
	AgentName = "aida"

	// PromptName is the Dotprompt file name (prompts/aida.prompt) registered in Genkit.
	PromptName = "aida"

	// ModelName is the default Vertex AI Gemini model used by AIDA.
	ModelName = "vertexai/gemini-3.8-flash"

	// GoogleAIModelName is the default Google AI (Gemini Developer API) model used by AIDA.
	GoogleAIModelName = "googleai/gemini-3.8-flash"

	// ThinkingLevel is the thinking level configured for AIDA.
	ThinkingLevel = "LOW"

	// DefaultPromptDir is the default directory containing Dotprompt files.
	DefaultPromptDir = "prompts"

	// DefaultSkillsDir is the default directory containing OS skill subdirectories.
	DefaultSkillsDir = "skills"

	// DefaultLocation is the default Vertex AI location for Gemini 3.8 Flash.
	DefaultLocation = "global"

	gcloudProjectTimeout = 5 * time.Second
)

// PromptInput defines the input schema passed to prompts/aida.prompt.
type PromptInput struct {
	OS string `json:"os"`
}

// Config holds initialization settings for the AIDA diagnostic agent.
type Config struct {
	ProjectID     string
	Location      string
	Model         string
	PromptDir     string
	SkillsDir     string
	OS            string
	OsqueryBinary string
}

// TextCallback receives streamed text chunks from the model during a turn.
type TextCallback func(chunk string)

// ToolCallback receives real-time notifications when a tool request starts or finishes.
type ToolCallback func(name, input, output string, running bool, err error)

// AIDA encapsulates the Genkit runtime, AIDA diagnostic agent, standalone A2UI
// catalog, osquery runner, interruptible remediation tool, and session store.
type AIDA struct {
	g             *genkit.Genkit
	agent         *aix.Agent[any]
	osqueryRunner *osquery.Runner
	osName        string
	modelName     string

	mu        sync.Mutex
	sessionID string
}

// DetectOS inspects runtime.GOOS and validates that it is a supported AIDA operating system.
func DetectOS() (string, error) {
	return ValidateOS(runtime.GOOS)
}

// ValidateOS validates that the given OS identifier is one of "darwin", "linux", or "windows".
func ValidateOS(goos string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(goos))
	switch normalized {
	case "darwin", "linux", "windows":
		return normalized, nil
	default:
		return "", fmt.Errorf(
			"unsupported operating system %q (supported values: darwin, linux, windows)",
			goos,
		)
	}
}

// ResolveProjectID resolves the Google Cloud project ID for Vertex AI from explicit config,
// GOOGLE_CLOUD_PROJECT or GCLOUD_PROJECT environment variables, or active gcloud configuration.
// It fails immediately with a rich diagnostic error if no project ID is configured.
func ResolveProjectID(configured string) (string, error) {
	return resolveProjectIDWithContext(context.Background(), configured)
}

func resolveProjectIDWithContext(ctx context.Context, configured string) (string, error) {
	if trimmed := strings.TrimSpace(configured); trimmed != "" {
		return trimmed, nil
	}

	if envProject := strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_PROJECT")); envProject != "" {
		return envProject, nil
	}
	if envProject := strings.TrimSpace(os.Getenv("GCLOUD_PROJECT")); envProject != "" {
		return envProject, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	cmdCtx, cancel := context.WithTimeout(ctx, gcloudProjectTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, "gcloud", "config", "get-value", "project", "--quiet")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf(
			"vertex AI project ID is not configured: GOOGLE_CLOUD_PROJECT is unset and `gcloud config get-value project` failed (stderr=%q): %w",
			strings.TrimSpace(stderr.String()),
			err,
		)
	}

	projectID := strings.TrimSpace(stdout.String())
	if projectID == "" || projectID == "(unset)" {
		return "", errors.New(
			"vertex AI project ID is not configured: set GOOGLE_CLOUD_PROJECT or run `gcloud config set project <PROJECT_ID>`",
		)
	}
	return projectID, nil
}

// ResolveLocation resolves the Google Cloud location for Vertex AI from explicit config,
// GOOGLE_CLOUD_LOCATION, GOOGLE_CLOUD_REGION, or DefaultLocation ("global").
func ResolveLocation(configured string) string {
	if trimmed := strings.TrimSpace(configured); trimmed != "" {
		return trimmed
	}
	if loc := strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_LOCATION")); loc != "" {
		return loc
	}
	if reg := strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_REGION")); reg != "" {
		return reg
	}
	return DefaultLocation
}

// ResolveModel resolves and validates the Genkit model identifier from Config.Model,
// the AIDA_MODEL environment variable, or provider-aware defaults:
//   - "googleai/gemini-3.8-flash" when GEMINI_API_KEY or GOOGLE_API_KEY is set and no GCP project is configured
//   - "vertexai/gemini-3.8-flash" otherwise
func ResolveModel(cfg Config) (string, error) {
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = strings.TrimSpace(os.Getenv("AIDA_MODEL"))
	}
	if model == "" {
		hasGeminiKey := strings.TrimSpace(os.Getenv("GEMINI_API_KEY")) != "" || strings.TrimSpace(os.Getenv("GOOGLE_API_KEY")) != ""
		hasVertexProject := strings.TrimSpace(cfg.ProjectID) != "" ||
			strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_PROJECT")) != "" ||
			strings.TrimSpace(os.Getenv("GCLOUD_PROJECT")) != ""
		if hasGeminiKey && !hasVertexProject {
			model = GoogleAIModelName
		} else {
			model = ModelName
		}
	}

	switch {
	case strings.HasPrefix(model, "vertexai/"):
		if strings.TrimSpace(strings.TrimPrefix(model, "vertexai/")) == "" {
			return "", fmt.Errorf("invalid model %q: vertexai/ prefix requires a non-empty model name", model)
		}
		return model, nil
	case strings.HasPrefix(model, "googleai/"):
		if strings.TrimSpace(strings.TrimPrefix(model, "googleai/")) == "" {
			return "", fmt.Errorf("invalid model %q: googleai/ prefix requires a non-empty model name", model)
		}
		return model, nil
	default:
		return "", fmt.Errorf(
			"unsupported model %q: must start with \"vertexai/\" or \"googleai/\"",
			model,
		)
	}
}

// New initializes the Genkit runtime, verifies osqueryi and the OS skill files,
// registers the standalone AIDA A2UI v0.9 catalog, run_osquery tool, interruptible
// runCommand tool, and the AIDA agent backed by InMemorySessionStore.
// It fails immediately on any missing prerequisite.
func New(ctx context.Context, cfg Config) (*AIDA, error) {
	if ctx == nil {
		return nil, errors.New("cannot initialize aida agent: context is nil")
	}

	osName := strings.TrimSpace(cfg.OS)
	var err error
	if osName == "" {
		osName, err = DetectOS()
	} else {
		osName, err = ValidateOS(osName)
	}
	if err != nil {
		return nil, fmt.Errorf("aida OS detection failed: %w", err)
	}

	binary := strings.TrimSpace(cfg.OsqueryBinary)
	if binary == "" {
		binary = osquery.DefaultBinary
	}
	runner, err := osquery.NewRunnerWithBinary(binary)
	if err != nil {
		return nil, fmt.Errorf("aida osquery verification failed: %w", err)
	}

	promptDir := strings.TrimSpace(cfg.PromptDir)
	if promptDir == "" {
		promptDir = DefaultPromptDir
	}
	promptFile := filepath.Join(promptDir, PromptName+".prompt")
	if err := verifyFileReadable(promptFile, "aida Dotprompt file"); err != nil {
		return nil, err
	}

	skillsDir := strings.TrimSpace(cfg.SkillsDir)
	if skillsDir == "" {
		skillsDir = DefaultSkillsDir
	}
	for _, requiredSkill := range []string{"darwin", "linux", "windows"} {
		skillFile := filepath.Join(skillsDir, requiredSkill, "SKILL.md")
		if err := verifyFileReadable(skillFile, fmt.Sprintf("aida %s OS skill file", requiredSkill)); err != nil {
			return nil, err
		}
	}

	resolvedModel, err := ResolveModel(cfg)
	if err != nil {
		return nil, fmt.Errorf("aida model resolution failed: %w", err)
	}

	var modelPlugin api.Plugin
	if strings.HasPrefix(resolvedModel, "googleai/") {
		if strings.TrimSpace(os.Getenv("GEMINI_API_KEY")) == "" && strings.TrimSpace(os.Getenv("GOOGLE_API_KEY")) == "" {
			return nil, fmt.Errorf(
				"google AI model %q requires GEMINI_API_KEY or GOOGLE_API_KEY environment variable to be set",
				resolvedModel,
			)
		}
		modelPlugin = &googlegenai.GoogleAI{}
	} else {
		projectID, projErr := resolveProjectIDWithContext(ctx, cfg.ProjectID)
		if projErr != nil {
			return nil, projErr
		}
		location := ResolveLocation(cfg.Location)
		modelPlugin = &googlegenai.VertexAI{
			ProjectID: projectID,
			Location:  location,
		}
	}

	var (
		initGenkit *genkit.Genkit
		initAgent  *aix.Agent[any]
	)

	if err := catchPanic("genkit and aida agent initialization", func() error {
		initGenkit = genkit.Init(
			ctx,
			genkit.WithExperimental(),
			genkit.WithDefaultModel(resolvedModel),
			genkit.WithPromptDir(promptDir),
			genkit.WithPlugins(
				modelPlugin,
				&middleware.Middleware{},
				&a2uix.A2UI{},
			),
		)

		// 1. Register the custom "aida" A2UI component catalog
		if regErr := a2uix.LoadCatalog(initGenkit, AidaCatalog()); regErr != nil {
			return fmt.Errorf("failed to register aida A2UI catalog %q: %w", CatalogID, regErr)
		}

		// 2. Register read-only diagnostics (osquery) and HITL shell commands (command)
		if _, regErr := osquery.RegisterTool(initGenkit, runner); regErr != nil {
			return regErr
		}

		if commandTool := command.RegisterTool(initGenkit); commandTool == nil {
			return errors.New("failed to register interruptible runCommand tool")
		}

		for _, mw := range []ai.Middleware{
			&middleware.Skills{SkillPaths: []string{skillsDir}},
			&a2uix.Surfaces{
				CatalogID: CatalogID,
				Validate:  a2uix.ValidateStrict,
			},
		} {
			if _, mwErr := mw.New(ctx); mwErr != nil {
				return fmt.Errorf("failed to initialize agent middleware %q: %w", mw.Name(), mwErr)
			}
		}

		if prompt := genkit.LookupPrompt(initGenkit, PromptName); prompt == nil {
			return fmt.Errorf(
				"prompt %q was not found in Genkit registry after loading prompt directory %q",
				PromptName,
				promptDir,
			)
		}

		sessionStore := localstore.NewInMemorySessionStore[any]()

		// 3. Define the single AIDA agent from prompts/aida.prompt
		initAgent = genkitx.DefinePromptAgent(
			initGenkit,
			AgentName,
			aix.WithDescription[any]("AIDA — AI Diagnostic Agent"),
			aix.WithSessionStore[any](sessionStore),
			aix.WithNamedPrompt[any](PromptName, PromptInput{OS: osName}),
		)
		return nil
	}); err != nil {
		return nil, err
	}

	return &AIDA{
		g:             initGenkit,
		agent:         initAgent,
		osqueryRunner: runner,
		osName:        osName,
		modelName:     resolvedModel,
	}, nil
}

// Genkit returns the underlying Genkit instance.
func (a *AIDA) Genkit() *genkit.Genkit {
	if a == nil {
		return nil
	}
	return a.g
}

// Agent returns the underlying experimental Genkit agent.
func (a *AIDA) Agent() *aix.Agent[any] {
	if a == nil {
		return nil
	}
	return a.agent
}

// OsqueryRunner returns the osqueryi runner bound to this agent.
func (a *AIDA) OsqueryRunner() *osquery.Runner {
	if a == nil {
		return nil
	}
	return a.osqueryRunner
}

// OS returns the detected or configured host operating system ("darwin", "linux", or "windows").
func (a *AIDA) OS() string {
	if a == nil {
		return ""
	}
	return a.osName
}

// OSSkill returns the host OS skill identifier ("darwin", "linux", or "windows").
func (a *AIDA) OSSkill() string {
	if a == nil {
		return ""
	}
	return a.osName
}

// Model returns the configured Genkit model name.
func (a *AIDA) Model() string {
	if a == nil || a.modelName == "" {
		return ModelName
	}
	return a.modelName
}

// ThinkingLevel returns the configured thinking level ("LOW").
func (a *AIDA) ThinkingLevel() string {
	return ThinkingLevel
}

// OsqueryVersion queries the local osqueryi binary for its version string.
func (a *AIDA) OsqueryVersion(ctx context.Context) (string, error) {
	if a == nil || a.osqueryRunner == nil {
		return "", errors.New("aida agent osquery runner is not initialized")
	}
	return a.osqueryRunner.Version(ctx)
}

// RenderSystemPrompt renders the AIDA Dotprompt for the configured host OS and returns the system prompt text.
func (a *AIDA) RenderSystemPrompt(ctx context.Context) (string, error) {
	if a == nil || a.g == nil {
		return "", errors.New("cannot render system prompt: aida agent is not initialized")
	}
	if ctx == nil {
		return "", errors.New("cannot render system prompt: context is nil")
	}
	prompt := genkit.LookupPrompt(a.g, PromptName)
	if prompt == nil {
		return "", fmt.Errorf("cannot render system prompt: prompt %q not found", PromptName)
	}
	opts, err := prompt.Render(ctx, PromptInput{OS: a.osName})
	if err != nil {
		return "", fmt.Errorf("failed to render prompt %q: %w", PromptName, err)
	}
	if opts == nil || len(opts.Messages) == 0 {
		return "", fmt.Errorf("rendered prompt %q returned zero messages", PromptName)
	}
	return opts.Messages[0].Text(), nil
}

// StreamTurn executes a single conversational turn on the AIDA agent while streaming
// model text chunks and tool request/response events to the provided callbacks.
// Session state is persisted via InMemorySessionStore and resumed across turns using WithSessionID.
func (a *AIDA) StreamTurn(
	ctx context.Context,
	prompt string,
	onText TextCallback,
	onTool ToolCallback,
) (string, error) {
	if a == nil || a.agent == nil {
		return "", errors.New("cannot run turn: aida agent is not initialized")
	}
	if ctx == nil {
		return "", errors.New("cannot run turn: context is nil")
	}
	trimmedPrompt := strings.TrimSpace(prompt)
	if trimmedPrompt == "" {
		return "", errors.New("cannot run turn: prompt must not be empty")
	}

	a.mu.Lock()
	sessionID := a.sessionID
	a.mu.Unlock()

	var opts []aix.InvocationOption[any]
	if sessionID != "" {
		opts = append(opts, aix.WithSessionID[any](sessionID))
	}

	conn, err := a.agent.Connect(ctx, opts...)
	if err != nil {
		return "", fmt.Errorf("failed to connect to aida agent: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SendText(trimmedPrompt); err != nil {
		return "", fmt.Errorf("failed to send prompt to aida agent: %w", err)
	}

	var streamedText strings.Builder
	toolInputs := make(map[string]string)

	for chunk, recvErr := range conn.Receive() {
		if recvErr != nil {
			return "", fmt.Errorf("error receiving stream chunk from aida agent: %w", recvErr)
		}
		if chunk == nil {
			continue
		}

		if chunk.ModelChunk != nil {
			for _, part := range chunk.ModelChunk.Content {
				if part == nil {
					continue
				}
				if part.IsToolRequest() && part.ToolRequest != nil {
					inputStr := formatToolPayload(part.ToolRequest.Input)
					if part.ToolRequest.Ref != "" {
						toolInputs[part.ToolRequest.Ref] = inputStr
					}
					if onTool != nil {
						onTool(part.ToolRequest.Name, inputStr, "", true, nil)
					}
					continue
				}
				if part.IsToolResponse() && part.ToolResponse != nil {
					outputStr := formatToolPayload(part.ToolResponse.Output)
					inputStr := toolInputs[part.ToolResponse.Ref]
					if onTool != nil {
						onTool(part.ToolResponse.Name, inputStr, outputStr, false, nil)
					}
					continue
				}
				if part.IsText() && part.Text != "" {
					streamedText.WriteString(part.Text)
					if onText != nil {
						onText(part.Text)
					}
				}
			}
		}

		if chunk.TurnEnd != nil {
			break
		}
	}

	out, outErr := conn.Output()
	if outErr != nil {
		return "", fmt.Errorf("aida agent turn failed: %w", outErr)
	}
	if out == nil {
		return "", errors.New("aida agent turn returned nil output")
	}
	if out.Error != nil {
		return "", fmt.Errorf(
			"aida agent turn failed (finishReason=%s): %s",
			out.FinishReason,
			out.Error.Message,
		)
	}
	if out.SessionID != "" {
		a.mu.Lock()
		a.sessionID = out.SessionID
		a.mu.Unlock()
	} else if out.State != nil && out.State.SessionID != "" {
		a.mu.Lock()
		a.sessionID = out.State.SessionID
		a.mu.Unlock()
	}

	if string(out.FinishReason) == string(ai.FinishReasonInterrupted) {
		return "", errors.New("aida agent turn interrupted: runCommand requires interactive HITL approval in the Web Cockpit (go-aida)")
	}

	finalText := streamedText.String()
	if finalText == "" && out.Message != nil {
		finalText = out.Message.Text()
		if finalText != "" && onText != nil {
			onText(finalText)
		}
	}
	return finalText, nil
}

func formatToolPayload(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func verifyFileReadable(path, label string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %q is missing or inaccessible: %w", label, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s %q is a directory, expected a file", label, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s %q cannot be opened for reading: %w", label, path, err)
	}
	if closeErr := f.Close(); closeErr != nil {
		return fmt.Errorf("closing %s %q failed: %w", label, path, closeErr)
	}
	return nil
}

func catchPanic(operation string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s panicked: %v", operation, r)
		}
	}()
	return fn()
}
