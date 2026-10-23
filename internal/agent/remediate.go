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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	aix "github.com/firebase/genkit/go/ai/exp"
	"github.com/firebase/genkit/go/ai/exp/tool"
	"github.com/firebase/genkit/go/core/status"
	"github.com/firebase/genkit/go/genkit"
	genkitx "github.com/firebase/genkit/go/genkit/exp"
)

const (
	// CommandToolName is the canonical name of the human-in-the-loop remediation tool.
	CommandToolName = "runCommand"

	// commandExecutionTimeout bounds any approved remediation shell command.
	commandExecutionTimeout = 30 * time.Second

	// commandWaitDelay bounds how long os/exec waits for child I/O pipes after exit/kill.
	commandWaitDelay = 3 * time.Second

	// maxCommandOutputBytes caps stdout and stderr buffers at 1 MiB.
	maxCommandOutputBytes = 1 << 20
)

var allowedCommandEnvVars = []string{
	"PATH",
	"HOME",
	"USER",
	"LOGNAME",
	"LANG",
	"LC_ALL",
	"TERM",
	"TMPDIR",
	"TEMP",
	"TMP",
	"SystemRoot",
	"ComSpec",
	"windir",
}

// CommandInput defines the input schema for the interruptible runCommand tool.
type CommandInput struct {
	Command string `json:"command" jsonschema:"description=The exact shell command to execute for host remediation"`
	Reason  string `json:"reason" jsonschema:"description=Why this remediation command is needed"`
	Risk    string `json:"risk" jsonschema:"description=Risk level: LOW, MEDIUM, or HIGH"`
}

// CommandInterrupt is the structured interrupt metadata emitted when runCommand pauses for HITL approval.
type CommandInterrupt struct {
	Command string `json:"command" jsonschema:"description=The exact shell command awaiting human operator approval"`
	Reason  string `json:"reason" jsonschema:"description=Why this remediation command is needed"`
	Risk    string `json:"risk" jsonschema:"description=Normalized risk level: LOW, MEDIUM, or HIGH"`
}

// CommandConfirmation is the typed resume payload sent back by the human operator to approve or reject runCommand.
type CommandConfirmation struct {
	Approved bool   `json:"approved" jsonschema:"description=True if the human operator approved executing the command"`
	Feedback string `json:"feedback,omitempty" jsonschema:"description=Optional operator note or rejection reason"`
}

// CommandOutput is the structured result returned by runCommand after human approval or rejection.
type CommandOutput struct {
	Command  string `json:"command" jsonschema:"description=The shell command that was evaluated or executed"`
	Status   string `json:"status" jsonschema:"description=Outcome status: executed or rejected"`
	ExitCode int    `json:"exitCode" jsonschema:"description=Process exit code (0 on success, -1 when rejected)"`
	Stdout   string `json:"stdout" jsonschema:"description=Captured standard output"`
	Stderr   string `json:"stderr" jsonschema:"description=Captured standard error or operator feedback"`
}

// RegisterCommandTool defines and registers the interruptible `runCommand` tool on the Genkit instance.
// On initial invocation (`res == nil`), it always pauses execution via `tool.Interrupt(CommandInterrupt{...})`
// so the human operator can inspect and approve or reject the command in the AIDA cockpit.
func RegisterCommandTool(g *genkit.Genkit) *aix.InterruptibleTool[CommandInput, CommandOutput, CommandConfirmation] {
	return genkitx.DefineInterruptibleTool[CommandInput, CommandOutput, CommandConfirmation](
		g,
		CommandToolName,
		"Execute a host remediation or diagnostic shell command after mandatory Human-in-the-Loop (HITL) operator approval.",
		func(ctx context.Context, in CommandInput, res *CommandConfirmation) (CommandOutput, error) {
			trimmedCmd := strings.TrimSpace(in.Command)
			if trimmedCmd == "" {
				return CommandOutput{}, status.Errorf(
					status.ErrInvalidArgument,
					"%s: command must not be empty",
					CommandToolName,
				)
			}

			trimmedReason := strings.TrimSpace(in.Reason)
			if trimmedReason == "" {
				return CommandOutput{}, status.Errorf(
					status.ErrInvalidArgument,
					"%s: reason must not be empty",
					CommandToolName,
				)
			}

			risk, err := normalizeRisk(in.Risk)
			if err != nil {
				return CommandOutput{}, err
			}

			if res == nil {
				return CommandOutput{}, tool.Interrupt(CommandInterrupt{
					Command: trimmedCmd,
					Reason:  trimmedReason,
					Risk:    risk,
				})
			}

			if !res.Approved {
				feedback := strings.TrimSpace(res.Feedback)
				if feedback == "" {
					feedback = "Command execution rejected by human operator."
				}
				return CommandOutput{
					Command:  trimmedCmd,
					Status:   "rejected",
					ExitCode: -1,
					Stdout:   "",
					Stderr:   feedback,
				}, nil
			}

			return executeApprovedCommand(ctx, trimmedCmd)
		},
	)
}

func executeApprovedCommand(ctx context.Context, command string) (CommandOutput, error) {
	if ctx == nil {
		return CommandOutput{}, status.Errorf(status.ErrInvalidArgument, "%s: execution context is nil", CommandToolName)
	}

	execCtx, cancel := context.WithTimeout(ctx, commandExecutionTimeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(execCtx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(execCtx, "sh", "-c", command)
	}

	stdout := &limitedOutputBuffer{maxBytes: maxCommandOutputBytes}
	stderr := &limitedOutputBuffer{maxBytes: maxCommandOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = sanitizedCommandEnv()
	cmd.WaitDelay = commandWaitDelay

	runErr := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return CommandOutput{}, status.Errorf(
			status.ErrResourceExhausted,
			"%s: command %q output exceeded %d-byte buffer limit",
			CommandToolName,
			command,
			maxCommandOutputBytes,
		)
	}

	outStr := strings.TrimSpace(stdout.String())
	errStr := strings.TrimSpace(stderr.String())

	if runErr != nil {
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			return CommandOutput{}, status.Errorf(
				status.ErrDeadlineExceeded,
				"%s: command %q timed out after %s (stdout=%q, stderr=%q)",
				CommandToolName,
				command,
				commandExecutionTimeout,
				outStr,
				errStr,
			)
		}
		if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
			if errStr == "" {
				errStr = fmt.Sprintf("command exited with code %d", exitErr.ExitCode())
			}
			return CommandOutput{
				Command:  command,
				Status:   "executed",
				ExitCode: exitErr.ExitCode(),
				Stdout:   outStr,
				Stderr:   errStr,
			}, nil
		}
		return CommandOutput{}, status.Errorf(
			status.ErrInternal,
			"%s: failed to execute command %q (stderr=%q): %w",
			CommandToolName,
			command,
			errStr,
			runErr,
		)
	}

	return CommandOutput{
		Command:  command,
		Status:   "executed",
		ExitCode: 0,
		Stdout:   outStr,
		Stderr:   errStr,
	}, nil
}

func normalizeRisk(risk string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(risk)) {
	case "LOW":
		return "LOW", nil
	case "MEDIUM", "MED":
		return "MEDIUM", nil
	case "HIGH", "CRITICAL":
		return "HIGH", nil
	default:
		return "", status.Errorf(
			status.ErrInvalidArgument,
			"%s: invalid risk %q (must be LOW, MEDIUM, or HIGH)",
			CommandToolName,
			risk,
		)
	}
}

func sanitizedCommandEnv() []string {
	env := make([]string, 0, len(allowedCommandEnvVars))
	for _, key := range allowedCommandEnvVars {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	return env
}

type limitedOutputBuffer struct {
	buf      bytes.Buffer
	maxBytes int
	exceeded bool
}

func (b *limitedOutputBuffer) Write(p []byte) (int, error) {
	if b.maxBytes > 0 && b.buf.Len()+len(p) > b.maxBytes {
		remaining := b.maxBytes - b.buf.Len()
		if remaining > 0 {
			_, _ = b.buf.Write(p[:remaining])
		}
		b.exceeded = true
		return 0, fmt.Errorf("command output exceeded maximum buffer size (%d bytes)", b.maxBytes)
	}
	return b.buf.Write(p)
}

func (b *limitedOutputBuffer) String() string {
	return b.buf.String()
}
