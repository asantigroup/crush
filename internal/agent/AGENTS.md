# Agent Loop

This document describes the orchestration layer in `internal/agent/`, with
a focus on the run loop that drives a single user prompt from dispatch to
terminal event.

## Two-Layer Architecture

Agent execution is split into two layers:

- **`coordinator`** (`coordinator.go`) — the top-level entry point exposed
  to the rest of the app via the `Coordinator` interface. It owns the
  configured `SessionAgent`s ("coder", "task"), resolves models and
  provider options per run, refreshes OAuth/API-key credentials, and
  coalesces retry chains (e.g. 401 → re-auth → retry) into a single
  user-visible terminal event. There is exactly one coordinator per
  workspace, created in `app.New` / `backend.CreateWorkspace`.
- **`sessionAgent`** (`agent.go`) — the per-agent run loop. Each
  `SessionAgent` (`coder`, `task`) runs turns against a single
  `fantasy.Agent`. The coordinator delegates to it via
  `SessionAgent.Run`, which is where the actual streaming loop lives.

The `Coordinator.Run` / `RunAccepted` methods are thin wrappers over
`coordinator.run`, which builds a `SessionAgentCall`, threads the
`RunID` from the context, installs the `OnComplete` coalesce hook, and
hands off to `currentAgent.Run` inside `runWithUnauthorizedRetry`.

## The Run Loop (`sessionAgent.Run`)

`Run` is the heart of the agent. A single invocation drives one user
prompt through zero or more LLM streaming steps, then hands off to the
next queued prompt. The phases below all live in
`internal/agent/agent.go`.

### 1. Dispatch Handoff

Before any streaming starts, `Run` decides how the prompt enters the
session. There are two entry paths, distinguished by whether the call
carries an `AcceptedRun` reservation:

- **Accepted (fire-and-forget) path** — used by `RunAccepted`, the
  HTTP/backend dispatch path. `Run` takes the per-session dispatch
  mutex (`sessionMu`) and atomically chooses one of:
  - **Cancel-on-entry**: the call's accept sequence is at or below the
    session's `cancelMark` (a cancel arrived while this prompt was
    dispatched but not yet active). The accept reservation is released,
    a canceled turn is persisted without entering streaming, and a
    terminal `RunComplete{Cancelled: true}` is published.
  - **Queue**: the session is busy with an earlier prompt. The call is
    appended to `messageQueue` (with `OnComplete` and `Accepted`
    stripped) and the reservation is released.
  - **Become active**: the session is idle. A run context + cancel func
    is created under the lock and stored in `activeRequests` *before*
    the lock is dropped, so a concurrent `Cancel` can't miss it.
- **In-process path** — used by local callers (`AppWorkspace`,
  `coordinator.Run`). If the session is busy the call is queued and
  returns immediately; otherwise it proceeds and registers
    `activeRequests` later, after the assistant message context is set
    up.

The dispatch mutex (`dispatchMu`) serializes the accepted →
(cancel | queued | active) transition against a concurrent `Cancel`,
guaranteeing every cancel observes at least one of: a cancel mark, an
`activeRequests` entry, or a `messageQueue` entry it can clear.

### 2. Session & Prompt Preparation

After the handoff, `Run`:

1. Snapshots mutable fields (`tools`, `largeModel`, `systemPrompt`,
   `promptPrefix`) under their `csync` locks to avoid races with
   `SetTools`/`SetModels`.
2. Appends any connected MCP server instructions to the system prompt.
3. Applies Anthropic prompt-caching options to the last tool and
   message boundaries.
4. Constructs a `fantasy.Agent` via `fantasy.NewAgent` with the system
   prompt, tools, user agent, and a 10-retry cap.
5. Loads the session and its message history (`getSessionMessages`),
   trimming to the last summary message when one exists.
6. Lazily generates a session title from the first user prompt (runs on
   its own goroutine via `wg.Go`).
7. Persists the user message (`createUserMessage`).

### 3. The Streaming Call

`Run` invokes `agent.Stream(genCtx, call)` with a set of callbacks. The
`fantasy` library drives the multi-step conversation, calling back into
Crush at each phase of each step:

- **`PrepareStep`** — runs at the *start* of every step. It:
  - Refreshes the tool list from `a.tools` (picks up MCP tool changes).
  - Drains queued follow-up prompts for this step via
    `drainQueueForStep`. Calls covered by a pending cancel are dropped
    (their `RunComplete` is still published if they carry a `RunID`);
    uncanceled prompts without a `RunID` are folded into this turn's
    message list; uncanceled prompts with a `RunID` stay queued to run
    as their own turn.
  - Applies provider media limitations and prompt-caching breakpoints.
  - Creates the assistant `message.Message` row and stashes it in
    `currentAssistant` (a pointer captured by the deferred
    `RunComplete` publish and by every streaming callback).
  - Seeds the call context with `MessageIDContextKey`,
    `SupportsImagesContextKey`, and `ModelNameContextKey` so tools can
    read them.

- **Reasoning callbacks** (`OnReasoningStart`/`OnReasoningDelta`/
  `OnReasoningEnd`) — append reasoning content to the assistant message
  and persist each delta. `OnReasoningEnd` also extracts provider
    signatures (Anthropic, Google, OpenAI Responses) and calls
    `FinishThinking`.

- **`OnTextDelta`** — appends streamed text, stripping a leading
  newline from the first chunk (important for non-interactive mode).

- **`OnToolInputStart`** — registers a tool call stub on the assistant
  message before its input has finished streaming.

- **`OnToolCall`** — finalizes a tool call. Input is sanitized
  (`sanitizeToolInput`); if sanitization rewrote it, the call is
  flagged so `OnToolResult` can substitute an error response.

- **`OnToolResult`** — converts the provider result into a
  `message.ToolResult` and creates a `message.Tool` row. Sanitized
  calls get a synthetic JSON-format error instead of the real result.

- **`OnRetry`** — logs provider retries with structured fields.

- **`OnStepFinish`** — maps the fantasy finish reason to Crush's
  `message.FinishReason`, downgrades a tool-halting step to
  `FinishReasonEndTurn` when a tool result set `StopTurn` (hook halt /
  permission denial), updates session usage and cost
  (`updateSessionUsage`, with an estimated fallback when the provider
  omits usage), and persists the assistant message.

  Note: tool execution itself is delegated by `fantasy` to each tool's
  `Run`. Built-in tools live in `internal/agent/tools/`; each tool is
  optionally wrapped by a `hookedTool` (`hooked_tool.go`) that runs
  `PreToolUse` hooks, applies allow/deny/halt decisions, rewrites input,
  and pre-approves permissions before the inner tool runs.

### 4. Stop Conditions

The stream ends when one of the `StopWhen` conditions fires
(`agent.go:1005`):

- **Auto-summarize threshold**: when remaining context-window tokens
  drop below a buffer (20k for large windows, 20% for small ones) and
  auto-summarize isn't disabled. Sets `shouldSummarize = true`.
- **Loop detection** (`loop_detection.go`): when any single tool-call
  signature (a SHA-256 over tool name + input + result output) repeats
  more than `loopDetectionMaxRepeats` (5) times within the last
  `loopDetectionWindowSize` (10) steps. This halts runs stuck calling
  the same tool with the same arguments in a loop.

Otherwise the stream ends naturally when the model stops emitting tool
calls (`FinishReasonStop`).

### 5. Error Handling & Recovery

After `Stream` returns, `Run` inspects the error:

- **Cancel-before-assistant window** (canceled after
  `activeRequests.Set` but before `PrepareStep` created the assistant
  row): `persistCanceledTurn` writes the missing assistant message
  with `FinishReasonCanceled`.
- **Context canceled**: the assistant is marked
  `FinishReasonCanceled`; incomplete tool calls get synthetic error
  tool results so the persisted history is valid for the next turn.
- **Hyper 401**: `FinishReasonError("Unauthorized")` with a
  re-authenticate hint.
- **Hyper 402**: `FinishReasonError("No credits")` with a top-up link.
- **Copilot "model not supported"**: `FinishReasonError` with a link to
  the Copilot features page.
- **Generic provider / fantasy errors**: the error's title and message
  are attached to the assistant's finish metadata.

All post-error persistence uses a detached `context.WithoutCancel`
(`cleanupCtx`) with a 5s timeout, because the run context is canceled
by the time these writes run. Incomplete tool calls (no matching tool
result) are backfilled with synthetic error results so the message
history never violates the LLM APIs' tool_use→tool_result invariant.

### 6. Auto-Summarize

If `shouldSummarize` fired, `Run` releases the active-request slot and
calls `Summarize`, which:

1. Builds a fresh `fantasy.Agent` with the embedded `summary.md` prompt.
2. Creates an assistant message flagged `IsSummaryMessage`.
3. Streams a summary of the conversation so far.
4. On success, points `session.SummaryMessageID` at the summary and
   resets token counters — `getSessionMessages` will subsequently trim
   history to start at the summary.
5. If the interrupted turn had outstanding tool calls, re-queues the
   original prompt (with an "interrupted because it got too long"
   preamble) so it resumes after summarization.

`Summarize` then drains its own queue the same way `Run` does.

### 7. Queue Drain & Recursion

After a turn completes (success or handled error), `Run` performs the
queue handoff under `dispatchMu`:

1. Re-checks the cancel mark against any queued prompts. Covered
   prompts are dropped (their `RunComplete` is published if they carry
   a `RunID`); prompts accepted after the cancel are kept.
2. If the queue is empty, clears the cancel mark (only when no
   accepted runs remain in flight) and returns.
3. Otherwise dequeues the first prompt, reserves a fresh `AcceptedRun`
   for it (so `acceptedRuns > 0` across the handoff into the recursive
   `Run`), sets `skipRunComplete = true` on the current turn, and
   **recurses** via `return a.Run(ctx, firstQueuedMessage)`.

Each queued prompt with a `RunID` runs as its own turn and publishes
its own terminal `RunComplete`. The outer turn publishes its own
`RunComplete` first (`outerOwesRunComplete`) unless it's handing off
to itself via the summarize-continuation path (same `RunID`).

### 8. Terminal Event

A deferred function (`agent.go:745`) runs at every `Run` exit:

1. Flushes pending message updates via `messages.FlushAll` on a
   detached context (5s timeout) so streaming deltas land before the
   DB closes.
2. Unless `skipRunComplete` is set (recursion path), builds the
   authoritative `notify.RunComplete{SessionID, RunID, MessageID, Text}`
   and publishes it via `publishRunComplete`.
3. `publishRunComplete` honors the per-call `OnComplete` hook (so the
   coordinator can coalesce retries) and otherwise falls back to
   `runComplete.PublishMustDeliver` so a full subscriber buffer can't
   silently drop the terminal event and hang non-interactive clients.

The `RunComplete` event is the single source of truth for turn
completion. `RunID` lets clients (`crush run`, the TUI) correlate a
terminal event with the specific `SendMessage` that started it, even
when the session is busy and other turns are finishing concurrently.

## Cancellation

`Cancel(sessionID)` (`agent.go:1896`) takes the per-session dispatch
mutex and:

1. Cancels the active request's context (if any). The entry stays in
   `activeRequests` so `IsBusy` remains true until the goroutine
   finishes its cleanup writes.
2. Cancels any active summarize request.
3. Raises `cancelMark` to the current accept sequence — but only when
   `acceptedRuns > 0`, so an idle Escape is a true no-op and never
   poisons the next prompt.
4. Clears the message queue, publishing cancelled `RunComplete`s for
   any dropped prompts that carried a `RunID`.

`CancelAll` iterates every active session and waits (up to 5s) for
busy state to clear.

## Sub-Agents

The `agent` tool (`agent_tool.go`) exposes the "task" `SessionAgent`
as a parallel tool the coder agent can invoke. `runSubAgent` creates a
child session (`CreateTaskSession`), runs the sub-agent to completion,
propagates cost/tokens to the parent session, and returns the final
assistant text as the tool result. Sub-agents never fire hooks (see
`wrapToolsWithHooks`); the top-level invocation of the tool itself is
already wrapped on the caller's side.

## Key Types

| Type | File | Role |
|---|---|---|
| `Coordinator` | `coordinator.go` | Top-level agent manager exposed to the app |
| `SessionAgent` | `agent.go` | Per-agent run-loop interface |
| `sessionAgent` | `agent.go` | `SessionAgent` implementation; owns the streaming loop |
| `SessionAgentCall` | `agent.go` | One prompt's parameters + `RunID`/`Accepted`/`OnComplete` |
| `AcceptedRun` | `agent.go` | Accept reservation with monotonic sequence for cancel coverage |
| `Model` | `agent.go` | Wraps a `fantasy.LanguageModel`, catwalk config, and selected model cfg |
| `notify.RunComplete` | `notify/notify.go` | Authoritative terminal event for a turn |
| `notify.Notification` | `notify/notify.go` | Agent lifecycle events (finished, re-auth, error) |
| `hookedTool` | `hooked_tool.go` | Tool decorator running `PreToolUse` hooks + permission gating |
| `runCompleteMarker` | `run_marker.go` | Context flag deduping terminal events across dispatch layers |

## Key Concurrency Primitives

All live on `sessionAgent` and are keyed by session ID:

- `activeRequests` — `sessionID → context.CancelFunc` for the active
  (or canceling) run. Presence means busy.
- `messageQueue` — `sessionID → []SessionAgentCall` of pending prompts.
- `dispatchMu` — per-session mutex serializing the dispatch handoff
  against `Cancel` (created lazily via `sessionMu`, guarded by
  `dispatchMuCreate`).
- `acceptedRuns` — per-session count of dispatched-but-not-yet-active
  accepted runs. >0 means a cancel should record a mark.
- `cancelMark` — per-session high-water accept sequence. A handle is
  covered iff its sequence ≤ the mark; a handle accepted after the
  cancel (higher sequence) is never poisoned.
- `acceptedMu` — serializes `acceptedRuns` mutations and accept
  sequence assignment, separate from `dispatchMu` so `AcceptedRun.Close`
  can run while `Run` holds `dispatchMu`.

`largeModel`, `smallModel`, `systemPrompt`, `systemPromptPrefix`, and
`tools` are `csync.Value`/`csync.Slice` so they can be swapped at
runtime by `SetModels`/`SetTools`/`SetSystemPrompt` without locking
the run loop.
