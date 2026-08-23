# Apex Runtime Adapter v0.1

This crate provides the first narrow, opt-in ApexCode gate for one Codex
runtime action: read-only file inspection.

The adapter is disabled in the normal `codex-app-server` build, preserving
existing upstream behavior. Building `codex-app-server` with the
`apex-runtime-adapter` Cargo feature enables the gate at the typed
`fs/readFile` dispatch boundary. Classification and policy evaluation happen
before the existing filesystem processor is called; blocked requests never
reach that processor.

The adapter does not create evidence, approvals, trusted execution receipts,
or release authority. It records only bounded request identity and gate
metadata; file paths and file contents are not included in `GateRecord`.

## v0.2a exec observation

The optional `apex-runtime-adapter` feature in `codex-core` observes the
resolved `exec_command` representation immediately before
`UnifiedExecProcessManager::exec_command`. It classifies only high-confidence
command shapes, including shell wrappers, and reports `Unknown` for compound
or unsupported syntax.

This phase is observation-only. The classifier cannot alter commands,
arguments, cwd, approvals, sandbox permissions, or execution results. Apex
failure therefore leaves the existing Codex behavior authoritative. Aggregate
classification counters are emitted through session telemetry. Bounded,
sanitized stderr diagnostics are available only when
`APEXCODE_EXEC_OBSERVATION_DEBUG=1` or `true` is explicitly set; environment
secrets, stdin, full environment state, and file contents are never recorded.
