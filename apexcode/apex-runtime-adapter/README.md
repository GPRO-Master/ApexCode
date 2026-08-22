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
