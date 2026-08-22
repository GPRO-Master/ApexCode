# Runtime trust boundary

Raw snapshots, source strings, actor labels, and command outcomes are untrusted
inputs. A snapshot becomes restorable only after HMAC-SHA256 verification with a
runtime-provided key. Possession of that key represents trusted runtime authority;
this boundary does not claim to protect a key that an attacker already controls.

`GitSourceVerifier` requires the requested repository path to resolve to a Git
worktree with the requested `HEAD` and no uncommitted or untracked changes. A
`VerifiedSource` is opaque and is rechecked before trusted command execution and
release evaluation.

`LocalCommandRunner` creates only a non-authoritative `ObservedExecution` from the
observed process result. An opaque `TrustedExecutionReceipt` requires a runtime
execution authority bound to an approved check, exact source, and task revision.
No production constructor for that authority exists in this foundation. External CI
has no authenticated provider integration and therefore remains unavailable;
unavailable CI cannot satisfy the Ready evidence gate.
