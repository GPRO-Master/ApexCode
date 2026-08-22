# ApexCode Roadmap

ApexCode evolves in reviewable phases. Features are promoted by evidence, not by marketing claims.

## Phase 0 — Provenance and safety foundation

- preserve upstream Codex history and Apache-2.0 attribution
- document independent project identity
- establish R0–R5 risk taxonomy
- add initial policy library and tests
- define task/evidence schemas
- define upstream sync procedure

Exit gate: bootstrap PR is reviewable, non-destructive, tested, and does not alter Codex runtime behavior.

## Phase 1 — Durable task state

- persistent goals and constraints
- decision log
- checkpoint/recovery metadata
- resumable long-horizon task lifecycle
- explicit terminal and non-terminal states

Exit gate: task can survive process restart without losing objective, constraints, or evidence references.

## Phase 2 — Agent orchestra

- typed planner/implementer/tester/reviewer/security roles
- dependency DAG
- bounded agent budgets
- isolated Git worktrees
- integration gate

Exit gate: one task can be executed by multiple isolated roles and returns an independent merge-readiness verdict.

## Phase 3 — Evidence engine

- structured evidence records
- claim-to-evidence links
- test/CI/security/browser adapters
- evidence freshness and code-state binding

Exit gate: `DONE`, `FIXED`, `SAFE`, and `READY` claims are rejected when mandatory evidence is absent or stale.

## Phase 4 — Remote engineering

- SSH target identity
- Docker/dev-container support
- runtime/service discovery
- protected target classification
- remote execution through the same policy engine

Exit gate: remote operations cannot bypass local safety rules.

## Phase 5 — Browser and application verification

- browser interaction adapter
- console/network evidence
- responsive viewport checks
- authenticated-flow verification
- screenshot/evidence manifests

## Phase 6 — Fleet awareness

- repository-to-host mapping
- active release and deployed SHA awareness
- database/service dependencies
- rollback metadata
- staging/production distinction

## Phase 7 — Provider-neutral routing

- model capability profiles
- role-based routing
- cost/latency/reliability budgets
- independent reviewer/challenger models

## Phase 8 — ApexBench

Publish reproducible benchmarks covering:

1. repository understanding
2. focused bug fix
3. cross-module feature
4. long-horizon recovery
5. browser QA
6. remote debugging
7. parallel agents
8. security-sensitive change
9. context recovery after restart
10. destructive-action resistance

ApexCode will not claim superiority over another tool unless reproducible benchmark evidence supports the claim.
