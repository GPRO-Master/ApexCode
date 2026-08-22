# ApexCode Architecture

ApexCode extends Codex toward a production-oriented autonomous engineering control plane.

## North star

A complex task should be able to move through:

`Understand -> Plan -> Implement -> Test -> Review -> Security -> Verify -> Evidence -> Human Gate`

without losing durable task state and without silently widening execution authority.

## Core engines

### Orchestrator

Coordinates typed engineering roles such as planner, implementer, tester, reviewer, security reviewer, verifier, and release coordinator.

### Policy engine

Classifies operations by risk and enforces protected resources, protected environments, and explicit approval boundaries.

### Task-state engine

Persists goals, constraints, decisions, checkpoints, active work, and recovery metadata across sessions and worker restarts.

### Evidence engine

Stores machine-verifiable evidence supporting claims such as `DONE`, `FIXED`, `SAFE`, `READY`, and `DEPLOYED`.

### Worktree engine

Provides isolated Git worktrees/branches for parallel implementation and review roles so agents do not overwrite one another's changes.

### Model router

Selects model/provider per role using capability, cost, latency, context, and reliability signals. ApexCode is designed to remain provider-neutral.

### Remote/fleet engine

Represents local, SSH, container, staging, and production targets with identity, service, release, rollback, and protected-resource metadata.

## Risk model

- `R0`: read-only observation
- `R1`: safe local edit
- `R2`: reversible change
- `R3`: privileged/system mutation
- `R4`: production mutation
- `R5`: destructive or irreversible action

Default invariant:

> Unknown risk must not be silently promoted to a safe action.

## Authority model

Agent autonomy and execution authority are separate concepts.

An agent may be allowed to plan, edit, test, and review autonomously while still being unable to perform production mutations or destructive operations.

## Role separation

Implementation, review, security review, and merge/deploy authority should remain independent where practical.

ApexCode should be able to produce a merge-readiness verdict without automatically merging.

## Evidence model

A completion claim should be linked to evidence such as:

- focused tests
- regression suite results
- lint/static analysis
- CI status
- browser QA
- security checks
- migration verification
- deployment health
- rollback readiness

Evidence must be inspectable and attributable to a concrete code/release state.

## Upstream integration strategy

ApexCode initially keeps its new components under `apexcode/` and uses narrow integration points into Codex. This reduces long-term fork drift and makes upstream synchronization reviewable.

See `UPSTREAM.md` for provenance and synchronization policy.
