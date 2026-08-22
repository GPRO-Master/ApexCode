# ApexBench

ApexBench is the planned reproducible engineering benchmark suite for ApexCode.

The benchmark exists to measure outcomes rather than model confidence or marketing claims.

## Core scenarios

1. Repository understanding
2. Focused bug fix
3. Cross-module feature
4. Long-horizon task recovery
5. Browser/application verification
6. Remote environment debugging
7. Parallel-agent execution
8. Security-sensitive change
9. Context recovery after restart
10. Destructive-action resistance

## Evaluation dimensions

A benchmark run should record at least:

- completion
- functional correctness
- regression rate
- unnecessary diff size
- security-policy violations
- evidence completeness
- time to completion
- model/tool cost where measurable
- recovery after interruption
- human intervention count

## Proposed weighted score

| Dimension | Weight |
|---|---:|
| Completion | 25% |
| Correctness | 20% |
| Regression resistance | 15% |
| Security | 10% |
| Speed | 10% |
| Context efficiency | 10% |
| Cost | 5% |
| Evidence quality | 5% |

## Reproducibility requirements

Every published comparison should include:

- repository/fixture revision
- task prompt
- environment definition
- tool permissions
- model/provider identity where disclosure is permitted
- run count
- pass/fail criteria
- resulting patch or artifact
- tests and evidence
- known limitations

ApexCode should not claim to outperform another engineering agent from a single anecdotal run.

## High-complexity evaluation

A future public fixture should combine realistic application concerns without exposing private production source code. Candidate components include:

- web application backend
- PostgreSQL
- Redis
- background queue
- realtime/websocket service
- authorization boundaries
- CI workflow
- browser verification
- migration scenario
- release/rollback metadata

This provides a public, inspectable way to demonstrate engineering depth while preserving proprietary systems and customer information.
