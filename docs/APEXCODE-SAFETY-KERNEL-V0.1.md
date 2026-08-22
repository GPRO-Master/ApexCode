# ApexCode Safety Kernel v0.1

Status: security-reviewed candidate. This document describes the reviewed
foundation; it is not a production-readiness claim.

## Reviewed foundation

Previous public candidate SHA (superseded):

`bae1efc121a158c91cab08b8ae4e7cfe4199e77f`

Final closure checkpoint SHA:

`aed18794421bf75deed3cdb8c90e94f47bf685d6`

The final checkpoint incorporates the remaining reachable review feedback;
the previous SHA must not be read as containing these later fixes.

The kernel is composed of:

- `apex-policy`
- `apex-task-state`
- `apex-evidence`
- `apex-orchestrator`
- `apex-runtime-trust`

## Evidence

- Kernel test suite: **76/76 PASS**
- Apex workspace total: **86/86 PASS**
- Eight previously discovered security findings were remediated and
  revalidated.

The reviewed kernel provides these security properties:

- unknown classifications fail closed;
- evidence is bound to the exact task, revision, and source;
- stale evidence is invalidated;
- implementation, review, security, and release roles remain separated;
- task checkpoints are authenticated;
- source provenance is verified;
- arbitrary command execution produces non-authoritative observations;
- runtime decisions protect against stale time-of-check/time-of-use state;
- R4 release requires explicit release authority; and
- R5 is denied by default.

## Engineering context

ApexCode grew out of real-world Codex use across 11 GPRO projects. That
experience covered AI orchestration, Laravel and business applications,
realtime support, publishing, SEO and workflow automation, infrastructure and
DevOps, security, and multi-repository operations. No proprietary source is
included in this description.

Repeated operational experience motivated persistent task state,
evidence-bound completion, role separation, runtime provenance, fail-closed
execution, and policy gates.

## Project positioning and provenance

ApexCode is an independent open-source project based on [OpenAI
Codex](https://github.com/openai/codex). It is not an official OpenAI product
and is not endorsed by OpenAI.

The project preserves Apache-2.0 attribution and upstream provenance. See the
repository [LICENSE](../LICENSE), [NOTICE](../NOTICE), and
[UPSTREAM.md](../UPSTREAM.md).
