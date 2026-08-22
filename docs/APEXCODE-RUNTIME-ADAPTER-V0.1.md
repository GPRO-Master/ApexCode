# ApexCode Runtime Adapter v0.1

Status: security-reviewed candidate. This document describes the first
reviewed runtime integration; it is not a production-readiness claim.

## Reviewed candidate

Previous runtime candidate SHA (superseded):

`3575971d7be163413a1abe9be71224b8d332e012`

Final integrated closure checkpoint SHA:

`aed18794421bf75deed3cdb8c90e94f47bf685d6`

The final checkpoint incorporates closure feedback around the surrounding
trust kernel. The previous runtime SHA must not be read as containing those
later kernel fixes.

Runtime boundary:

`codex-rs/app-server/src/message_processor.rs`
`MessageProcessor::handle_initialized_client_request`

Gated action:

`ClientRequest::FsReadFile` / `fs/readFile`

## Architecture

```text
Codex Request
      ↓
Apex Runtime Adapter
      ↓
Risk Classification
      ↓
Apex Policy
      ↓
ALLOW / BLOCK / DENY
      ↓
Existing Codex execution
```

The gate runs **before** `FsRequestProcessor::read_file`. A blocked request
returns without invoking the existing filesystem processor. An allowed request
then continues to the existing Codex implementation.

ApexCode does not replace the existing Codex filesystem implementation. The
adapter is an opt-in compile-time feature and does not create evidence,
approval, trusted execution receipts, or release authority. It is disabled in
the normal app-server build to preserve intentional upstream compatibility.

## Public validation results

- Safety kernel: **76/76 PASS**
- Apex workspace: **86/86 PASS**
- Runtime adapter: **10/10 PASS**
- Focused upstream integration: **3/3 PASS** (PR #4 evidence; `codex-rs` is
  unchanged)
- Nearest upstream filesystem regression: **14/14 PASS** (PR #4 evidence;
  `codex-rs` is unchanged)
- Security review: **HIGH 0, MEDIUM 0, LOW 0**
- Kernel modification: **NONE**
- Alternate `fs/readFile` bypass: **ABSENT**
- Blocked request invokes the filesystem processor: **NO**
- Adapter-disabled compatibility: **PASS**

The current Windows GNU toolchain rerun was blocked before upstream test
execution by its linker resolving a user-profile path with a space. No
`codex-rs` source changed, so the published upstream counts remain the
unchanged PR #4 evidence and are identified as such above.

The integration remains a reviewed candidate and is not claimed to be
production-ready.

## Project positioning and provenance

ApexCode is an independent open-source project based on [OpenAI
Codex](https://github.com/openai/codex). It is not an official OpenAI product
and is not endorsed by OpenAI. Apache-2.0 attribution and upstream provenance
are preserved; see the repository [LICENSE](../LICENSE), [NOTICE](../NOTICE),
and [UPSTREAM.md](../UPSTREAM.md).
