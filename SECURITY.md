# Security Policy

ApexCode is an independent open-source derivative and extension of OpenAI Codex. Security issues must be routed according to the component they affect.

## OpenAI Codex vulnerabilities

For vulnerabilities in upstream OpenAI Codex, follow OpenAI's security process. The upstream Codex security program is managed through Bugcrowd:

https://bugcrowd.com/engagements/openai

Codex security boundaries, including sandboxing, approvals, and network controls, are documented at:

https://developers.openai.com/codex/agent-approvals-security

## ApexCode-specific vulnerabilities

Do not publish exploitable vulnerability details, credentials, tokens, private keys, customer information, or production access material in public issues or pull requests.

Until ApexCode configures a dedicated private reporting channel, open a minimal public issue containing only:

- that you found a security issue
- the affected ApexCode component
- a request for a private maintainer contact

Do not include reproduction details that would enable exploitation.

## ApexCode security invariants

ApexCode development should preserve these invariants:

1. Unknown operation risk is not treated as safe by default.
2. Production mutations require explicit authorization.
3. Destructive or irreversible actions are denied by default unless an intentionally configured policy says otherwise.
4. Secrets must not be committed to the repository or emitted into normal logs or evidence.
5. Agent autonomy does not implicitly grant production or destructive authority.
6. Review and security roles must not be silently collapsed into the implementation role when a workflow requires independent approval.
7. Remote execution must pass through the same policy boundary as local execution.
8. Evidence used to authorize higher-risk transitions must be bound to a concrete code or release state.
9. Protected paths, branches, hosts, databases, and environments must fail closed when classification is uncertain.
10. ApexCode must not claim successful verification when required checks were skipped or unavailable.

## Examples of high-risk operations

Examples include, but are not limited to:

- destructive filesystem operations against non-disposable data
- destructive database statements such as `DROP` or `TRUNCATE`
- force-pushing protected branches
- production schema migrations
- production deploy or promotion
- credential rotation
- firewall or SSH changes that can cause lockout
- repository or cloud-resource deletion
- secret-store mutation

These examples are inputs to policy classification, not an exhaustive allow/deny list.

## Threat-model direction

The project will maintain explicit threat models for:

- prompt/tool boundary confusion
- malicious repository instructions
- command injection through tool inputs
- secret disclosure
- approval bypass
- stale or fabricated evidence
- cross-agent trust failures
- worktree and branch races
- remote target misidentification
- model-provider trust boundaries
- MCP or plugin capability escalation

Security-sensitive behavior should ship with focused tests and documented failure semantics.
