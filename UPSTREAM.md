# ApexCode Upstream Provenance

ApexCode is an independent open-source derivative and extension of [OpenAI Codex](https://github.com/openai/codex).

## Canonical repositories

- Upstream: `openai/codex`
- ApexCode: `GPRO-Master/ApexCode`
- Upstream default branch: `main`
- ApexCode development bootstrap branch: `apex/bootstrap`

## Bootstrap baseline

The ApexCode bootstrap branch was created from Codex commit:

`4f39251a010a8bd7d692d25fb33832ff06f1635a`

ApexCode-specific work should remain easy to identify, review, and rebase against future upstream Codex changes.

## Sync policy

1. Preserve the upstream Git history.
2. Never rewrite upstream history merely to make ApexCode changes appear native.
3. Prefer additive modules and narrow integration points over broad rewrites.
4. Keep ApexCode work on dedicated branches and merge through reviewed pull requests.
5. Record meaningful deviations from upstream behavior.
6. Re-run focused regression, security, and policy tests after every upstream synchronization.
7. Never resolve an upstream conflict by silently dropping an ApexCode safety invariant.

## Attribution and trademarks

OpenAI Codex is licensed under Apache License 2.0. ApexCode preserves the upstream `LICENSE`, `NOTICE`, copyright, patent, trademark, and attribution notices required by that license.

ApexCode is an independent project. It is not an official OpenAI product and is not endorsed by OpenAI. References to OpenAI and Codex are used to describe project origin and compatibility.

## Proprietary boundaries

ApexCode may be informed by production engineering experience, but proprietary applications, customer data, production credentials, infrastructure secrets, private business logic, and confidential deployment material are not part of the public OSS repository.

Only reusable, sanitized, generic engineering components belong in ApexCode.
