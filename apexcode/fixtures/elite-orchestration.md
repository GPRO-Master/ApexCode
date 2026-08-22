# GPRO elite orchestration fixture

This fixture demonstrates exact subject binding and separation of duties without integrating with `codex-rs`.

```text
Coding (Implementer)
        ↓ submits SHA A
Tester (Tester)
        ↓ submits test evidence for task revision N / SHA A
Reviewer (Reviewer)
        ↓ approves task revision N / SHA A
Security / CSO (Security)
        ↓ approves task revision N / SHA A
DevOps (DevOps)
        ↓ prepares the release for task revision N / SHA A
ReleaseAuthority (ReleaseAuthority)
        ↓ authorizes only after all exact gates pass

Coding pushes SHA B.

Every approval and evidence record bound to SHA A is stale for SHA B.
DevOps cannot release SHA B until new evidence, review, and security approval
are bound to task revision N+1 / SHA B, with a distinct ReleaseAuthority actor.
```

The orchestrator records each action with actor, role, task revision, and source revision. It does not rewrite evidence history.
