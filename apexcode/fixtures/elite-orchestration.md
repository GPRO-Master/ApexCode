# GPRO elite orchestration fixture

This fixture demonstrates exact subject binding and separation of duties without integrating with `codex-rs`.

```text
Coding actor A (Implementer)
        ↓ submits SHA A
Tester actor B (Tester)
        ↓ submits test evidence for task revision N / SHA A
Reviewer actor C (Reviewer)
        ↓ approves task revision N / SHA A
Security / CSO actor D (Security)
        ↓ approves task revision N / SHA A
DevOps actor E (DevOps)
        ↓ prepares the release for task revision N / SHA A
ReleaseAuthority actor F (ReleaseAuthority)
        ↓ authorizes only after all exact gates pass

Coding actor A pushes SHA B.

Every approval, evidence record, and release authorization bound to SHA A is
stale for SHA B. DevOps actor E cannot release SHA B until new evidence,
review, security approval, and ReleaseAuthority authorization are bound to
task revision N+1 / SHA B. All mandatory identities remain distinct.
```

The orchestrator records each action with actor, role, task revision, and source revision. It does not rewrite evidence history.
