# Revision-bound evidence fixture

This fixture documents the cross-contract boundary without adding a runtime dependency between crates.

```text
Task State revision 7
source SHA abc123

        ↓

EvidenceSubject {
    task_revision: 7,
    source_revision: abc123
}

        ↓ source changes

Task State revision 8
source SHA def456

        ↓

ALL evidence for revision 7 / abc123 is stale.
```

An evidence gate must report that evidence as `Blocker::Stale`; it must not silently reuse the older proof.
