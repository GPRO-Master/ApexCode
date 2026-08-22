# Revision-bound evidence fixture

This fixture documents the cross-contract boundary without adding a runtime dependency between crates.

```text
Task State revision 7
source SHA abc123

        ↓

EvidenceSubject {
    task_revision: 7,
    source_revision: abc123,
    provenance: Verified
}

        ↓ source changes

Task State revision 8
source SHA def456

        ↓

ALL evidence for revision 7 / abc123 is stale.
```

Raw caller-supplied subjects remain `Unverified` and cannot satisfy an
authoritative gate. A trusted host verifier must explicitly produce the
verified subject. When the source changes, all evidence for revision 7 /
abc123 is stale and cannot be reused for revision 8 / def456.
