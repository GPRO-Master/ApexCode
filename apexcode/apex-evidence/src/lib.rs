// Modified for ApexCode by GPRO-Master.
// Licensed under Apache-2.0. See the repository LICENSE file.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    Test,
    Ci,
    Browser,
    Security,
    Review,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStatus {
    Pass,
    Fail,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvidenceSubject {
    task_id: String,
    task_revision: u64,
    source_revision: String,
    provenance: SubjectProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SubjectProvenance {
    Unverified,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceRole {
    Tester,
    Ci,
    Security,
    Reviewer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceProvenance {
    Unverified,
    Actor { id: String, role: EvidenceRole },
    TrustedSystem { id: String, role: EvidenceRole },
}

pub trait SourceVerifier {
    fn verify(&self, task_id: &str, task_revision: u64, source_revision: &str) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    EmptyTaskId,
    EmptySourceRevision,
    EmptyRequirements,
    VerificationFailed,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTaskId => formatter.write_str("evidence task id must not be empty"),
            Self::EmptySourceRevision => {
                formatter.write_str("evidence source revision must not be empty")
            }
            Self::EmptyRequirements => {
                formatter.write_str("evidence requirements must not be empty")
            }
            Self::VerificationFailed => {
                formatter.write_str("source revision provenance could not be verified")
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

impl EvidenceSubject {
    pub fn new(
        task_id: impl Into<String>,
        task_revision: u64,
        source_revision: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        let subject = Self {
            task_id: task_id.into(),
            task_revision,
            source_revision: source_revision.into(),
            provenance: SubjectProvenance::Unverified,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub fn verify_with<V: SourceVerifier>(mut self, verifier: &V) -> Result<Self, EvidenceError> {
        if !verifier.verify(&self.task_id, self.task_revision, &self.source_revision) {
            return Err(EvidenceError::VerificationFailed);
        }
        self.provenance = SubjectProvenance::Verified;
        Ok(self)
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub const fn task_revision(&self) -> u64 {
        self.task_revision
    }

    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub const fn is_verified(&self) -> bool {
        matches!(self.provenance, SubjectProvenance::Verified)
    }

    fn validate(&self) -> Result<(), EvidenceError> {
        if self.task_id.is_empty() {
            return Err(EvidenceError::EmptyTaskId);
        }
        if self.source_revision.is_empty() {
            return Err(EvidenceError::EmptySourceRevision);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    kind: EvidenceKind,
    status: EvidenceStatus,
    subject: EvidenceSubject,
    detail: String,
    provenance: EvidenceProvenance,
}

impl EvidenceRecord {
    pub fn new(
        kind: EvidenceKind,
        status: EvidenceStatus,
        subject: EvidenceSubject,
        detail: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        subject.validate()?;
        Ok(Self {
            kind,
            status,
            subject,
            detail: detail.into(),
            provenance: EvidenceProvenance::Unverified,
        })
    }

    pub fn with_provenance(
        kind: EvidenceKind,
        status: EvidenceStatus,
        subject: EvidenceSubject,
        detail: impl Into<String>,
        provenance: EvidenceProvenance,
    ) -> Result<Self, EvidenceError> {
        subject.validate()?;
        if let EvidenceProvenance::Actor { id, .. } | EvidenceProvenance::TrustedSystem { id, .. } =
            &provenance
            && id.is_empty()
        {
            return Err(EvidenceError::EmptyTaskId);
        }
        Ok(Self {
            kind,
            status,
            subject,
            detail: detail.into(),
            provenance,
        })
    }

    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }

    pub const fn status(&self) -> EvidenceStatus {
        self.status
    }

    pub fn subject(&self) -> &EvidenceSubject {
        &self.subject
    }

    pub fn provenance(&self) -> &EvidenceProvenance {
        &self.provenance
    }

    fn is_authoritative_for(&self, kind: EvidenceKind) -> bool {
        let required_role = match kind {
            EvidenceKind::Test => EvidenceRole::Tester,
            EvidenceKind::Ci => EvidenceRole::Ci,
            EvidenceKind::Security => EvidenceRole::Security,
            EvidenceKind::Review => EvidenceRole::Reviewer,
            EvidenceKind::Browser | EvidenceKind::Release => return false,
        };
        match &self.provenance {
            EvidenceProvenance::Actor { role, .. }
            | EvidenceProvenance::TrustedSystem { role, .. } => *role == required_role,
            EvidenceProvenance::Unverified => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGate {
    expected_subject: EvidenceSubject,
    required_kinds: Vec<EvidenceKind>,
}

impl EvidenceGate {
    pub fn new(
        expected_subject: EvidenceSubject,
        required_kinds: impl IntoIterator<Item = EvidenceKind>,
    ) -> Result<Self, EvidenceError> {
        expected_subject.validate()?;
        let mut kinds = Vec::new();
        for kind in required_kinds {
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        if kinds.is_empty() {
            return Err(EvidenceError::EmptyRequirements);
        }
        Ok(Self {
            expected_subject,
            required_kinds: kinds,
        })
    }

    pub fn expected_subject(&self) -> &EvidenceSubject {
        &self.expected_subject
    }

    pub fn required_kinds(&self) -> &[EvidenceKind] {
        &self.required_kinds
    }

    pub fn for_claim(
        expected_subject: EvidenceSubject,
        claim: CompletionClaim,
    ) -> Result<Self, EvidenceError> {
        Self::new(
            expected_subject,
            claim.default_requirements().iter().copied(),
        )
    }

    pub fn evaluate(&self, evidence: &[EvidenceRecord]) -> GateResult {
        let mut blockers = Vec::new();

        if !self.expected_subject.is_verified() {
            return GateResult::Blocked(vec![Blocker::ProvenanceRequired]);
        }

        for &kind in &self.required_kinds {
            let matching_kind = evidence.iter().filter(|record| record.kind == kind);
            let mut exact = Vec::new();
            let mut stale = Vec::new();
            for record in matching_kind {
                if record.subject == self.expected_subject {
                    exact.push(record);
                } else {
                    stale.push(record);
                }
            }

            if exact
                .iter()
                .any(|record| !record.is_authoritative_for(kind))
            {
                blockers.push(Blocker::ProvenanceRequired);
            } else if exact
                .iter()
                .any(|record| record.status == EvidenceStatus::Fail)
            {
                blockers.push(Blocker::Failed(kind));
            } else if exact
                .iter()
                .any(|record| record.status == EvidenceStatus::Unavailable)
            {
                blockers.push(Blocker::Unavailable(kind));
            } else if exact
                .iter()
                .any(|record| record.status == EvidenceStatus::Pass)
            {
                continue;
            } else if !stale.is_empty() {
                for record in stale {
                    blockers.push(Blocker::Stale {
                        kind,
                        subject: record.subject.clone(),
                    });
                }
            } else {
                blockers.push(Blocker::Missing(kind));
            }
        }

        if blockers.is_empty() {
            GateResult::Ready
        } else {
            GateResult::Blocked(blockers)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionClaim {
    Done,
    Fixed,
    Safe,
    Ready,
}

impl CompletionClaim {
    pub const fn default_requirements(self) -> &'static [EvidenceKind] {
        match self {
            Self::Done | Self::Fixed => &[EvidenceKind::Test, EvidenceKind::Review],
            Self::Safe => &[
                EvidenceKind::Test,
                EvidenceKind::Security,
                EvidenceKind::Review,
            ],
            Self::Ready => &[
                EvidenceKind::Test,
                EvidenceKind::Ci,
                EvidenceKind::Security,
                EvidenceKind::Review,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    Missing(EvidenceKind),
    Failed(EvidenceKind),
    Unavailable(EvidenceKind),
    ProvenanceRequired,
    Stale {
        kind: EvidenceKind,
        subject: EvidenceSubject,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateResult {
    Ready,
    Blocked(Vec<Blocker>),
}

impl GateResult {
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureVerifier;

    impl SourceVerifier for FixtureVerifier {
        fn verify(&self, _task_id: &str, _task_revision: u64, _source_revision: &str) -> bool {
            true
        }
    }

    fn subject(task_id: &str, revision: u64, source: &str) -> EvidenceSubject {
        EvidenceSubject::new(task_id, revision, source)
            .unwrap()
            .verify_with(&FixtureVerifier)
            .unwrap()
    }

    fn record(
        kind: EvidenceKind,
        status: EvidenceStatus,
        expected: &EvidenceSubject,
    ) -> EvidenceRecord {
        let provenance = match kind {
            EvidenceKind::Test => EvidenceProvenance::Actor {
                id: "tester".into(),
                role: EvidenceRole::Tester,
            },
            EvidenceKind::Ci => EvidenceProvenance::TrustedSystem {
                id: "ci".into(),
                role: EvidenceRole::Ci,
            },
            EvidenceKind::Security => EvidenceProvenance::Actor {
                id: "security".into(),
                role: EvidenceRole::Security,
            },
            EvidenceKind::Review => EvidenceProvenance::Actor {
                id: "reviewer".into(),
                role: EvidenceRole::Reviewer,
            },
            EvidenceKind::Browser | EvidenceKind::Release => EvidenceProvenance::Unverified,
        };
        EvidenceRecord::with_provenance(kind, status, expected.clone(), "fixture", provenance)
            .unwrap()
    }

    fn gate(subject: &EvidenceSubject, kind: EvidenceKind) -> EvidenceGate {
        EvidenceGate::new(subject.clone(), [kind]).unwrap()
    }

    #[test]
    fn exact_matching_evidence_passes_gate() {
        let expected = subject("task-a", 7, "abc123");
        let result = gate(&expected, EvidenceKind::Test).evaluate(&[record(
            EvidenceKind::Test,
            EvidenceStatus::Pass,
            &expected,
        )]);
        assert_eq!(result, GateResult::Ready);
    }

    #[test]
    fn missing_evidence_blocks() {
        let expected = subject("task-a", 7, "abc123");
        assert_eq!(
            gate(&expected, EvidenceKind::Test).evaluate(&[]),
            GateResult::Blocked(vec![Blocker::Missing(EvidenceKind::Test),])
        );
    }

    #[test]
    fn failed_evidence_blocks() {
        let expected = subject("task-a", 7, "abc123");
        assert_eq!(
            gate(&expected, EvidenceKind::Test).evaluate(&[record(
                EvidenceKind::Test,
                EvidenceStatus::Fail,
                &expected,
            )]),
            GateResult::Blocked(vec![Blocker::Failed(EvidenceKind::Test)])
        );
    }

    #[test]
    fn unavailable_evidence_blocks() {
        let expected = subject("task-a", 7, "abc123");
        assert_eq!(
            gate(&expected, EvidenceKind::Test).evaluate(&[record(
                EvidenceKind::Test,
                EvidenceStatus::Unavailable,
                &expected,
            )]),
            GateResult::Blocked(vec![Blocker::Unavailable(EvidenceKind::Test)])
        );
    }

    #[test]
    fn stale_task_revision_blocks() {
        let expected = subject("task-a", 8, "def456");
        let stale = subject("task-a", 7, "abc123");
        let result = gate(&expected, EvidenceKind::Test).evaluate(&[record(
            EvidenceKind::Test,
            EvidenceStatus::Pass,
            &stale,
        )]);
        assert!(
            matches!(result, GateResult::Blocked(blockers) if blockers == vec![Blocker::Stale {
                kind: EvidenceKind::Test,
                subject: stale,
            }])
        );
    }

    #[test]
    fn stale_source_revision_blocks() {
        let expected = subject("task-a", 7, "def456");
        let stale = subject("task-a", 7, "abc123");
        let result = gate(&expected, EvidenceKind::Test).evaluate(&[record(
            EvidenceKind::Test,
            EvidenceStatus::Pass,
            &stale,
        )]);
        assert!(
            matches!(result, GateResult::Blocked(blockers) if blockers == vec![Blocker::Stale {
                kind: EvidenceKind::Test,
                subject: stale,
            }])
        );
    }

    #[test]
    fn evidence_from_another_task_blocks() {
        let expected = subject("task-b", 7, "abc123");
        let other_task = subject("task-a", 7, "abc123");
        let result = gate(&expected, EvidenceKind::Test).evaluate(&[record(
            EvidenceKind::Test,
            EvidenceStatus::Pass,
            &other_task,
        )]);
        assert!(matches!(result, GateResult::Blocked(blockers) if matches!(
            blockers.as_slice(),
            [Blocker::Stale { kind: EvidenceKind::Test, subject }] if subject == &other_task
        )));
    }

    #[test]
    fn fail_overrides_pass_for_same_requirement() {
        let expected = subject("task-a", 7, "abc123");
        let result = gate(&expected, EvidenceKind::Test).evaluate(&[
            record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
            record(EvidenceKind::Test, EvidenceStatus::Fail, &expected),
        ]);
        assert_eq!(
            result,
            GateResult::Blocked(vec![Blocker::Failed(EvidenceKind::Test)])
        );
    }

    #[test]
    fn pass_and_fail_block_in_either_order() {
        let expected = subject("task-a", 7, "abc123");
        for evidence in [
            vec![
                record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
                record(EvidenceKind::Test, EvidenceStatus::Fail, &expected),
            ],
            vec![
                record(EvidenceKind::Test, EvidenceStatus::Fail, &expected),
                record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
            ],
        ] {
            assert_eq!(
                gate(&expected, EvidenceKind::Test).evaluate(&evidence),
                GateResult::Blocked(vec![Blocker::Failed(EvidenceKind::Test)])
            );
        }
    }

    #[test]
    fn pass_and_unavailable_block_in_either_order() {
        let expected = subject("task-a", 7, "abc123");
        for evidence in [
            vec![
                record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
                record(EvidenceKind::Test, EvidenceStatus::Unavailable, &expected),
            ],
            vec![
                record(EvidenceKind::Test, EvidenceStatus::Unavailable, &expected),
                record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
            ],
        ] {
            assert_eq!(
                gate(&expected, EvidenceKind::Test).evaluate(&evidence),
                GateResult::Blocked(vec![Blocker::Unavailable(EvidenceKind::Test)])
            );
        }
    }

    #[test]
    fn duplicate_pass_is_satisfied() {
        let expected = subject("task-a", 7, "abc123");
        let evidence = [
            record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
            record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
        ];
        assert_eq!(
            gate(&expected, EvidenceKind::Test).evaluate(&evidence),
            GateResult::Ready
        );
    }

    #[test]
    fn stale_pass_plus_exact_pass_is_satisfied() {
        let expected = subject("task-a", 8, "def456");
        let stale = subject("task-a", 7, "abc123");
        let evidence = [
            record(EvidenceKind::Test, EvidenceStatus::Pass, &stale),
            record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
        ];
        assert_eq!(
            gate(&expected, EvidenceKind::Test).evaluate(&evidence),
            GateResult::Ready
        );
    }

    #[test]
    fn unverified_subject_cannot_satisfy_gate() {
        let expected = EvidenceSubject::new("task-a", 7, "abc123").unwrap();
        assert_eq!(
            gate(&expected, EvidenceKind::Test).evaluate(&[]),
            GateResult::Blocked(vec![Blocker::ProvenanceRequired])
        );
    }

    #[test]
    fn safe_requires_security_evidence() {
        let expected = subject("task-a", 7, "abc123");
        let evidence = [
            record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
            record(EvidenceKind::Review, EvidenceStatus::Pass, &expected),
        ];
        let result = EvidenceGate::for_claim(expected, CompletionClaim::Safe)
            .unwrap()
            .evaluate(&evidence);
        assert_eq!(
            result,
            GateResult::Blocked(vec![Blocker::Missing(EvidenceKind::Security)])
        );
    }

    #[test]
    fn ready_requires_ci_evidence() {
        let expected = subject("task-a", 7, "abc123");
        let evidence = [
            record(EvidenceKind::Test, EvidenceStatus::Pass, &expected),
            record(EvidenceKind::Security, EvidenceStatus::Pass, &expected),
            record(EvidenceKind::Review, EvidenceStatus::Pass, &expected),
        ];
        let result = EvidenceGate::for_claim(expected, CompletionClaim::Ready)
            .unwrap()
            .evaluate(&evidence);
        assert_eq!(
            result,
            GateResult::Blocked(vec![Blocker::Missing(EvidenceKind::Ci)])
        );
    }

    #[test]
    fn updated_source_invalidates_previously_passing_evidence() {
        let old_subject = subject("task-a", 7, "abc123");
        let new_subject = subject("task-a", 8, "def456");
        let old_evidence = [record(
            EvidenceKind::Test,
            EvidenceStatus::Pass,
            &old_subject,
        )];
        let result = gate(&new_subject, EvidenceKind::Test).evaluate(&old_evidence);
        assert!(matches!(result, GateResult::Blocked(blockers) if matches!(
            blockers.as_slice(),
            [Blocker::Stale { kind: EvidenceKind::Test, subject }] if subject == &old_subject
        )));
    }

    #[test]
    fn empty_requirement_sets_are_rejected() {
        let expected = subject("task-a", 7, "abc123");
        assert_eq!(
            EvidenceGate::new(expected, []),
            Err(EvidenceError::EmptyRequirements)
        );
    }

    #[test]
    fn revision_binding_fixture_matches_contract() {
        let old = subject("task-a", 7, "abc123");
        let updated = subject("task-a", 8, "def456");
        let evidence = [record(EvidenceKind::Test, EvidenceStatus::Pass, &old)];
        assert!(matches!(
            gate(&updated, EvidenceKind::Test).evaluate(&evidence),
            GateResult::Blocked(blockers) if matches!(blockers.as_slice(), [Blocker::Stale { .. }])
        ));
    }
}
