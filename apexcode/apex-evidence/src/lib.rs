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
    pub task_id: String,
    pub task_revision: u64,
    pub source_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    EmptyTaskId,
    EmptySourceRevision,
    EmptyRequirements,
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
        };
        subject.validate()?;
        Ok(subject)
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
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub subject: EvidenceSubject,
    pub detail: String,
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
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGate {
    pub expected_subject: EvidenceSubject,
    pub required_kinds: Vec<EvidenceKind>,
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

        for &kind in &self.required_kinds {
            let matching_kind = evidence.iter().filter(|record| record.kind == kind);
            let mut exact = Vec::new();
            for record in matching_kind {
                if record.subject == self.expected_subject {
                    exact.push(record);
                } else {
                    blockers.push(Blocker::Stale {
                        kind,
                        subject: record.subject.clone(),
                    });
                }
            }

            if exact
                .iter()
                .any(|record| record.status == EvidenceStatus::Fail)
            {
                blockers.push(Blocker::Failed(kind));
            } else if exact
                .iter()
                .any(|record| record.status == EvidenceStatus::Pass)
            {
                continue;
            } else if exact
                .iter()
                .any(|record| record.status == EvidenceStatus::Unavailable)
            {
                blockers.push(Blocker::Unavailable(kind));
            } else if !evidence.iter().any(|record| record.kind == kind) {
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

    fn subject(task_id: &str, revision: u64, source: &str) -> EvidenceSubject {
        EvidenceSubject::new(task_id, revision, source).unwrap()
    }

    fn record(
        kind: EvidenceKind,
        status: EvidenceStatus,
        expected: &EvidenceSubject,
    ) -> EvidenceRecord {
        EvidenceRecord::new(kind, status, expected.clone(), "fixture").unwrap()
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
