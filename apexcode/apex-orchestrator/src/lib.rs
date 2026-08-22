// Modified for ApexCode by GPRO-Master.
// Licensed under Apache-2.0. See the repository LICENSE file.

use apex_evidence::{
    Blocker as EvidenceBlocker, CompletionClaim, EvidenceGate, EvidenceRecord, EvidenceSubject,
    GateResult,
};
use apex_policy::{PolicyDecision, RiskLevel};
use apex_task_state::{TaskState, TaskStatus};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentRole {
    Planner,
    Architect,
    Implementer,
    Tester,
    Reviewer,
    Security,
    DevOps,
    ReleaseAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    ProposePlan,
    ModifyWorkspace,
    SubmitImplementation,
    SubmitTestEvidence,
    ApproveImplementation,
    ApproveSecurity,
    PrepareRelease,
    InspectDeploymentState,
    AuthorizeRelease,
}

impl AgentRole {
    pub const fn allows(self, capability: Capability) -> bool {
        match self {
            Self::Planner => matches!(capability, Capability::ProposePlan),
            Self::Architect => matches!(capability, Capability::ProposePlan),
            Self::Implementer => matches!(
                capability,
                Capability::ModifyWorkspace | Capability::SubmitImplementation
            ),
            Self::Tester => matches!(capability, Capability::SubmitTestEvidence),
            Self::Reviewer => matches!(capability, Capability::ApproveImplementation),
            Self::Security => matches!(capability, Capability::ApproveSecurity),
            Self::DevOps => matches!(
                capability,
                Capability::PrepareRelease | Capability::InspectDeploymentState
            ),
            Self::ReleaseAuthority => matches!(capability, Capability::AuthorizeRelease),
        }
    }

    pub const fn capabilities(self) -> &'static [Capability] {
        match self {
            Self::Planner => &[Capability::ProposePlan],
            Self::Architect => &[Capability::ProposePlan],
            Self::Implementer => &[
                Capability::ModifyWorkspace,
                Capability::SubmitImplementation,
            ],
            Self::Tester => &[Capability::SubmitTestEvidence],
            Self::Reviewer => &[Capability::ApproveImplementation],
            Self::Security => &[Capability::ApproveSecurity],
            Self::DevOps => &[
                Capability::PrepareRelease,
                Capability::InspectDeploymentState,
            ],
            Self::ReleaseAuthority => &[Capability::AuthorizeRelease],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActorId(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub id: ActorId,
    pub role: AgentRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowStage {
    Planned,
    Implementing,
    Testing,
    Reviewing,
    SecurityReview,
    AwaitingEvidence,
    ReadyForRelease,
    Released,
    Blocked,
    Cancelled,
}

impl WorkflowStage {
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Planned,
                Self::Implementing | Self::Blocked | Self::Cancelled
            ) | (
                Self::Implementing,
                Self::Testing | Self::Blocked | Self::Cancelled
            ) | (
                Self::Testing,
                Self::Reviewing | Self::Blocked | Self::Cancelled
            ) | (
                Self::Reviewing,
                Self::SecurityReview | Self::AwaitingEvidence | Self::Blocked | Self::Cancelled
            ) | (
                Self::SecurityReview,
                Self::AwaitingEvidence | Self::ReadyForRelease | Self::Blocked | Self::Cancelled
            ) | (
                Self::AwaitingEvidence,
                Self::ReadyForRelease
                    | Self::Reviewing
                    | Self::SecurityReview
                    | Self::Blocked
                    | Self::Cancelled
            ) | (
                Self::ReadyForRelease,
                Self::Released | Self::Blocked | Self::Cancelled
            ) | (
                Self::Blocked,
                Self::Implementing
                    | Self::Testing
                    | Self::Reviewing
                    | Self::SecurityReview
                    | Self::AwaitingEvidence
                    | Self::Cancelled
            )
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowAction {
    ProposePlan,
    ModifyWorkspace,
    SubmitImplementation,
    SubmitTestEvidence,
    ApproveImplementation,
    ApproveSecurity,
    PrepareRelease,
    InspectDeploymentState,
    AuthorizeRelease,
    Transition {
        from: WorkflowStage,
        to: WorkflowStage,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub actor: ActorId,
    pub role: AgentRole,
    pub action: WorkflowAction,
    pub task_revision: u64,
    pub source_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestrationError {
    EmptyActorId,
    EmptyTaskId,
    EmptySourceRevision,
    UnauthorizedAction {
        role: AgentRole,
        action: WorkflowAction,
    },
    InvalidTransition {
        from: WorkflowStage,
        to: WorkflowStage,
    },
    SubjectMismatch,
    MissingPrerequisite(WorkflowAction),
    SeparationOfDutiesViolation,
}

impl fmt::Display for OrchestrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyActorId => formatter.write_str("actor id must not be empty"),
            Self::EmptyTaskId => formatter.write_str("orchestration task id must not be empty"),
            Self::EmptySourceRevision => {
                formatter.write_str("orchestration source revision must not be empty")
            }
            Self::UnauthorizedAction { role, action } => {
                write!(formatter, "role {role:?} cannot perform action {action:?}")
            }
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid workflow transition: {from:?} -> {to:?}")
            }
            Self::SubjectMismatch => {
                formatter.write_str("action subject does not match workflow subject")
            }
            Self::MissingPrerequisite(action) => {
                write!(formatter, "missing prerequisite action: {action:?}")
            }
            Self::SeparationOfDutiesViolation => {
                formatter.write_str("separation of duties requirement was not met")
            }
        }
    }
}

impl std::error::Error for OrchestrationError {}

impl ActorId {
    pub fn new(value: impl Into<String>) -> Result<Self, OrchestrationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(OrchestrationError::EmptyActorId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActorId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Actor {
    pub fn new(id: impl Into<String>, role: AgentRole) -> Result<Self, OrchestrationError> {
        Ok(Self {
            id: ActorId::new(id)?,
            role,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseBlocker {
    TaskNotReady,
    EvidenceIncomplete,
    ReviewMissing,
    SecurityApprovalMissing,
    ReleaseAuthorityMissing,
    SeparationOfDutiesViolation,
    SourceRevisionMismatch,
    ProductionApprovalRequired,
    PolicyDenied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseDecision {
    Allowed,
    Blocked(Vec<ReleaseBlocker>),
}

impl ReleaseDecision {
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workflow {
    subject: EvidenceSubject,
    risk: RiskLevel,
    stage: WorkflowStage,
    audit_log: Vec<AuditEntry>,
}

impl Workflow {
    pub fn new(
        task_id: impl Into<String>,
        task_revision: u64,
        source_revision: impl Into<String>,
        risk: RiskLevel,
    ) -> Result<Self, OrchestrationError> {
        let task_id = task_id.into();
        if task_id.is_empty() {
            return Err(OrchestrationError::EmptyTaskId);
        }
        let source_revision = source_revision.into();
        if source_revision.is_empty() {
            return Err(OrchestrationError::EmptySourceRevision);
        }
        Ok(Self {
            subject: EvidenceSubject {
                task_id,
                task_revision,
                source_revision,
            },
            risk,
            stage: WorkflowStage::Planned,
            audit_log: Vec::new(),
        })
    }

    pub fn from_task_state(
        state: &TaskState,
        source_revision: impl Into<String>,
        risk: RiskLevel,
    ) -> Result<Self, OrchestrationError> {
        Self::new(state.id.to_string(), state.revision, source_revision, risk)
    }

    pub fn subject(&self) -> &EvidenceSubject {
        &self.subject
    }

    pub const fn risk(&self) -> RiskLevel {
        self.risk
    }

    pub const fn stage(&self) -> WorkflowStage {
        self.stage
    }

    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    pub fn transition(
        &mut self,
        actor: &Actor,
        next: WorkflowStage,
    ) -> Result<(), OrchestrationError> {
        if !self.stage.can_transition_to(next) {
            return Err(OrchestrationError::InvalidTransition {
                from: self.stage,
                to: next,
            });
        }
        let from = self.stage;
        self.stage = next;
        self.audit_log
            .push(self.entry(actor, WorkflowAction::Transition { from, to: next }));
        Ok(())
    }

    pub fn propose_plan(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.record_capability(
            actor,
            Capability::ProposePlan,
            WorkflowAction::ProposePlan,
            subject,
        )
    }

    pub fn modify_workspace(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.record_capability(
            actor,
            Capability::ModifyWorkspace,
            WorkflowAction::ModifyWorkspace,
            subject,
        )
    }

    pub fn submit_implementation(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.record_capability(
            actor,
            Capability::SubmitImplementation,
            WorkflowAction::SubmitImplementation,
            subject,
        )
    }

    pub fn submit_test_evidence(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.record_capability(
            actor,
            Capability::SubmitTestEvidence,
            WorkflowAction::SubmitTestEvidence,
            subject,
        )
    }

    pub fn approve_implementation(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.require_subject(subject)?;
        self.require_capability(
            actor,
            Capability::ApproveImplementation,
            WorkflowAction::ApproveImplementation,
        )?;
        let implementer = self.actor_for_action(WorkflowAction::SubmitImplementation, subject);
        let Some(implementer) = implementer else {
            return Err(OrchestrationError::MissingPrerequisite(
                WorkflowAction::SubmitImplementation,
            ));
        };
        if implementer == &actor.id {
            return Err(OrchestrationError::SeparationOfDutiesViolation);
        }
        self.audit_log
            .push(self.entry(actor, WorkflowAction::ApproveImplementation));
        Ok(())
    }

    pub fn approve_security(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.require_subject(subject)?;
        self.require_capability(
            actor,
            Capability::ApproveSecurity,
            WorkflowAction::ApproveSecurity,
        )?;
        let implementer = self.actor_for_action(WorkflowAction::SubmitImplementation, subject);
        let Some(implementer) = implementer else {
            return Err(OrchestrationError::MissingPrerequisite(
                WorkflowAction::SubmitImplementation,
            ));
        };
        if implementer == &actor.id {
            return Err(OrchestrationError::SeparationOfDutiesViolation);
        }
        self.audit_log
            .push(self.entry(actor, WorkflowAction::ApproveSecurity));
        Ok(())
    }

    pub fn inspect_deployment_state(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.record_capability(
            actor,
            Capability::InspectDeploymentState,
            WorkflowAction::InspectDeploymentState,
            subject,
        )
    }

    pub fn prepare_release(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.record_capability(
            actor,
            Capability::PrepareRelease,
            WorkflowAction::PrepareRelease,
            subject,
        )
    }

    pub fn authorize_release(
        &mut self,
        actor: &Actor,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.require_subject(subject)?;
        self.require_capability(
            actor,
            Capability::AuthorizeRelease,
            WorkflowAction::AuthorizeRelease,
        )?;
        let devops = self.actor_for_action(WorkflowAction::PrepareRelease, subject);
        let Some(devops) = devops else {
            return Err(OrchestrationError::MissingPrerequisite(
                WorkflowAction::PrepareRelease,
            ));
        };
        if devops == &actor.id {
            return Err(OrchestrationError::SeparationOfDutiesViolation);
        }
        self.audit_log
            .push(self.entry(actor, WorkflowAction::AuthorizeRelease));
        Ok(())
    }

    pub fn release_decision(
        &self,
        task_state: &TaskState,
        source_revision: &str,
        evidence: &[EvidenceRecord],
    ) -> ReleaseDecision {
        let mut blockers = Vec::new();
        if task_state.id.as_str() != self.subject.task_id
            || task_state.revision != self.subject.task_revision
            || source_revision != self.subject.source_revision
        {
            push_unique(&mut blockers, ReleaseBlocker::SourceRevisionMismatch);
        }
        if task_state.status != TaskStatus::ReadyForReview
            || self.stage != WorkflowStage::ReadyForRelease
        {
            push_unique(&mut blockers, ReleaseBlocker::TaskNotReady);
        }

        let gate = EvidenceGate::for_claim(self.subject.clone(), CompletionClaim::Ready)
            .expect("bootstrap Ready requirements are non-empty and subject was validated");
        if let GateResult::Blocked(evidence_blockers) = gate.evaluate(evidence) {
            for blocker in evidence_blockers {
                match blocker {
                    EvidenceBlocker::Stale { .. } => {
                        push_unique(&mut blockers, ReleaseBlocker::SourceRevisionMismatch)
                    }
                    EvidenceBlocker::Missing(_)
                    | EvidenceBlocker::Failed(_)
                    | EvidenceBlocker::Unavailable(_) => {
                        push_unique(&mut blockers, ReleaseBlocker::EvidenceIncomplete)
                    }
                }
            }
        }

        if !self.has_action(WorkflowAction::ApproveImplementation) {
            push_unique(&mut blockers, ReleaseBlocker::ReviewMissing);
        }

        let security_required = matches!(self.risk, RiskLevel::R3 | RiskLevel::R4 | RiskLevel::R5);
        if security_required && !self.has_action(WorkflowAction::ApproveSecurity) {
            push_unique(&mut blockers, ReleaseBlocker::SecurityApprovalMissing);
        }

        match self.risk.default_decision() {
            PolicyDecision::DenyByDefault => {
                push_unique(&mut blockers, ReleaseBlocker::PolicyDenied);
            }
            PolicyDecision::RequireApproval => {
                if !self.has_action(WorkflowAction::AuthorizeRelease) {
                    push_unique(&mut blockers, ReleaseBlocker::ReleaseAuthorityMissing);
                }
            }
            PolicyDecision::Allow | PolicyDecision::AllowWithEvidence => {}
        }
        if self.risk == RiskLevel::R4 && !self.has_action(WorkflowAction::AuthorizeRelease) {
            push_unique(&mut blockers, ReleaseBlocker::ProductionApprovalRequired);
        }
        if self.has_separation_violation() {
            push_unique(&mut blockers, ReleaseBlocker::SeparationOfDutiesViolation);
        }

        if blockers.is_empty() {
            ReleaseDecision::Allowed
        } else {
            ReleaseDecision::Blocked(blockers)
        }
    }

    fn record_capability(
        &mut self,
        actor: &Actor,
        capability: Capability,
        action: WorkflowAction,
        subject: &EvidenceSubject,
    ) -> Result<(), OrchestrationError> {
        self.require_subject(subject)?;
        self.require_capability(actor, capability, action)?;
        self.audit_log.push(self.entry(actor, action));
        Ok(())
    }

    fn require_subject(&self, subject: &EvidenceSubject) -> Result<(), OrchestrationError> {
        if subject == &self.subject {
            Ok(())
        } else {
            Err(OrchestrationError::SubjectMismatch)
        }
    }

    fn require_capability(
        &self,
        actor: &Actor,
        capability: Capability,
        action: WorkflowAction,
    ) -> Result<(), OrchestrationError> {
        if actor.role.allows(capability) {
            Ok(())
        } else {
            Err(OrchestrationError::UnauthorizedAction {
                role: actor.role,
                action,
            })
        }
    }

    fn entry(&self, actor: &Actor, action: WorkflowAction) -> AuditEntry {
        AuditEntry {
            actor: actor.id.clone(),
            role: actor.role,
            action,
            task_revision: self.subject.task_revision,
            source_revision: self.subject.source_revision.clone(),
        }
    }

    fn actor_for_action(
        &self,
        action: WorkflowAction,
        subject: &EvidenceSubject,
    ) -> Option<&ActorId> {
        self.audit_log.iter().find_map(|entry| {
            (entry.action == action
                && entry.task_revision == subject.task_revision
                && entry.source_revision == subject.source_revision)
                .then_some(&entry.actor)
        })
    }

    fn has_action(&self, action: WorkflowAction) -> bool {
        self.audit_log.iter().any(|entry| entry.action == action)
    }

    fn has_separation_violation(&self) -> bool {
        let implementer =
            self.actor_for_action(WorkflowAction::SubmitImplementation, &self.subject);
        let reviewer = self.actor_for_action(WorkflowAction::ApproveImplementation, &self.subject);
        let security = self.actor_for_action(WorkflowAction::ApproveSecurity, &self.subject);
        let devops = self.actor_for_action(WorkflowAction::PrepareRelease, &self.subject);
        let release_authority =
            self.actor_for_action(WorkflowAction::AuthorizeRelease, &self.subject);
        implementer
            .zip(reviewer)
            .is_some_and(|(left, right)| left == right)
            || (matches!(self.risk, RiskLevel::R3 | RiskLevel::R4 | RiskLevel::R5)
                && implementer
                    .zip(security)
                    .is_some_and(|(left, right)| left == right))
            || devops
                .zip(release_authority)
                .is_some_and(|(left, right)| left == right)
    }
}

fn push_unique(blockers: &mut Vec<ReleaseBlocker>, blocker: ReleaseBlocker) {
    if !blockers.contains(&blocker) {
        blockers.push(blocker);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apex_evidence::{EvidenceKind, EvidenceStatus, EvidenceSubject};

    fn actor(id: &str, role: AgentRole) -> Actor {
        Actor::new(id, role).unwrap()
    }

    fn ready_task() -> TaskState {
        let mut state = TaskState::new("task-1", "release the foundation", vec![]).unwrap();
        state.transition(TaskStatus::Running).unwrap();
        state.transition(TaskStatus::AwaitingEvidence).unwrap();
        state.transition(TaskStatus::ReadyForReview).unwrap();
        state
    }

    fn evidence(
        subject: &EvidenceSubject,
        kind: EvidenceKind,
        status: EvidenceStatus,
    ) -> EvidenceRecord {
        EvidenceRecord::new(kind, status, subject.clone(), "fixture").unwrap()
    }

    fn all_ready_evidence(subject: &EvidenceSubject) -> Vec<EvidenceRecord> {
        [
            EvidenceKind::Test,
            EvidenceKind::Ci,
            EvidenceKind::Security,
            EvidenceKind::Review,
        ]
        .into_iter()
        .map(|kind| evidence(subject, kind, EvidenceStatus::Pass))
        .collect()
    }

    fn staged_workflow(
        risk: RiskLevel,
        authorize: bool,
    ) -> (Workflow, TaskState, Actor, Actor, Actor, Actor) {
        let state = ready_task();
        let mut workflow = Workflow::from_task_state(&state, "sha-a", risk).unwrap();
        let implementer = actor("implementer", AgentRole::Implementer);
        let reviewer = actor("reviewer", AgentRole::Reviewer);
        let security = actor("security", AgentRole::Security);
        let devops = actor("devops", AgentRole::DevOps);
        let authority = actor("authority", AgentRole::ReleaseAuthority);
        let subject = workflow.subject().clone();
        workflow
            .transition(&implementer, WorkflowStage::Implementing)
            .unwrap();
        workflow
            .submit_implementation(&implementer, &subject)
            .unwrap();
        workflow
            .transition(&implementer, WorkflowStage::Testing)
            .unwrap();
        workflow
            .submit_test_evidence(&actor("tester", AgentRole::Tester), &subject)
            .unwrap();
        workflow
            .transition(&reviewer, WorkflowStage::Reviewing)
            .unwrap();
        workflow
            .approve_implementation(&reviewer, &subject)
            .unwrap();
        workflow
            .transition(&security, WorkflowStage::SecurityReview)
            .unwrap();
        workflow.approve_security(&security, &subject).unwrap();
        workflow
            .transition(&devops, WorkflowStage::AwaitingEvidence)
            .unwrap();
        workflow.prepare_release(&devops, &subject).unwrap();
        workflow
            .transition(&authority, WorkflowStage::ReadyForRelease)
            .unwrap();
        if authorize {
            workflow.authorize_release(&authority, &subject).unwrap();
        }
        (workflow, state, implementer, reviewer, security, devops)
    }

    #[test]
    fn implementer_cannot_self_review() {
        let state = ready_task();
        let mut workflow = Workflow::from_task_state(&state, "sha-a", RiskLevel::R4).unwrap();
        let implementer = actor("same", AgentRole::Implementer);
        let subject = workflow.subject().clone();
        workflow
            .transition(&implementer, WorkflowStage::Implementing)
            .unwrap();
        workflow
            .submit_implementation(&implementer, &subject)
            .unwrap();
        assert!(
            workflow
                .approve_implementation(&implementer, &subject)
                .is_err()
        );
    }

    #[test]
    fn reviewer_can_approve_another_implementer() {
        let (workflow, _, _, _, _, _) = staged_workflow(RiskLevel::R4, false);
        assert!(workflow.has_action(WorkflowAction::ApproveImplementation));
    }

    #[test]
    fn implementer_cannot_satisfy_security_gate() {
        let state = ready_task();
        let mut workflow = Workflow::from_task_state(&state, "sha-a", RiskLevel::R4).unwrap();
        let implementer = actor("implementer", AgentRole::Implementer);
        let subject = workflow.subject().clone();
        workflow
            .transition(&implementer, WorkflowStage::Implementing)
            .unwrap();
        workflow
            .submit_implementation(&implementer, &subject)
            .unwrap();
        assert!(workflow.approve_security(&implementer, &subject).is_err());
    }

    #[test]
    fn devops_cannot_self_authorize_production_release() {
        let (mut workflow, _, _, _, _, devops) = staged_workflow(RiskLevel::R4, false);
        let same_identity = Actor::new(devops.id.as_str(), AgentRole::ReleaseAuthority).unwrap();
        let subject = workflow.subject().clone();
        assert_eq!(
            workflow.authorize_release(&same_identity, &subject),
            Err(OrchestrationError::SeparationOfDutiesViolation)
        );
    }

    #[test]
    fn release_authority_can_authorize_after_all_gates_pass() {
        let (workflow, state, _, _, _, _) = staged_workflow(RiskLevel::R4, true);
        let result =
            workflow.release_decision(&state, "sha-a", &all_ready_evidence(workflow.subject()));
        assert_eq!(result, ReleaseDecision::Allowed);
    }

    #[test]
    fn missing_test_evidence_blocks_release() {
        let (workflow, state, _, _, _, _) = staged_workflow(RiskLevel::R4, true);
        let evidence = all_ready_evidence(workflow.subject())
            .into_iter()
            .filter(|record| record.kind != EvidenceKind::Test)
            .collect::<Vec<_>>();
        assert!(matches!(
            workflow.release_decision(&state, "sha-a", &evidence),
            ReleaseDecision::Blocked(blockers) if blockers.contains(&ReleaseBlocker::EvidenceIncomplete)
        ));
    }

    #[test]
    fn failed_security_evidence_blocks_release() {
        let (workflow, state, _, _, _, _) = staged_workflow(RiskLevel::R4, true);
        let mut records = all_ready_evidence(workflow.subject());
        records.retain(|record| record.kind != EvidenceKind::Security);
        records.push(evidence(
            workflow.subject(),
            EvidenceKind::Security,
            EvidenceStatus::Fail,
        ));
        assert!(matches!(
            workflow.release_decision(&state, "sha-a", &records),
            ReleaseDecision::Blocked(blockers) if blockers.contains(&ReleaseBlocker::EvidenceIncomplete)
        ));
    }

    #[test]
    fn stale_source_evidence_blocks_release() {
        let (workflow, state, _, _, _, _) = staged_workflow(RiskLevel::R4, true);
        let stale = EvidenceSubject::new("task-1", state.revision, "sha-b").unwrap();
        let evidence = all_ready_evidence(workflow.subject())
            .into_iter()
            .filter(|record| record.kind != EvidenceKind::Review)
            .chain([evidence(&stale, EvidenceKind::Review, EvidenceStatus::Pass)])
            .collect::<Vec<_>>();
        assert!(matches!(
            workflow.release_decision(&state, "sha-a", &evidence),
            ReleaseDecision::Blocked(blockers) if blockers.contains(&ReleaseBlocker::SourceRevisionMismatch)
        ));
    }

    #[test]
    fn stale_task_revision_blocks_release() {
        let (workflow, mut state, _, _, _, _) = staged_workflow(RiskLevel::R4, true);
        state.transition(TaskStatus::Running).unwrap();
        assert!(matches!(
            workflow.release_decision(&state, "sha-a", &all_ready_evidence(workflow.subject())),
            ReleaseDecision::Blocked(blockers) if blockers.contains(&ReleaseBlocker::SourceRevisionMismatch)
        ));
    }

    #[test]
    fn r4_requires_explicit_release_authority() {
        let (workflow, state, _, _, _, _) = staged_workflow(RiskLevel::R4, false);
        assert!(matches!(
            workflow.release_decision(&state, "sha-a", &all_ready_evidence(workflow.subject())),
            ReleaseDecision::Blocked(blockers)
                if blockers.contains(&ReleaseBlocker::ReleaseAuthorityMissing)
                    && blockers.contains(&ReleaseBlocker::ProductionApprovalRequired)
        ));
    }

    #[test]
    fn r5_is_denied_by_default() {
        let (workflow, state, _, _, _, _) = staged_workflow(RiskLevel::R5, true);
        assert!(matches!(
            workflow.release_decision(&state, "sha-a", &all_ready_evidence(workflow.subject())),
            ReleaseDecision::Blocked(blockers) if blockers.contains(&ReleaseBlocker::PolicyDenied)
        ));
    }

    #[test]
    fn invalid_workflow_transition_fails_closed() {
        let state = ready_task();
        let mut workflow = Workflow::from_task_state(&state, "sha-a", RiskLevel::R2).unwrap();
        let planner = actor("planner", AgentRole::Planner);
        assert_eq!(
            workflow.transition(&planner, WorkflowStage::Released),
            Err(OrchestrationError::InvalidTransition {
                from: WorkflowStage::Planned,
                to: WorkflowStage::Released,
            })
        );
        assert_eq!(workflow.stage(), WorkflowStage::Planned);
        assert!(workflow.audit_log().is_empty());
    }

    #[test]
    fn released_state_is_terminal() {
        let (mut workflow, _, _, _, _, _) = staged_workflow(RiskLevel::R2, true);
        let authority = actor("authority", AgentRole::ReleaseAuthority);
        workflow
            .transition(&authority, WorkflowStage::Released)
            .unwrap();
        assert!(
            workflow
                .transition(&authority, WorkflowStage::Blocked)
                .is_err()
        );
        assert_eq!(workflow.stage(), WorkflowStage::Released);
    }

    #[test]
    fn cancelled_state_is_terminal() {
        let state = ready_task();
        let mut workflow = Workflow::from_task_state(&state, "sha-a", RiskLevel::R2).unwrap();
        let planner = actor("planner", AgentRole::Planner);
        workflow
            .transition(&planner, WorkflowStage::Cancelled)
            .unwrap();
        assert!(
            workflow
                .transition(&planner, WorkflowStage::Implementing)
                .is_err()
        );
    }

    #[test]
    fn task_revision_change_invalidates_previous_release_readiness() {
        let (workflow, mut state, _, _, _, _) = staged_workflow(RiskLevel::R4, true);
        let old_evidence = all_ready_evidence(workflow.subject());
        assert_eq!(
            workflow.release_decision(&state, "sha-a", &old_evidence),
            ReleaseDecision::Allowed
        );
        state.transition(TaskStatus::Running).unwrap();
        assert!(matches!(
            workflow.release_decision(&state, "sha-a", &old_evidence),
            ReleaseDecision::Blocked(blockers) if blockers.contains(&ReleaseBlocker::SourceRevisionMismatch)
        ));
    }

    #[test]
    fn source_sha_change_invalidates_previous_release_readiness() {
        let (workflow, state, _, _, _, _) = staged_workflow(RiskLevel::R4, true);
        assert!(matches!(
            workflow.release_decision(&state, "sha-b", &all_ready_evidence(workflow.subject())),
            ReleaseDecision::Blocked(blockers) if blockers.contains(&ReleaseBlocker::SourceRevisionMismatch)
        ));
    }

    #[test]
    fn blocked_workflow_can_resume_through_valid_transition() {
        let state = ready_task();
        let mut workflow = Workflow::from_task_state(&state, "sha-a", RiskLevel::R2).unwrap();
        let planner = actor("planner", AgentRole::Planner);
        workflow
            .transition(&planner, WorkflowStage::Blocked)
            .unwrap();
        workflow
            .transition(&planner, WorkflowStage::Implementing)
            .unwrap();
        assert_eq!(workflow.stage(), WorkflowStage::Implementing);
    }

    #[test]
    fn audit_entry_records_exact_actor_and_revision() {
        let state = ready_task();
        let mut workflow = Workflow::from_task_state(&state, "sha-a", RiskLevel::R2).unwrap();
        let implementer = actor("impl-1", AgentRole::Implementer);
        let subject = workflow.subject().clone();
        workflow
            .submit_implementation(&implementer, &subject)
            .unwrap();
        assert_eq!(
            workflow.audit_log().last(),
            Some(&AuditEntry {
                actor: implementer.id,
                role: AgentRole::Implementer,
                action: WorkflowAction::SubmitImplementation,
                task_revision: state.revision,
                source_revision: "sha-a".into(),
            })
        );
    }
}
