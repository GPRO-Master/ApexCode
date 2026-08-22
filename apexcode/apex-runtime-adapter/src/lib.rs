//! Narrow, opt-in policy gating for the Codex runtime.
//!
//! v0.1 recognizes exactly one action: an already-typed, absolute-path file
//! read. The adapter only decides whether the caller may invoke the existing
//! runtime implementation; it never performs the action and never creates
//! evidence, approval, trust, or release authority.

use apex_policy::PolicyDecision;
use apex_policy::RiskLevel;
use std::path::Path;

mod exec_classifier;
mod exec_observer;

pub use exec_observer::EXEC_OBSERVATION_CLASSIFICATION_METRIC;
pub use exec_observer::EXEC_OBSERVATION_DEBUG_ENV;
pub use exec_observer::EXEC_OBSERVATION_TOTAL_METRIC;
pub use exec_observer::ExecClassification;
pub use exec_observer::ExecConfidence;
pub use exec_observer::ExecExecutionMode;
pub use exec_observer::ExecObservation;
pub use exec_observer::ExecShellKind;
pub use exec_observer::diagnostics_enabled;
pub use exec_observer::observe_exec_command;

const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;

/// The runtime action kinds understood by this adapter boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeActionKind {
    /// Read one file through the existing Codex filesystem processor.
    ReadFile,
    /// Any action outside the v0.1 boundary.
    Unsupported,
}

/// The adapter's bounded request input.
///
/// The request contains only data used for classification and audit identity.
/// It has no caller-provided risk, policy, approval, or trust fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeActionRequest {
    request_id: String,
    request_id_within_bound: bool,
    action_kind: RuntimeActionKind,
    path: Option<String>,
    path_within_bound: bool,
}

impl RuntimeActionRequest {
    /// Build a request for the one supported read-only action.
    pub fn read_file(request_id: impl Into<String>, path: impl Into<String>) -> Self {
        let (request_id, request_id_within_bound) =
            bounded_text(request_id.into(), MAX_REQUEST_ID_BYTES);
        let (path, path_within_bound) = bounded_text(path.into(), MAX_PATH_BYTES);
        Self {
            request_id,
            request_id_within_bound,
            action_kind: RuntimeActionKind::ReadFile,
            path: Some(path),
            path_within_bound,
        }
    }

    /// Build a request for an action outside the adapter boundary.
    pub fn unsupported(request_id: impl Into<String>) -> Self {
        let (request_id, request_id_within_bound) =
            bounded_text(request_id.into(), MAX_REQUEST_ID_BYTES);
        Self {
            request_id,
            request_id_within_bound,
            action_kind: RuntimeActionKind::Unsupported,
            path: None,
            path_within_bound: true,
        }
    }
}

/// The adapter's classification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeActionClassification {
    /// A supported read-only file inspection.
    R0,
    /// An action that cannot be confidently classified by v0.1.
    Unknown,
}

/// Reasons for a blocked request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateBlockReason {
    /// The action is not confidently classified by this adapter.
    UnknownClassification,
    /// The policy requires evidence, which v0.1 cannot fabricate.
    EvidenceRequired,
    /// The policy requires approval, which v0.1 cannot fabricate.
    ApprovalRequired,
    /// The adapter could not produce a safe decision.
    AdapterError,
}

/// The final gate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// The existing runtime action may now be invoked.
    Allow,
    /// The action is blocked pending a capability not implemented here.
    Block,
    /// The policy denies the action by default.
    Deny,
}

/// A lightweight, secret-free audit record for one gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRecord {
    request_id: String,
    action_kind: RuntimeActionKind,
    classification: RuntimeActionClassification,
    policy_decision: PolicyDecision,
    outcome: GateOutcome,
}

impl GateRecord {
    /// Return the bounded request identity.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Return the classified action kind.
    pub const fn action_kind(&self) -> RuntimeActionKind {
        self.action_kind
    }

    /// Return the adapter classification.
    pub const fn classification(&self) -> RuntimeActionClassification {
        self.classification
    }

    /// Return the policy decision used by the gate.
    pub const fn policy_decision(&self) -> PolicyDecision {
        self.policy_decision
    }

    /// Return the final gate outcome.
    pub const fn outcome(&self) -> GateOutcome {
        self.outcome
    }
}

/// The result of evaluating one request before the original action runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateDecision {
    record: GateRecord,
    block_reason: Option<GateBlockReason>,
}

impl GateDecision {
    /// Evaluate the request using the Apex policy mapping.
    pub fn evaluate(request: &RuntimeActionRequest) -> Self {
        let classification = classify(request);
        evaluate_classification(request, Ok(classification))
    }

    /// Return the generated audit record.
    pub const fn record(&self) -> &GateRecord {
        &self.record
    }

    /// Return whether the existing runtime action may be invoked.
    pub const fn is_allowed(&self) -> bool {
        matches!(self.record.outcome, GateOutcome::Allow)
    }

    /// Return the blocking reason, if the request was not allowed.
    pub const fn block_reason(&self) -> Option<GateBlockReason> {
        self.block_reason
    }
}

fn classify(request: &RuntimeActionRequest) -> RuntimeActionClassification {
    let Some(path) = request.path.as_deref() else {
        return RuntimeActionClassification::Unknown;
    };

    if request.action_kind != RuntimeActionKind::ReadFile
        || request.request_id.is_empty()
        || !request.request_id_within_bound
        || path.is_empty()
        || !request.path_within_bound
        || !Path::new(path).is_absolute()
    {
        return RuntimeActionClassification::Unknown;
    }

    RuntimeActionClassification::R0
}

fn bounded_text(value: String, limit: usize) -> (String, bool) {
    if value.len() <= limit {
        return (value, true);
    }

    let end = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= limit)
        .last()
        .unwrap_or(0);
    (value[..end].to_string(), false)
}

fn evaluate_classification(
    request: &RuntimeActionRequest,
    classification: Result<RuntimeActionClassification, GateBlockReason>,
) -> GateDecision {
    let (classification, policy_decision, outcome, block_reason) = match classification {
        Ok(RuntimeActionClassification::R0) => {
            return decision_for_policy(
                request,
                RuntimeActionClassification::R0,
                RiskLevel::R0.default_decision(),
            );
        }
        Ok(RuntimeActionClassification::Unknown) => (
            RuntimeActionClassification::Unknown,
            PolicyDecision::RequireApproval,
            GateOutcome::Block,
            Some(GateBlockReason::UnknownClassification),
        ),
        Err(reason) => (
            RuntimeActionClassification::Unknown,
            PolicyDecision::RequireApproval,
            GateOutcome::Block,
            Some(reason),
        ),
    };

    GateDecision {
        record: GateRecord {
            request_id: request.request_id.clone(),
            action_kind: request.action_kind,
            classification,
            policy_decision,
            outcome,
        },
        block_reason,
    }
}

fn decision_for_policy(
    request: &RuntimeActionRequest,
    classification: RuntimeActionClassification,
    policy_decision: PolicyDecision,
) -> GateDecision {
    let (outcome, block_reason) = match policy_decision {
        PolicyDecision::Allow => (GateOutcome::Allow, None),
        PolicyDecision::AllowWithEvidence => {
            (GateOutcome::Block, Some(GateBlockReason::EvidenceRequired))
        }
        PolicyDecision::RequireApproval => {
            (GateOutcome::Block, Some(GateBlockReason::ApprovalRequired))
        }
        PolicyDecision::DenyByDefault => (GateOutcome::Deny, None),
    };
    GateDecision {
        record: GateRecord {
            request_id: request.request_id.clone(),
            action_kind: request.action_kind,
            classification,
            policy_decision,
            outcome,
        },
        block_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_request() -> RuntimeActionRequest {
        RuntimeActionRequest::read_file(
            "request-1",
            std::env::temp_dir()
                .join("read-only.txt")
                .display()
                .to_string(),
        )
    }

    #[test]
    fn supported_read_only_action_is_classified_as_r0() {
        let decision = GateDecision::evaluate(&read_request());
        assert_eq!(
            decision.record().classification(),
            RuntimeActionClassification::R0
        );
    }

    #[test]
    fn r0_is_allowed() {
        let decision = GateDecision::evaluate(&read_request());
        assert!(decision.is_allowed());
        assert_eq!(decision.record().policy_decision(), PolicyDecision::Allow);
    }

    #[test]
    fn unknown_action_is_blocked() {
        let decision = GateDecision::evaluate(&RuntimeActionRequest::unsupported("request-1"));
        assert_eq!(
            decision.record().classification(),
            RuntimeActionClassification::Unknown
        );
        assert_eq!(decision.record().outcome(), GateOutcome::Block);
        assert_eq!(
            decision.block_reason(),
            Some(GateBlockReason::UnknownClassification)
        );
    }

    #[test]
    fn policy_decisions_that_need_evidence_or_approval_fail_closed() {
        let request = read_request();
        let evidence = decision_for_policy(
            &request,
            RuntimeActionClassification::Unknown,
            PolicyDecision::AllowWithEvidence,
        );
        let approval = decision_for_policy(
            &request,
            RuntimeActionClassification::Unknown,
            PolicyDecision::RequireApproval,
        );
        assert_eq!(
            evidence.block_reason(),
            Some(GateBlockReason::EvidenceRequired)
        );
        assert_eq!(
            approval.block_reason(),
            Some(GateBlockReason::ApprovalRequired)
        );
        assert!(!evidence.is_allowed());
        assert!(!approval.is_allowed());
    }

    #[test]
    fn deny_by_default_is_denied() {
        let decision = decision_for_policy(
            &read_request(),
            RuntimeActionClassification::Unknown,
            PolicyDecision::DenyByDefault,
        );
        assert_eq!(decision.record().outcome(), GateOutcome::Deny);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn adapter_internal_error_is_blocked() {
        let decision = evaluate_classification(&read_request(), Err(GateBlockReason::AdapterError));
        assert_eq!(decision.record().outcome(), GateOutcome::Block);
        assert_eq!(decision.block_reason(), Some(GateBlockReason::AdapterError));
    }

    #[test]
    fn caller_cannot_supply_a_risk_hint_to_override_classification() {
        let decision = GateDecision::evaluate(&RuntimeActionRequest::unsupported("request-1"));
        assert_eq!(
            decision.record().classification(),
            RuntimeActionClassification::Unknown
        );
        assert!(!decision.is_allowed());
    }

    #[test]
    fn malformed_read_request_is_unknown_and_blocked() {
        let decision = GateDecision::evaluate(&RuntimeActionRequest::read_file("", "relative"));
        assert_eq!(
            decision.record().classification(),
            RuntimeActionClassification::Unknown
        );
        assert_eq!(
            decision.block_reason(),
            Some(GateBlockReason::UnknownClassification)
        );
    }

    #[test]
    fn oversized_metadata_is_bounded_and_blocked() {
        let request = RuntimeActionRequest::read_file(
            "request-1",
            format!(
                "{}{}",
                std::path::MAIN_SEPARATOR,
                "x".repeat(MAX_PATH_BYTES)
            ),
        );
        let decision = GateDecision::evaluate(&request);
        assert_eq!(
            decision.record().classification(),
            RuntimeActionClassification::Unknown
        );
        assert!(decision.record().request_id().len() <= MAX_REQUEST_ID_BYTES);
        assert_eq!(decision.record().outcome(), GateOutcome::Block);
    }

    #[test]
    fn gate_record_does_not_contain_path_or_contents() {
        let request = RuntimeActionRequest::read_file(
            "request-1",
            "/secret/path.txt?contents=must-not-be-recorded",
        );
        let record = GateDecision::evaluate(&request).record().clone();
        let debug = format!("{record:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("contents"));
    }
}
