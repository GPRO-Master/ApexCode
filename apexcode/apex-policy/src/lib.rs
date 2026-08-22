// Modified for ApexCode by GPRO-Master.
// Licensed under Apache-2.0. See the repository LICENSE file.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    AllowWithEvidence,
    RequireApproval,
    DenyByDefault,
}

impl RiskLevel {
    pub const fn default_decision(self) -> PolicyDecision {
        match self {
            Self::R0 | Self::R1 => PolicyDecision::Allow,
            Self::R2 => PolicyDecision::AllowWithEvidence,
            Self::R3 | Self::R4 => PolicyDecision::RequireApproval,
            Self::R5 => PolicyDecision::DenyByDefault,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub risk: Option<RiskLevel>,
    pub reason: String,
}

impl Classification {
    pub fn known(risk: RiskLevel, reason: impl Into<String>) -> Self {
        Self {
            risk: Some(risk),
            reason: reason.into(),
        }
    }

    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            risk: None,
            reason: reason.into(),
        }
    }

    pub const fn decision(&self) -> PolicyDecision {
        match self.risk {
            Some(risk) => risk.default_decision(),
            None => PolicyDecision::RequireApproval,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_risk_operations_are_allowed() {
        assert_eq!(RiskLevel::R0.default_decision(), PolicyDecision::Allow);
        assert_eq!(RiskLevel::R1.default_decision(), PolicyDecision::Allow);
    }

    #[test]
    fn reversible_changes_require_evidence() {
        assert_eq!(
            RiskLevel::R2.default_decision(),
            PolicyDecision::AllowWithEvidence
        );
    }

    #[test]
    fn privileged_and_production_changes_require_approval() {
        assert_eq!(
            RiskLevel::R3.default_decision(),
            PolicyDecision::RequireApproval
        );
        assert_eq!(
            RiskLevel::R4.default_decision(),
            PolicyDecision::RequireApproval
        );
    }

    #[test]
    fn destructive_changes_are_denied_by_default() {
        assert_eq!(
            RiskLevel::R5.default_decision(),
            PolicyDecision::DenyByDefault
        );
    }

    #[test]
    fn unknown_risk_fails_closed() {
        let classification = Classification::unknown("operation has not been classified");
        assert_eq!(classification.decision(), PolicyDecision::RequireApproval);
    }
}
