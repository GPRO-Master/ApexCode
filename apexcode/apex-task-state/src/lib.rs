// Modified for ApexCode by GPRO-Master.
// Licensed under Apache-2.0. See the repository LICENSE file.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

pub const SNAPSHOT_VERSION: u16 = 2;

const SNAPSHOT_MAGIC: &[u8] = b"APEX_TASK_STATE\0";
const SNAPSHOT_MAC_LENGTH: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStateError {
    EmptyTaskId,
    EmptyObjective,
    RevisionOverflow,
    InvalidTransition { from: TaskStatus, to: TaskStatus },
    InvalidRevision { status: TaskStatus, revision: u64 },
}

impl fmt::Display for TaskStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTaskId => formatter.write_str("task id must not be empty"),
            Self::EmptyObjective => formatter.write_str("objective must not be empty"),
            Self::RevisionOverflow => formatter.write_str("task revision cannot be incremented"),
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid task transition: {from:?} -> {to:?}")
            }
            Self::InvalidRevision { status, revision } => {
                write!(
                    formatter,
                    "revision {revision} is invalid for task status {status:?}"
                )
            }
        }
    }
}

impl std::error::Error for TaskStateError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaskId(String);

impl TaskId {
    pub fn new(value: impl Into<String>) -> Result<Self, TaskStateError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TaskStateError::EmptyTaskId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TaskId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Planned,
    Running,
    Blocked,
    AwaitingEvidence,
    ReadyForReview,
    Completed,
    Cancelled,
}

impl TaskStatus {
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Planned, Self::Running | Self::Cancelled)
                | (
                    Self::Running,
                    Self::Blocked | Self::AwaitingEvidence | Self::Cancelled
                )
                | (Self::Blocked, Self::Running | Self::Cancelled)
                | (
                    Self::AwaitingEvidence,
                    Self::Running | Self::ReadyForReview | Self::Blocked | Self::Cancelled
                )
                | (
                    Self::ReadyForReview,
                    Self::Running | Self::Blocked | Self::Completed | Self::Cancelled
                )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    id: TaskId,
    objective: String,
    constraints: Vec<String>,
    status: TaskStatus,
    revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskState {
    id: TaskId,
    objective: String,
    constraints: Vec<String>,
    status: TaskStatus,
    revision: u64,
}

impl TaskState {
    pub fn new(
        id: impl Into<String>,
        objective: impl Into<String>,
        constraints: Vec<String>,
    ) -> Result<Self, TaskStateError> {
        let id = TaskId::new(id)?;
        let objective = objective.into();
        if objective.is_empty() {
            return Err(TaskStateError::EmptyObjective);
        }
        Ok(Self {
            id,
            objective,
            constraints,
            status: TaskStatus::Planned,
            revision: 0,
        })
    }

    pub fn id(&self) -> &TaskId {
        &self.id
    }

    pub fn objective(&self) -> &str {
        &self.objective
    }

    pub fn constraints(&self) -> &[String] {
        &self.constraints
    }

    pub const fn status(&self) -> TaskStatus {
        self.status
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn validate(&self) -> Result<(), TaskStateError> {
        validate_checkpoint(&self.checkpoint())
    }

    pub fn transition(&mut self, next: TaskStatus) -> Result<(), TaskStateError> {
        if !self.status.can_transition_to(next) {
            return Err(TaskStateError::InvalidTransition {
                from: self.status,
                to: next,
            });
        }

        let revision = self
            .revision
            .checked_add(1)
            .ok_or(TaskStateError::RevisionOverflow)?;
        self.status = next;
        self.revision = revision;
        Ok(())
    }

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            id: self.id.clone(),
            objective: self.objective.clone(),
            constraints: self.constraints.clone(),
            status: self.status,
            revision: self.revision,
        }
    }

    fn from_checkpoint_inner(checkpoint: Checkpoint) -> Result<Self, TaskStateError> {
        validate_checkpoint(&checkpoint)?;
        let state = Self {
            id: checkpoint.id,
            objective: checkpoint.objective,
            constraints: checkpoint.constraints,
            status: checkpoint.status,
            revision: checkpoint.revision,
        };
        Ok(state)
    }
}

fn validate_checkpoint(checkpoint: &Checkpoint) -> Result<(), TaskStateError> {
    if checkpoint.id.as_str().is_empty() {
        return Err(TaskStateError::EmptyTaskId);
    }
    if checkpoint.objective.is_empty() {
        return Err(TaskStateError::EmptyObjective);
    }
    if checkpoint.revision < minimum_revision(checkpoint.status) {
        return Err(TaskStateError::InvalidRevision {
            status: checkpoint.status,
            revision: checkpoint.revision,
        });
    }
    Ok(())
}

const fn minimum_revision(status: TaskStatus) -> u64 {
    match status {
        TaskStatus::Planned => 0,
        TaskStatus::Running => 1,
        TaskStatus::Blocked => 2,
        TaskStatus::AwaitingEvidence => 2,
        TaskStatus::ReadyForReview => 3,
        TaskStatus::Completed => 4,
        TaskStatus::Cancelled => 1,
    }
}

const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
const MAX_CONSTRAINTS: usize = 1024;
const SNAPSHOT_TRAILER_BYTES: usize = 1 + std::mem::size_of::<u64>();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidFormat,
    InvalidUtf8,
    UnsupportedVersion(u16),
    InvalidState(TaskStateError),
    InvalidKey,
    AuthenticationFailed,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => formatter.write_str("invalid task-state snapshot format"),
            Self::InvalidUtf8 => formatter.write_str("task-state snapshot contains invalid UTF-8"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported task-state snapshot version {version}"
                )
            }
            Self::InvalidState(error) => write!(formatter, "invalid task state: {error}"),
            Self::InvalidKey => formatter.write_str("snapshot authentication key must be 32 bytes"),
            Self::AuthenticationFailed => formatter.write_str("snapshot authentication failed"),
        }
    }
}

impl std::error::Error for SnapshotError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCandidate {
    envelope: Vec<u8>,
    checkpoint: Checkpoint,
    mac: Option<[u8; SNAPSHOT_MAC_LENGTH]>,
}

#[derive(Clone)]
pub struct SnapshotAuthenticator {
    key: [u8; 32],
}

impl fmt::Debug for SnapshotAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SnapshotAuthenticator(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    checkpoint: Checkpoint,
}

impl SnapshotAuthenticator {
    pub fn from_runtime_key(key: &[u8]) -> Result<Self, SnapshotError> {
        let key: [u8; 32] = key.try_into().map_err(|_| SnapshotError::InvalidKey)?;
        Ok(Self { key })
    }

    pub fn authenticate(
        &self,
        candidate: &SnapshotCandidate,
    ) -> Result<VerifiedCheckpoint, SnapshotError> {
        let Some(mac) = candidate.mac else {
            return Err(SnapshotError::AuthenticationFailed);
        };
        let mut verifier = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| SnapshotError::AuthenticationFailed)?;
        verifier.update(&candidate.envelope);
        verifier
            .verify_slice(&mac)
            .map_err(|_| SnapshotError::AuthenticationFailed)?;
        Ok(VerifiedCheckpoint {
            checkpoint: candidate.checkpoint.clone(),
        })
    }
}

impl SnapshotCandidate {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotError::InvalidFormat);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take(SNAPSHOT_MAGIC.len()) != Some(SNAPSHOT_MAGIC) {
            return Err(SnapshotError::InvalidFormat);
        }
        let version = reader.u16().ok_or(SnapshotError::InvalidFormat)?;
        if version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }
        let payload_length = reader.u32().ok_or(SnapshotError::InvalidFormat)? as usize;
        if payload_length > reader.remaining() {
            return Err(SnapshotError::InvalidFormat);
        }
        let envelope_length = reader.position + payload_length;
        let envelope = bytes
            .get(..envelope_length)
            .ok_or(SnapshotError::InvalidFormat)?
            .to_vec();
        let payload = reader
            .take(payload_length)
            .ok_or(SnapshotError::InvalidFormat)?;
        let mut payload_reader = Reader {
            bytes: payload,
            position: 0,
        };
        let id = TaskId::new(payload_reader.string()?).map_err(SnapshotError::InvalidState)?;
        let objective = payload_reader.string()?;
        let constraint_count = payload_reader.u32().ok_or(SnapshotError::InvalidFormat)? as usize;
        let minimum_constraints_bytes = constraint_count
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or(SnapshotError::InvalidFormat)?;
        if constraint_count > MAX_CONSTRAINTS
            || minimum_constraints_bytes
                .checked_add(SNAPSHOT_TRAILER_BYTES)
                .is_none_or(|required| required > payload_reader.remaining())
        {
            return Err(SnapshotError::InvalidFormat);
        }
        let mut constraints = Vec::with_capacity(constraint_count);
        for _ in 0..constraint_count {
            constraints.push(payload_reader.string()?);
        }
        let status = byte_to_status(payload_reader.byte().ok_or(SnapshotError::InvalidFormat)?)
            .ok_or(SnapshotError::InvalidFormat)?;
        let revision = payload_reader.u64().ok_or(SnapshotError::InvalidFormat)?;
        if !payload_reader.is_empty() {
            return Err(SnapshotError::InvalidFormat);
        }
        let checkpoint = Checkpoint {
            id,
            objective,
            constraints,
            status,
            revision,
        };
        validate_checkpoint(&checkpoint).map_err(SnapshotError::InvalidState)?;

        let remaining = bytes.len().saturating_sub(envelope_length);
        let mac = match remaining {
            0 => None,
            SNAPSHOT_MAC_LENGTH => Some(
                bytes
                    .get(envelope_length..)
                    .ok_or(SnapshotError::InvalidFormat)?
                    .try_into()
                    .map_err(|_| SnapshotError::InvalidFormat)?,
            ),
            _ => return Err(SnapshotError::InvalidFormat),
        };
        Ok(Self {
            envelope,
            checkpoint,
            mac,
        })
    }
}

impl TaskState {
    pub fn from_verified_checkpoint(verified: VerifiedCheckpoint) -> Result<Self, TaskStateError> {
        Self::from_checkpoint_inner(verified.checkpoint)
    }

    pub fn encode_authenticated_snapshot(&self, authenticator: &SnapshotAuthenticator) -> Vec<u8> {
        encode_snapshot_payload(&self.checkpoint(), Some(authenticator))
    }

    pub fn decode_snapshot(bytes: &[u8]) -> Result<SnapshotCandidate, SnapshotError> {
        SnapshotCandidate::from_bytes(bytes)
    }
}

pub fn encode_authenticated_snapshot(
    state: &TaskState,
    authenticator: &SnapshotAuthenticator,
) -> Vec<u8> {
    state.encode_authenticated_snapshot(authenticator)
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<SnapshotCandidate, SnapshotError> {
    SnapshotCandidate::from_bytes(bytes)
}

fn encode_snapshot_payload(
    checkpoint: &Checkpoint,
    authenticator: Option<&SnapshotAuthenticator>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    put_string(&mut payload, checkpoint.id.as_str());
    put_string(&mut payload, &checkpoint.objective);
    payload.extend_from_slice(&(checkpoint.constraints.len() as u32).to_le_bytes());
    for constraint in &checkpoint.constraints {
        put_string(&mut payload, constraint);
    }
    payload.push(status_to_byte(checkpoint.status));
    payload.extend_from_slice(&checkpoint.revision.to_le_bytes());

    let mut bytes = Vec::new();
    bytes.extend_from_slice(SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    if let Some(authenticator) = authenticator {
        let mut signer =
            HmacSha256::new_from_slice(&authenticator.key).expect("fixed-size HMAC key is valid");
        signer.update(&bytes);
        bytes.extend_from_slice(&signer.finalize().into_bytes());
    }
    bytes
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn status_to_byte(status: TaskStatus) -> u8 {
    match status {
        TaskStatus::Planned => 0,
        TaskStatus::Running => 1,
        TaskStatus::Blocked => 2,
        TaskStatus::AwaitingEvidence => 3,
        TaskStatus::ReadyForReview => 4,
        TaskStatus::Completed => 5,
        TaskStatus::Cancelled => 6,
    }
}

fn byte_to_status(value: u8) -> Option<TaskStatus> {
    Some(match value {
        0 => TaskStatus::Planned,
        1 => TaskStatus::Running,
        2 => TaskStatus::Blocked,
        3 => TaskStatus::AwaitingEvidence,
        4 => TaskStatus::ReadyForReview,
        5 => TaskStatus::Completed,
        6 => TaskStatus::Cancelled,
        _ => return None,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(length)?;
        let result = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(result)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn string(&mut self) -> Result<String, SnapshotError> {
        let length = self.u32().ok_or(SnapshotError::InvalidFormat)? as usize;
        let bytes = self.take(length).ok_or(SnapshotError::InvalidFormat)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| SnapshotError::InvalidUtf8)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> TaskState {
        TaskState::new(
            "task-1",
            "implement the foundation",
            vec!["no runtime integration".into()],
        )
        .unwrap()
    }

    #[test]
    fn rejects_empty_task_id() {
        assert_eq!(
            TaskState::new("", "objective", vec![]),
            Err(TaskStateError::EmptyTaskId)
        );
    }

    #[test]
    fn rejects_empty_objective() {
        assert_eq!(
            TaskState::new("task-1", "", vec![]),
            Err(TaskStateError::EmptyObjective)
        );
    }

    #[test]
    fn valid_transition_increments_revision() {
        let mut state = task();
        state.transition(TaskStatus::Running).unwrap();
        assert_eq!(state.status(), TaskStatus::Running);
        assert_eq!(state.revision(), 1);
    }

    #[test]
    fn invalid_transition_preserves_original_state() {
        let mut state = task();
        let original = state.clone();
        assert_eq!(
            state.transition(TaskStatus::Completed),
            Err(TaskStateError::InvalidTransition {
                from: TaskStatus::Planned,
                to: TaskStatus::Completed
            })
        );
        assert_eq!(state, original);
    }

    #[test]
    fn revision_overflow_is_reported_without_mutating_state() {
        let mut state = task();
        state.revision = u64::MAX;
        let original = state.clone();
        assert_eq!(
            state.transition(TaskStatus::Running),
            Err(TaskStateError::RevisionOverflow)
        );
        assert_eq!(state, original);
    }

    #[test]
    fn blocked_task_can_resume() {
        let mut state = task();
        state.transition(TaskStatus::Running).unwrap();
        state.transition(TaskStatus::Blocked).unwrap();
        state.transition(TaskStatus::Running).unwrap();
        assert_eq!(state.revision(), 3);
        assert_eq!(state.status(), TaskStatus::Running);
    }

    #[test]
    fn completed_task_is_terminal() {
        let mut state = task();
        state.transition(TaskStatus::Running).unwrap();
        state.transition(TaskStatus::AwaitingEvidence).unwrap();
        state.transition(TaskStatus::ReadyForReview).unwrap();
        state.transition(TaskStatus::Completed).unwrap();
        let original = state.clone();
        assert!(state.transition(TaskStatus::Running).is_err());
        assert_eq!(state, original);
    }

    #[test]
    fn cancelled_task_is_terminal() {
        let mut state = task();
        state.transition(TaskStatus::Cancelled).unwrap();
        let original = state.clone();
        assert!(state.transition(TaskStatus::Running).is_err());
        assert_eq!(state, original);
    }

    #[test]
    fn checkpoint_restore_preserves_state() {
        let mut state = task();
        state.transition(TaskStatus::Running).unwrap();
        state.transition(TaskStatus::AwaitingEvidence).unwrap();
        let authenticator =
            SnapshotAuthenticator::from_runtime_key(b"01234567890123456789012345678901").unwrap();
        let candidate =
            SnapshotCandidate::from_bytes(&state.encode_authenticated_snapshot(&authenticator))
                .unwrap();
        let restored =
            TaskState::from_verified_checkpoint(authenticator.authenticate(&candidate).unwrap())
                .unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn invalid_checkpoint_revision_is_rejected() {
        assert_eq!(
            TaskState::from_checkpoint_inner(Checkpoint {
                id: TaskId::new("task-1").unwrap(),
                objective: "objective".into(),
                constraints: vec![],
                status: TaskStatus::ReadyForReview,
                revision: 0,
            }),
            Err(TaskStateError::InvalidRevision {
                status: TaskStatus::ReadyForReview,
                revision: 0,
            })
        );
    }

    #[test]
    fn snapshot_encode_decode_round_trip() {
        let mut state = task();
        state.transition(TaskStatus::Running).unwrap();
        state.transition(TaskStatus::Blocked).unwrap();
        let authenticator =
            SnapshotAuthenticator::from_runtime_key(b"01234567890123456789012345678901").unwrap();
        let encoded = state.encode_authenticated_snapshot(&authenticator);
        assert_eq!(encoded, state.encode_authenticated_snapshot(&authenticator));
        let candidate = TaskState::decode_snapshot(&encoded).unwrap();
        let restored =
            TaskState::from_verified_checkpoint(authenticator.authenticate(&candidate).unwrap())
                .unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn corrupt_snapshot_fails() {
        let authenticator =
            SnapshotAuthenticator::from_runtime_key(b"01234567890123456789012345678901").unwrap();
        let mut encoded = task().encode_authenticated_snapshot(&authenticator);
        encoded.pop();
        assert!(matches!(
            TaskState::decode_snapshot(&encoded),
            Err(SnapshotError::InvalidFormat)
        ));
    }

    #[test]
    fn oversized_constraint_count_is_rejected_before_allocation() {
        let mut payload = Vec::new();
        put_string(&mut payload, "task-1");
        put_string(&mut payload, "objective");
        payload.extend_from_slice(&(MAX_CONSTRAINTS as u32 + 1).to_le_bytes());
        payload.push(status_to_byte(TaskStatus::Planned));
        payload.extend_from_slice(&0u64.to_le_bytes());

        let mut encoded = Vec::new();
        encoded.extend_from_slice(SNAPSHOT_MAGIC);
        encoded.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        encoded.extend_from_slice(&payload);

        assert_eq!(
            SnapshotCandidate::from_bytes(&encoded),
            Err(SnapshotError::InvalidFormat)
        );
    }

    #[test]
    fn unsupported_snapshot_version_fails() {
        let mut encoded = encode_snapshot_payload(&task().checkpoint(), None);
        encoded[SNAPSHOT_MAGIC.len()] = 3;
        assert_eq!(
            TaskState::decode_snapshot(&encoded),
            Err(SnapshotError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn snapshot_authentication_binds_every_authoritative_field() {
        let authenticator =
            SnapshotAuthenticator::from_runtime_key(b"01234567890123456789012345678901").unwrap();
        let mut state = task();
        state.transition(TaskStatus::Running).unwrap();
        let encoded = state.encode_authenticated_snapshot(&authenticator);
        let mut variants = Vec::new();

        let revision_offset = encoded.len() - 32 - 1;
        variants.push(revision_offset);
        let id_offset = SNAPSHOT_MAGIC.len() + 2 + 4 + 4;
        variants.push(id_offset);
        let status_offset = encoded.len() - 32 - 9;
        variants.push(status_offset);

        for offset in variants {
            let mut modified = encoded.clone();
            modified[offset] ^= 1;
            let candidate = SnapshotCandidate::from_bytes(&modified).unwrap();
            assert_eq!(
                authenticator.authenticate(&candidate),
                Err(SnapshotError::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn wrong_key_and_unsigned_snapshot_cannot_restore() {
        let authenticator =
            SnapshotAuthenticator::from_runtime_key(b"01234567890123456789012345678901").unwrap();
        let wrong_key =
            SnapshotAuthenticator::from_runtime_key(b"abcdefghijklmnopqrstuvwxyz012345").unwrap();
        let state = task();
        let signed = state.encode_authenticated_snapshot(&authenticator);
        let candidate = SnapshotCandidate::from_bytes(&signed).unwrap();
        assert_eq!(
            wrong_key.authenticate(&candidate),
            Err(SnapshotError::AuthenticationFailed)
        );

        let unsigned =
            SnapshotCandidate::from_bytes(&encode_snapshot_payload(&state.checkpoint(), None))
                .unwrap();
        assert_eq!(
            authenticator.authenticate(&unsigned),
            Err(SnapshotError::AuthenticationFailed)
        );
    }

    #[test]
    fn fabricated_revision_and_completed_state_fail_authentication() {
        let authenticator =
            SnapshotAuthenticator::from_runtime_key(b"01234567890123456789012345678901").unwrap();
        let state = task();
        let encoded = state.encode_authenticated_snapshot(&authenticator);
        let revision_offset = encoded.len() - 32 - 8;
        let mut fabricated = encoded.clone();
        fabricated[revision_offset..revision_offset + 8].copy_from_slice(&999u64.to_le_bytes());
        let candidate = SnapshotCandidate::from_bytes(&fabricated).unwrap();
        assert_eq!(
            authenticator.authenticate(&candidate),
            Err(SnapshotError::AuthenticationFailed)
        );

        let mut completed = state;
        completed.transition(TaskStatus::Running).unwrap();
        completed.transition(TaskStatus::AwaitingEvidence).unwrap();
        completed.transition(TaskStatus::ReadyForReview).unwrap();
        completed.transition(TaskStatus::Completed).unwrap();
        let completed_bytes = completed.encode_authenticated_snapshot(&authenticator);
        let mut fabricated_completed = completed_bytes.clone();
        fabricated_completed[completed_bytes.len() - 32 - 9] = 4;
        fabricated_completed[completed_bytes.len() - 32 - 8..completed_bytes.len() - 32]
            .copy_from_slice(&999u64.to_le_bytes());
        let candidate = SnapshotCandidate::from_bytes(&fabricated_completed).unwrap();
        assert_eq!(
            authenticator.authenticate(&candidate),
            Err(SnapshotError::AuthenticationFailed)
        );
    }
}
