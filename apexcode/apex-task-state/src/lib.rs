// Modified for ApexCode by GPRO-Master.
// Licensed under Apache-2.0. See the repository LICENSE file.

use std::fmt;

pub const SNAPSHOT_VERSION: u16 = 1;

const SNAPSHOT_MAGIC: &[u8] = b"APEX_TASK_STATE\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStateError {
    EmptyTaskId,
    EmptyObjective,
    RevisionOverflow,
}

impl fmt::Display for TaskStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTaskId => formatter.write_str("task id must not be empty"),
            Self::EmptyObjective => formatter.write_str("objective must not be empty"),
            Self::RevisionOverflow => formatter.write_str("task revision cannot be incremented"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError {
    pub from: TaskStatus,
    pub to: TaskStatus,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid task transition: {:?} -> {:?}",
            self.from, self.to
        )
    }
}

impl std::error::Error for TransitionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub id: TaskId,
    pub objective: String,
    pub constraints: Vec<String>,
    pub status: TaskStatus,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskState {
    pub id: TaskId,
    pub objective: String,
    pub constraints: Vec<String>,
    pub status: TaskStatus,
    pub revision: u64,
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

    pub fn transition(&mut self, next: TaskStatus) -> Result<(), TransitionError> {
        if !self.status.can_transition_to(next) {
            return Err(TransitionError {
                from: self.status,
                to: next,
            });
        }

        let revision = self.revision.checked_add(1).ok_or(TransitionError {
            from: self.status,
            to: next,
        })?;
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

    pub fn from_checkpoint(checkpoint: Checkpoint) -> Result<Self, TaskStateError> {
        if checkpoint.id.as_str().is_empty() {
            return Err(TaskStateError::EmptyTaskId);
        }
        if checkpoint.objective.is_empty() {
            return Err(TaskStateError::EmptyObjective);
        }
        Ok(Self {
            id: checkpoint.id,
            objective: checkpoint.objective,
            constraints: checkpoint.constraints,
            status: checkpoint.status,
            revision: checkpoint.revision,
        })
    }

    pub fn encode_snapshot(&self) -> Vec<u8> {
        encode_snapshot(self)
    }

    pub fn decode_snapshot(bytes: &[u8]) -> Result<Self, SnapshotError> {
        decode_snapshot(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidFormat,
    InvalidUtf8,
    UnsupportedVersion(u16),
    InvalidState(TaskStateError),
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
        }
    }
}

impl std::error::Error for SnapshotError {}

pub fn encode_snapshot(state: &TaskState) -> Vec<u8> {
    let checkpoint = state.checkpoint();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    put_string(&mut bytes, checkpoint.id.as_str());
    put_string(&mut bytes, &checkpoint.objective);
    bytes.extend_from_slice(&(checkpoint.constraints.len() as u32).to_le_bytes());
    for constraint in &checkpoint.constraints {
        put_string(&mut bytes, constraint);
    }
    bytes.push(status_to_byte(checkpoint.status));
    bytes.extend_from_slice(&checkpoint.revision.to_le_bytes());
    bytes
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<TaskState, SnapshotError> {
    let mut reader = Reader { bytes, position: 0 };
    if reader.take(SNAPSHOT_MAGIC.len()) != Some(SNAPSHOT_MAGIC) {
        return Err(SnapshotError::InvalidFormat);
    }
    let version = reader.u16().ok_or(SnapshotError::InvalidFormat)?;
    if version != SNAPSHOT_VERSION {
        return Err(SnapshotError::UnsupportedVersion(version));
    }

    let id = TaskId::new(reader.string()?).map_err(SnapshotError::InvalidState)?;
    let objective = reader.string()?;
    let constraint_count = reader.u32().ok_or(SnapshotError::InvalidFormat)? as usize;
    if constraint_count > reader.remaining() {
        return Err(SnapshotError::InvalidFormat);
    }
    let mut constraints = Vec::with_capacity(constraint_count);
    for _ in 0..constraint_count {
        constraints.push(reader.string()?);
    }
    let status = byte_to_status(reader.byte().ok_or(SnapshotError::InvalidFormat)?)
        .ok_or(SnapshotError::InvalidFormat)?;
    let revision = reader.u64().ok_or(SnapshotError::InvalidFormat)?;
    if !reader.is_empty() {
        return Err(SnapshotError::InvalidFormat);
    }

    TaskState::from_checkpoint(Checkpoint {
        id,
        objective,
        constraints,
        status,
        revision,
    })
    .map_err(SnapshotError::InvalidState)
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
        assert_eq!(state.status, TaskStatus::Running);
        assert_eq!(state.revision, 1);
    }

    #[test]
    fn invalid_transition_preserves_original_state() {
        let mut state = task();
        let original = state.clone();
        assert_eq!(
            state.transition(TaskStatus::Completed),
            Err(TransitionError {
                from: TaskStatus::Planned,
                to: TaskStatus::Completed
            })
        );
        assert_eq!(state, original);
    }

    #[test]
    fn blocked_task_can_resume() {
        let mut state = task();
        state.transition(TaskStatus::Running).unwrap();
        state.transition(TaskStatus::Blocked).unwrap();
        state.transition(TaskStatus::Running).unwrap();
        assert_eq!(state.revision, 3);
        assert_eq!(state.status, TaskStatus::Running);
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
        let restored = TaskState::from_checkpoint(state.checkpoint()).unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn snapshot_encode_decode_round_trip() {
        let mut state = task();
        state.transition(TaskStatus::Running).unwrap();
        state.transition(TaskStatus::Blocked).unwrap();
        let encoded = state.encode_snapshot();
        assert_eq!(encoded, state.encode_snapshot());
        assert_eq!(TaskState::decode_snapshot(&encoded).unwrap(), state);
    }

    #[test]
    fn corrupt_snapshot_fails() {
        let mut encoded = task().encode_snapshot();
        encoded.pop();
        assert!(matches!(
            TaskState::decode_snapshot(&encoded),
            Err(SnapshotError::InvalidFormat)
        ));
    }

    #[test]
    fn unsupported_snapshot_version_fails() {
        let mut encoded = task().encode_snapshot();
        encoded[SNAPSHOT_MAGIC.len()] = 2;
        assert_eq!(
            TaskState::decode_snapshot(&encoded),
            Err(SnapshotError::UnsupportedVersion(2))
        );
    }
}
