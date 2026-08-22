// Modified for ApexCode by GPRO-Master.
// Licensed under Apache-2.0. See the repository LICENSE file.

use apex_task_state::{
    SnapshotAuthenticator, SnapshotCandidate, SnapshotError, TaskState, VerifiedCheckpoint,
};
use std::{
    fmt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    EmptyTaskId,
    EmptySourceRevision,
    EmptyDisplayLabel,
    EmptyApprovedCheck,
    EmptyProgram,
    InvalidSnapshotKey,
    Snapshot(SnapshotError),
    RepositoryNotFound,
    NotGitRepository,
    GitCommandFailed(String),
    HeadMismatch { expected: String, actual: String },
    DirtyWorktree,
    SourceMismatch,
    SourceNotCurrent,
    ExecutionFailed(String),
    ExecutionNotSuccessful,
    AuthorityMismatch,
    Timeout,
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTaskId => formatter.write_str("trust task id must not be empty"),
            Self::EmptySourceRevision => {
                formatter.write_str("trust source revision must not be empty")
            }
            Self::EmptyDisplayLabel => {
                formatter.write_str("execution display label must not be empty")
            }
            Self::EmptyApprovedCheck => formatter.write_str("approved check must not be empty"),
            Self::EmptyProgram => formatter.write_str("trusted command program must not be empty"),
            Self::InvalidSnapshotKey => formatter.write_str("snapshot key is invalid"),
            Self::Snapshot(error) => write!(formatter, "snapshot trust failed: {error}"),
            Self::RepositoryNotFound => formatter.write_str("repository root does not exist"),
            Self::NotGitRepository => formatter.write_str("path is not a Git repository"),
            Self::GitCommandFailed(error) => write!(formatter, "Git command failed: {error}"),
            Self::HeadMismatch { expected, actual } => {
                write!(
                    formatter,
                    "Git HEAD mismatch: expected {expected}, got {actual}"
                )
            }
            Self::DirtyWorktree => formatter.write_str("Git worktree is dirty"),
            Self::SourceMismatch => formatter.write_str("source does not match task binding"),
            Self::SourceNotCurrent => formatter.write_str("verified source is no longer current"),
            Self::ExecutionFailed(error) => {
                write!(formatter, "trusted command failed to start: {error}")
            }
            Self::ExecutionNotSuccessful => {
                formatter.write_str("execution did not produce a successful result")
            }
            Self::AuthorityMismatch => {
                formatter.write_str("execution does not match runtime authority")
            }
            Self::Timeout => formatter.write_str("trusted command timed out"),
        }
    }
}

impl std::error::Error for TrustError {}

pub struct CheckpointAuthenticator {
    inner: SnapshotAuthenticator,
}

impl fmt::Debug for CheckpointAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointAuthenticator(<redacted>)")
    }
}

impl CheckpointAuthenticator {
    pub fn from_runtime_key(key: &[u8]) -> Result<Self, TrustError> {
        Ok(Self {
            inner: SnapshotAuthenticator::from_runtime_key(key)
                .map_err(|_| TrustError::InvalidSnapshotKey)?,
        })
    }

    pub fn authenticate(
        &self,
        candidate: &SnapshotCandidate,
    ) -> Result<VerifiedCheckpoint, TrustError> {
        self.inner
            .authenticate(candidate)
            .map_err(TrustError::Snapshot)
    }

    pub fn sign(&self, state: &TaskState) -> Vec<u8> {
        state.encode_authenticated_snapshot(&self.inner)
    }

    pub fn restore(&self, candidate: &SnapshotCandidate) -> Result<TaskState, TrustError> {
        TaskState::from_verified_checkpoint(self.authenticate(candidate)?)
            .map_err(|error| TrustError::Snapshot(SnapshotError::InvalidState(error)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSource {
    repository_root: PathBuf,
    task_id: String,
    task_revision: u64,
    source_revision: String,
}

impl VerifiedSource {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub const fn task_revision(&self) -> u64 {
        self.task_revision
    }

    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    pub fn is_current(&self) -> bool {
        GitSourceVerifier::new()
            .verify_repository(
                &self.repository_root,
                &self.task_id,
                self.task_revision,
                &self.source_revision,
            )
            .is_ok()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GitSourceVerifier;

impl GitSourceVerifier {
    pub const fn new() -> Self {
        Self
    }

    pub fn verify_repository(
        &self,
        repository_root: impl AsRef<Path>,
        task_id: impl Into<String>,
        task_revision: u64,
        requested_sha: impl Into<String>,
    ) -> Result<VerifiedSource, TrustError> {
        let repository_root = repository_root.as_ref();
        if !repository_root.exists() {
            return Err(TrustError::RepositoryNotFound);
        }
        let task_id = task_id.into();
        if task_id.is_empty() {
            return Err(TrustError::EmptyTaskId);
        }
        let requested_sha = requested_sha.into();
        if requested_sha.is_empty() {
            return Err(TrustError::EmptySourceRevision);
        }
        let canonical_root =
            std::fs::canonicalize(repository_root).map_err(|_| TrustError::RepositoryNotFound)?;
        let git_root = self.git(repository_root, &["rev-parse", "--show-toplevel"])?;
        let git_root =
            std::fs::canonicalize(git_root.trim()).map_err(|_| TrustError::NotGitRepository)?;
        if git_root != canonical_root {
            return Err(TrustError::NotGitRepository);
        }
        let actual_sha = self.git(repository_root, &["rev-parse", "HEAD"])?;
        let actual_sha = actual_sha.trim().to_owned();
        if actual_sha != requested_sha {
            return Err(TrustError::HeadMismatch {
                expected: requested_sha,
                actual: actual_sha,
            });
        }
        if !self
            .git(
                repository_root,
                &["status", "--porcelain", "--untracked-files=all"],
            )?
            .trim()
            .is_empty()
        {
            return Err(TrustError::DirtyWorktree);
        }
        Ok(VerifiedSource {
            repository_root: canonical_root,
            task_id,
            task_revision,
            source_revision: requested_sha,
        })
    }

    fn git(&self, repository_root: &Path, args: &[&str]) -> Result<String, TrustError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository_root)
            .args(args)
            .output()
            .map_err(|error| TrustError::GitCommandFailed(error.to_string()))?;
        if !output.status.success() {
            return if args == ["rev-parse", "--show-toplevel"] {
                Err(TrustError::NotGitRepository)
            } else {
                Err(TrustError::GitCommandFailed(
                    String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                ))
            };
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    Pass,
    Fail,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorKind {
    LocalCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedExecution {
    executor: ExecutorKind,
    repository_root: PathBuf,
    task_id: String,
    task_revision: u64,
    source_revision: String,
    program: PathBuf,
    args: Vec<String>,
    display_label: String,
    outcome: ExecutionOutcome,
    exit_code: Option<i32>,
}

impl ObservedExecution {
    pub const fn executor(&self) -> ExecutorKind {
        self.executor
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository_root
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

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn display_label(&self) -> &str {
        &self.display_label
    }

    pub const fn outcome(&self) -> ExecutionOutcome {
        self.outcome
    }

    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedExecutionReceipt {
    executor: ExecutorKind,
    repository_root: PathBuf,
    task_id: String,
    task_revision: u64,
    source_revision: String,
    check_identity: String,
    outcome: ExecutionOutcome,
    exit_code: Option<i32>,
}

impl TrustedExecutionReceipt {
    pub const fn executor(&self) -> ExecutorKind {
        self.executor
    }

    pub fn repository_root(&self) -> &Path {
        &self.repository_root
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

    pub fn check_identity(&self) -> &str {
        &self.check_identity
    }

    pub const fn outcome(&self) -> ExecutionOutcome {
        self.outcome
    }

    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

#[derive(Debug)]
pub struct RuntimeExecutionAuthority {
    source: VerifiedSource,
    approved_check: String,
}

impl RuntimeExecutionAuthority {
    #[cfg(test)]
    fn test_fixture(
        source: &VerifiedSource,
        approved_check: impl Into<String>,
    ) -> Result<Self, TrustError> {
        let approved_check = approved_check.into();
        if approved_check.is_empty() {
            return Err(TrustError::EmptyApprovedCheck);
        }
        Ok(Self {
            source: source.clone(),
            approved_check,
        })
    }

    pub fn issue(
        &self,
        observed: &ObservedExecution,
    ) -> Result<TrustedExecutionReceipt, TrustError> {
        if observed.repository_root() != self.source.repository_root()
            || observed.task_id() != self.source.task_id()
            || observed.task_revision() != self.source.task_revision()
            || observed.source_revision() != self.source.source_revision()
        {
            return Err(TrustError::AuthorityMismatch);
        }
        if !self.source.is_current() {
            return Err(TrustError::SourceNotCurrent);
        }
        if observed.outcome() != ExecutionOutcome::Pass {
            return Err(TrustError::ExecutionNotSuccessful);
        }
        Ok(TrustedExecutionReceipt {
            executor: observed.executor(),
            repository_root: self.source.repository_root().to_owned(),
            task_id: self.source.task_id().to_owned(),
            task_revision: self.source.task_revision(),
            source_revision: self.source.source_revision().to_owned(),
            check_identity: self.approved_check.clone(),
            outcome: observed.outcome(),
            exit_code: observed.exit_code(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LocalCommandRunner {
    program: PathBuf,
    args: Vec<String>,
    display_label: String,
    timeout: Duration,
}

impl LocalCommandRunner {
    pub fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<String>>,
        display_label: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, TrustError> {
        let program = program.into();
        if program.as_os_str().is_empty() {
            return Err(TrustError::EmptyProgram);
        }
        let display_label = display_label.into();
        if display_label.is_empty() {
            return Err(TrustError::EmptyDisplayLabel);
        }
        if timeout.is_zero() {
            return Err(TrustError::Timeout);
        }
        Ok(Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
            display_label,
            timeout,
        })
    }

    pub fn execute(
        &self,
        source: &VerifiedSource,
        task_id: &str,
        task_revision: u64,
    ) -> Result<ObservedExecution, TrustError> {
        if source.task_id() != task_id || source.task_revision() != task_revision {
            return Err(TrustError::SourceMismatch);
        }
        if !source.is_current() {
            return Err(TrustError::SourceNotCurrent);
        }
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .current_dir(source.repository_root())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| TrustError::ExecutionFailed(error.to_string()))?;
        let deadline = Instant::now() + self.timeout;
        let (outcome, exit_code) = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| TrustError::ExecutionFailed(error.to_string()))?
            {
                let outcome = if status.success() {
                    ExecutionOutcome::Pass
                } else {
                    ExecutionOutcome::Fail
                };
                break (outcome, status.code());
            }
            if Instant::now() >= deadline {
                child
                    .kill()
                    .map_err(|error| TrustError::ExecutionFailed(error.to_string()))?;
                let _ = child.wait();
                break (ExecutionOutcome::Unavailable, None);
            }
            thread::sleep(Duration::from_millis(10));
        };
        Ok(ObservedExecution {
            executor: ExecutorKind::LocalCommand,
            repository_root: source.repository_root().to_owned(),
            task_id: task_id.to_owned(),
            task_revision,
            source_revision: source.source_revision().to_owned(),
            program: self.program.clone(),
            args: self.args.clone(),
            display_label: self.display_label.clone(),
            outcome,
            exit_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::SystemTime};

    fn fixture_repo() -> (PathBuf, String) {
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("apex-trust-{suffix}"));
        fs::create_dir_all(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["config", "user.email", "trust@example.invalid"]);
        run_git(&root, &["config", "user.name", "Apex Trust"]);
        fs::write(root.join("fixture.txt"), "one").unwrap();
        run_git(&root, &["add", "."]);
        run_git(&root, &["commit", "-qm", "fixture"]);
        let head = run_git(&root, &["rev-parse", "HEAD"]);
        (root, head)
    }

    fn run_git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    #[test]
    fn git_head_and_clean_worktree_verify() {
        let (root, head) = fixture_repo();
        let source = GitSourceVerifier::new()
            .verify_repository(&root, "task-1", 7, head)
            .unwrap();
        assert!(source.is_current());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_sha_and_non_repository_fail() {
        let (root, head) = fixture_repo();
        assert!(matches!(
            GitSourceVerifier::new().verify_repository(&root, "task-1", 7, format!("{head}x")),
            Err(TrustError::HeadMismatch { .. })
        ));
        assert_eq!(
            GitSourceVerifier::new().verify_repository(root.join("missing"), "task-1", 7, head),
            Err(TrustError::RepositoryNotFound)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dirty_worktree_and_changed_head_fail() {
        let (root, head) = fixture_repo();
        fs::write(root.join("fixture.txt"), "dirty").unwrap();
        assert_eq!(
            GitSourceVerifier::new().verify_repository(&root, "task-1", 7, &head),
            Err(TrustError::DirtyWorktree)
        );
        run_git(&root, &["add", "."]);
        run_git(&root, &["commit", "-qm", "changed"]);
        assert!(matches!(
            GitSourceVerifier::new().verify_repository(&root, "task-1", 7, &head),
            Err(TrustError::HeadMismatch { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_and_failed_commands_produce_observations() {
        let (root, head) = fixture_repo();
        let source = GitSourceVerifier::new()
            .verify_repository(&root, "task-1", 7, &head)
            .unwrap();
        let success = LocalCommandRunner::new(
            "rustc",
            ["--version"],
            "rustc-version",
            Duration::from_secs(5),
        )
        .unwrap()
        .execute(&source, "task-1", 7)
        .unwrap();
        assert_eq!(success.outcome(), ExecutionOutcome::Pass);
        assert_eq!(success.source_revision(), head);
        assert_eq!(success.display_label(), "rustc-version");
        let authority = RuntimeExecutionAuthority::test_fixture(&source, "approved-rustc").unwrap();
        let receipt = authority.issue(&success).unwrap();
        assert_eq!(receipt.check_identity(), "approved-rustc");
        assert_eq!(receipt.repository_root(), source.repository_root());

        let failure = LocalCommandRunner::new(
            "rustc",
            ["--not-a-real-option"],
            "rustc-failure",
            Duration::from_secs(5),
        )
        .unwrap()
        .execute(&source, "task-1", 7)
        .unwrap();
        assert_eq!(failure.outcome(), ExecutionOutcome::Fail);
        assert_eq!(
            authority.issue(&failure),
            Err(TrustError::ExecutionNotSuccessful)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn caller_selected_identity_is_observation_only() {
        let (root, head) = fixture_repo();
        let source = GitSourceVerifier::new()
            .verify_repository(&root, "task-1", 7, &head)
            .unwrap();
        let observed = LocalCommandRunner::new(
            "cmd.exe",
            ["/C", "exit", "0"],
            "github-actions",
            Duration::from_secs(5),
        )
        .unwrap()
        .execute(&source, "task-1", 7)
        .unwrap();
        assert_eq!(observed.outcome(), ExecutionOutcome::Pass);
        assert_eq!(observed.display_label(), "github-actions");

        let authority = RuntimeExecutionAuthority::test_fixture(&source, "approved-ci").unwrap();
        let receipt = authority.issue(&observed).unwrap();
        assert_eq!(receipt.check_identity(), "approved-ci");
        assert_ne!(receipt.check_identity(), observed.display_label());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authority_rejects_stale_or_mismatched_observations() {
        let (root, head) = fixture_repo();
        let source = GitSourceVerifier::new()
            .verify_repository(&root, "task-1", 7, &head)
            .unwrap();
        let authority = RuntimeExecutionAuthority::test_fixture(&source, "approved-test").unwrap();
        let other_source = GitSourceVerifier::new()
            .verify_repository(&root, "task-2", 7, &head)
            .unwrap();
        let observed = LocalCommandRunner::new(
            "rustc",
            ["--version"],
            "display-only",
            Duration::from_secs(5),
        )
        .unwrap()
        .execute(&other_source, "task-2", 7)
        .unwrap();
        assert_eq!(
            authority.issue(&observed),
            Err(TrustError::AuthorityMismatch)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
