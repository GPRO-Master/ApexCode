//! Observation-only classification for interactive `exec_command` requests.
//!
//! This module deliberately has no policy authority. It receives the command
//! after Codex has resolved its shell and permissions, returns a bounded,
//! secret-free observation, and never changes the command or execution path.

use super::exec_classifier;

const MAX_CWD_BYTES: usize = 512;
const MAX_EXECUTABLE_BYTES: usize = 256;
const MAX_REQUEST_ID_BYTES: usize = 128;

/// Environment variable enabling bounded stderr diagnostics for dogfood runs.
pub const EXEC_OBSERVATION_DEBUG_ENV: &str = "APEXCODE_EXEC_OBSERVATION_DEBUG";

/// Aggregate metric for all observed `exec_command` requests.
pub const EXEC_OBSERVATION_TOTAL_METRIC: &str = "apex.exec_command.observation.total";

/// Aggregate metric tagged with the observation classification.
pub const EXEC_OBSERVATION_CLASSIFICATION_METRIC: &str =
    "apex.exec_command.observation.classification";

/// High-level command classification used for observation only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecClassification {
    /// A command with high-confidence read or test semantics.
    ReadOnly,
    /// A command that can alter files or directories.
    PotentialWrite,
    /// A command that communicates with a network or remote host.
    Network,
    /// A command that starts, stops, or controls another process.
    ProcessControl,
    /// A package-manager installation command.
    PackageInstall,
    /// A Git command that mutates repository state.
    GitMutation,
    /// A command requesting elevated privileges.
    PrivilegeEscalation,
    /// A command that cannot be classified with high confidence.
    Unknown,
}

impl ExecClassification {
    /// Return the stable aggregate telemetry label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::PotentialWrite => "potential_write",
            Self::Network => "network",
            Self::ProcessControl => "process_control",
            Self::PackageInstall => "package_install",
            Self::GitMutation => "git_mutation",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::Unknown => "unknown",
        }
    }
}

/// Confidence attached to an observation classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecConfidence {
    /// The bounded command shape matched a known semantic rule.
    High,
    /// The command shape or nested shell text was not safely understood.
    Unknown,
}

impl ExecConfidence {
    /// Return the stable diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Unknown => "unknown",
        }
    }
}

/// Execution representation observed at the process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecExecutionMode {
    /// Codex resolved the request into a shell executable and script.
    ShellWrapped,
    /// The representation was not recognized as a shell wrapper.
    Unknown,
}

impl ExecExecutionMode {
    /// Return the stable diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShellWrapped => "shell_wrapped",
            Self::Unknown => "unknown",
        }
    }
}

/// Shell family used to execute the observed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecShellKind {
    /// Windows command processor.
    Cmd,
    /// Windows PowerShell or PowerShell Core.
    PowerShell,
    /// Bash.
    Bash,
    /// POSIX sh.
    Sh,
    /// Zsh.
    Zsh,
    /// An unrecognized shell family.
    Unknown,
}

impl ExecShellKind {
    /// Parse the shell label supplied by Codex.
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "cmd" => Self::Cmd,
            "powershell" | "pwsh" => Self::PowerShell,
            "bash" => Self::Bash,
            "sh" => Self::Sh,
            "zsh" => Self::Zsh,
            _ => Self::Unknown,
        }
    }

    /// Return the stable diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cmd => "cmd",
            Self::PowerShell => "powershell",
            Self::Bash => "bash",
            Self::Sh => "sh",
            Self::Zsh => "zsh",
            Self::Unknown => "unknown",
        }
    }
}

/// A bounded, secret-free observation of one interactive command.
///
/// The observation is non-authoritative. Callers must not use it to alter the
/// command, cwd, approval state, permissions, or execution result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecObservation {
    request_id: String,
    executable: String,
    args: Vec<String>,
    cwd: String,
    execution_mode: ExecExecutionMode,
    shell_kind: ExecShellKind,
    classification: ExecClassification,
    confidence: ExecConfidence,
    reasons: Vec<String>,
}

impl ExecObservation {
    /// Return the bounded request identity.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Return the sanitized executable name.
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Return sanitized, bounded arguments. No environment or stdin is stored.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Return the bounded working directory.
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Return the observed execution representation.
    pub const fn execution_mode(&self) -> ExecExecutionMode {
        self.execution_mode
    }

    /// Return the observed shell family.
    pub const fn shell_kind(&self) -> ExecShellKind {
        self.shell_kind
    }

    /// Return the observation classification.
    pub const fn classification(&self) -> ExecClassification {
        self.classification
    }

    /// Return the classification confidence.
    pub const fn confidence(&self) -> ExecConfidence {
        self.confidence
    }

    /// Return bounded reasons for the classification.
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    /// Return one sanitized line suitable for explicit dogfood stderr output.
    pub fn diagnostic_line(&self) -> String {
        format!(
            "request_id={} executable={} args={:?} cwd={} mode={} shell={} classification={} confidence={} reasons={:?}",
            self.request_id,
            self.executable,
            self.args,
            self.cwd,
            self.execution_mode.as_str(),
            self.shell_kind.as_str(),
            self.classification.as_str(),
            self.confidence.as_str(),
            self.reasons,
        )
    }
}

/// Observe a command at the resolved pre-execution boundary.
///
/// This function cannot fail and has no side effects. It does not parse the
/// full shell language; unsupported or compound syntax becomes `Unknown`.
pub fn observe_exec_command(
    request_id: impl Into<String>,
    command: &[String],
    cwd: impl AsRef<str>,
    shell_name: &str,
) -> ExecObservation {
    let shell_kind = ExecShellKind::from_name(shell_name);
    let request_id = exec_classifier::sanitize_text(&request_id.into(), MAX_REQUEST_ID_BYTES);
    let cwd = exec_classifier::sanitize_text(cwd.as_ref(), MAX_CWD_BYTES);
    let executable = command
        .first()
        .map(|value| exec_classifier::sanitize_text(value, MAX_EXECUTABLE_BYTES))
        .unwrap_or_default();
    let args = exec_classifier::sanitize_args(command.get(1..).unwrap_or(&[]));
    let (execution_mode, script) = exec_classifier::shell_script(command, shell_kind);
    let (classification, confidence, reasons) =
        script.map(exec_classifier::classify_script).unwrap_or((
            ExecClassification::Unknown,
            ExecConfidence::Unknown,
            vec!["unrecognized shell wrapper".to_string()],
        ));

    ExecObservation {
        request_id,
        executable,
        args,
        cwd,
        execution_mode,
        shell_kind,
        classification,
        confidence,
        reasons,
    }
}

/// Return whether explicit stderr diagnostics were requested for dogfood.
pub fn diagnostics_enabled() -> bool {
    std::env::var_os(EXEC_OBSERVATION_DEBUG_ENV)
        .map(|value| value == "1" || value.to_string_lossy().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
#[path = "exec_observer_tests.rs"]
mod tests;
