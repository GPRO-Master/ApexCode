use super::ExecClassification;
use super::ExecConfidence;
use super::ExecExecutionMode;
use super::ExecShellKind;

const MAX_ARGUMENT_BYTES: usize = 512;
const MAX_ARGUMENT_COUNT: usize = 64;
const MAX_TOTAL_ARGUMENT_BYTES: usize = 4096;

pub(super) fn shell_script(
    command: &[String],
    shell_kind: ExecShellKind,
) -> (ExecExecutionMode, Option<&str>) {
    let script_index = match shell_kind {
        ExecShellKind::Cmd => (command.get(1).map(String::as_str), 2),
        ExecShellKind::PowerShell => {
            let index = command
                .iter()
                .position(|argument| argument.eq_ignore_ascii_case("-command"));
            (
                index.map(|_| "-Command"),
                index.map_or(usize::MAX, |index| index + 1),
            )
        }
        ExecShellKind::Bash | ExecShellKind::Sh | ExecShellKind::Zsh => {
            let index = command
                .iter()
                .position(|argument| argument == "-c" || argument == "-lc");
            (
                index.map(|_| "-c"),
                index.map_or(usize::MAX, |index| index + 1),
            )
        }
        ExecShellKind::Unknown => (None, usize::MAX),
    };
    let valid_wrapper = match shell_kind {
        ExecShellKind::Cmd => script_index
            .0
            .is_some_and(|argument| argument.eq_ignore_ascii_case("/c")),
        ExecShellKind::PowerShell
        | ExecShellKind::Bash
        | ExecShellKind::Sh
        | ExecShellKind::Zsh => script_index.0.is_some(),
        ExecShellKind::Unknown => false,
    };
    if valid_wrapper {
        (
            ExecExecutionMode::ShellWrapped,
            command.get(script_index.1).map(String::as_str),
        )
    } else {
        (ExecExecutionMode::Unknown, None)
    }
}

pub(super) fn classify_script(script: &str) -> (ExecClassification, ExecConfidence, Vec<String>) {
    let normalized = script.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return unknown("empty shell script");
    }

    if contains_any(
        &normalized,
        &[
            "sudo",
            "runas",
            "-verb runas",
            "invoke-command -computername",
        ],
    ) {
        return high(ExecClassification::PrivilegeEscalation, "privilege marker");
    }
    if contains_any(
        &normalized,
        &[
            "curl",
            "wget",
            "invoke-webrequest",
            "invoke-restmethod",
            "ssh ",
            "scp ",
        ],
    ) {
        return high(ExecClassification::Network, "network command marker");
    }
    if contains_any(
        &normalized,
        &[
            "npm install",
            "composer install",
            "cargo install",
            "pip install",
            "brew install",
        ],
    ) {
        return high(
            ExecClassification::PackageInstall,
            "package installation marker",
        );
    }
    if contains_any(
        &normalized,
        &[
            "git reset",
            "git clean",
            "git checkout",
            "git commit",
            "git push",
            "git pull",
            "git merge",
            "git rebase",
            "git add",
            "git rm",
        ],
    ) {
        return high(ExecClassification::GitMutation, "git mutation marker");
    }
    if contains_any(
        &normalized,
        &[
            "taskkill",
            "stop-process",
            "start-process",
            "pkill",
            "kill ",
            "systemctl",
            "shutdown",
        ],
    ) {
        return high(ExecClassification::ProcessControl, "process-control marker");
    }
    if contains_any(
        &normalized,
        &[
            "rm -",
            "remove-item",
            "del ",
            "erase ",
            "rmdir ",
            "new-item",
            "set-content",
            "out-file",
            "tee ",
            "copy ",
            "cp ",
            "move ",
            "mv ",
            "rename ",
            "touch ",
            "mkdir ",
        ],
    ) || contains_unquoted_operator(&normalized, b'>')
        || contains_unquoted_operator(&normalized, b'<')
    {
        return high(
            ExecClassification::PotentialWrite,
            "write or redirection marker",
        );
    }

    if contains_unquoted_shell_operator(&normalized) {
        return unknown("compound shell syntax requires deeper parsing");
    }
    if is_known_read_only(&normalized) {
        return high(
            ExecClassification::ReadOnly,
            "known read-only or test command",
        );
    }
    unknown("command not in the high-confidence observation set")
}

fn is_known_read_only(command: &str) -> bool {
    let tokens = command.split_whitespace().collect::<Vec<_>>();
    let Some(first) = tokens.first().copied() else {
        return false;
    };
    let executable = first
        .trim_matches(['&', '\'', '"', '`'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(first)
        .trim_end_matches(".exe");
    match executable {
        "rg" | "grep" | "find" | "fd" | "ls" | "dir" | "cat" | "type" | "pwd" | "get-childitem"
        | "get-content" => true,
        "git" => tokens
            .get(1)
            .is_some_and(|token| matches!(*token, "status" | "diff" | "log" | "show")),
        "cargo" => {
            matches!(tokens.get(1), Some(&"test"))
                || (tokens.get(1) == Some(&"fmt") && tokens.contains(&"--check"))
        }
        "composer" => tokens.get(1) == Some(&"test"),
        "php" => tokens.get(1) == Some(&"artisan") && tokens.get(2) == Some(&"test"),
        "npm" => tokens.get(1) == Some(&"test"),
        _ => false,
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn contains_unquoted_shell_operator(value: &str) -> bool {
    b"|;&()`"
        .iter()
        .copied()
        .any(|operator| contains_unquoted_operator(value, operator))
}

fn contains_unquoted_operator(value: &str, operator: u8) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for byte in value.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        match quote {
            Some(current) if byte == current => quote = None,
            Some(_) => {}
            None if byte == b'\'' || byte == b'"' => quote = Some(byte),
            None if byte == operator => return true,
            None => {}
        }
    }
    false
}

pub(super) fn sanitize_args(arguments: &[String]) -> Vec<String> {
    let mut total_bytes = 0;
    arguments
        .iter()
        .take(MAX_ARGUMENT_COUNT)
        .map(|argument| {
            if total_bytes >= MAX_TOTAL_ARGUMENT_BYTES {
                return "<truncated>".to_string();
            }
            let sanitized = sanitize_argument(argument);
            total_bytes += sanitized.len();
            bounded_text(sanitized, MAX_ARGUMENT_BYTES)
        })
        .collect()
}

fn sanitize_argument(argument: &str) -> String {
    let lower = argument.to_ascii_lowercase();
    if lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("bearer ")
        || lower.contains("authorization:")
        || lower.contains("cookie:")
    {
        return "<redacted-secret>".to_string();
    }
    bounded_text(argument.to_string(), MAX_ARGUMENT_BYTES)
}

pub(super) fn bounded_text(value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let end = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= limit)
        .last()
        .unwrap_or(0);
    value[..end].to_string()
}

fn high(
    classification: ExecClassification,
    reason: &str,
) -> (ExecClassification, ExecConfidence, Vec<String>) {
    (
        classification,
        ExecConfidence::High,
        vec![reason.to_string()],
    )
}

fn unknown(reason: &str) -> (ExecClassification, ExecConfidence, Vec<String>) {
    (
        ExecClassification::Unknown,
        ExecConfidence::Unknown,
        vec![reason.to_string()],
    )
}
