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
    if normalized.contains(['\r', '\n']) {
        return unknown("line-separated shell syntax requires deeper parsing");
    }
    if normalized.contains("<<") || normalized.contains("@\"") || normalized.contains("@'") {
        return unknown("here-document syntax requires deeper parsing");
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
        "cargo" => tokens.get(1) == Some(&"fmt") && tokens.contains(&"--check"),
        _ => false,
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn contains_unquoted_shell_operator(value: &str) -> bool {
    if value.contains("$(") || value.contains(char::from(96)) {
        return true;
    }
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
    let mut redact_next = false;
    let mut authorization_values_remaining: usize = 0;
    let mut sanitized_arguments = Vec::new();
    for argument in arguments.iter().take(MAX_ARGUMENT_COUNT) {
        if total_bytes >= MAX_TOTAL_ARGUMENT_BYTES {
            break;
        }
        let authorization_header = is_authorization_header_name(argument);
        let sanitized = if redact_next
            || authorization_values_remaining > 0
            || is_sensitive_flag(argument)
            || contains_sensitive_assignment(argument)
            || contains_sensitive_flag_value(argument)
            || contains_authorization_value(&argument.to_ascii_lowercase())
            || contains_url_credentials(argument)
            || contains_private_key_marker(&argument.to_ascii_lowercase())
            || contains_opaque_secret(argument)
        {
            "<redacted-secret>".to_string()
        } else {
            sanitize_text(argument, MAX_ARGUMENT_BYTES)
        };
        let remaining_bytes = MAX_TOTAL_ARGUMENT_BYTES - total_bytes;
        let sanitized = bounded_text(sanitized, remaining_bytes);
        total_bytes += sanitized.len();
        sanitized_arguments.push(sanitized);
        authorization_values_remaining = authorization_values_remaining.saturating_sub(1);
        if authorization_header {
            authorization_values_remaining = 2;
        }
        redact_next = expects_sensitive_value(argument);
    }
    sanitized_arguments
}

pub(super) fn sanitize_text(argument: &str, limit: usize) -> String {
    let lower = argument.to_ascii_lowercase();
    let sanitized = if contains_sensitive_assignment(argument)
        || contains_sensitive_flag_value(argument)
        || contains_authorization_value(&lower)
        || contains_url_credentials(argument)
        || contains_private_key_marker(&lower)
        || contains_opaque_secret(argument)
    {
        "<redacted-secret>".to_string()
    } else {
        let bounded_argument = argument.chars().take(limit).collect::<String>();
        bounded_argument.escape_debug().to_string()
    };
    bounded_text(sanitized, limit)
}

fn contains_sensitive_flag_value(argument: &str) -> bool {
    let tokens = argument.split_whitespace().collect::<Vec<_>>();
    tokens
        .windows(2)
        .any(|window| expects_sensitive_value(window[0]))
}

fn is_sensitive_flag(argument: &str) -> bool {
    let argument = argument
        .trim_matches(['\'', '"', '(', ')', '[', ']', ',', ';'])
        .trim_start_matches('-');
    !argument.contains('=') && is_sensitive_key(argument)
}

fn expects_sensitive_value(argument: &str) -> bool {
    let normalized = argument
        .trim_matches(['\'', '"', '(', ')', '[', ']', ',', ';'])
        .to_ascii_lowercase();
    matches!(normalized.as_str(), "-u" | "--user" | "-p" | "--password")
        || is_sensitive_flag(argument)
}

fn contains_sensitive_assignment(argument: &str) -> bool {
    argument.split_whitespace().any(|token| {
        let Some((key, _)) = token.split_once('=') else {
            return false;
        };
        let key = key
            .trim_matches(['\'', '"', '(', ')', '[', ']', ',', ';'])
            .trim_start_matches('-')
            .to_ascii_lowercase();
        is_sensitive_key(&key)
    })
}

fn is_sensitive_key(key: &str) -> bool {
    const SENSITIVE_KEYS: &[&str] = &[
        "password",
        "pass",
        "passwd",
        "db_pass",
        "db_password",
        "token",
        "api_key",
        "apikey",
        "secret",
        "client_secret",
        "access_token",
        "refresh_token",
        "auth_token",
        "database_url",
        "redis_url",
    ];
    let key = key
        .trim_matches(['\'', '"', '(', ')', '[', ']', ',', ';'])
        .trim_start_matches('-')
        .strip_prefix("$env:")
        .unwrap_or(key)
        .to_ascii_lowercase();
    is_sensitive_key_with_list(&key, SENSITIVE_KEYS)
        || key.ends_with("_key")
        || key.ends_with("_token")
        || key.ends_with("_secret")
        || key.ends_with("_password")
}

fn is_sensitive_key_with_list(key: &str, sensitive_keys: &[&str]) -> bool {
    sensitive_keys.contains(&key)
}

fn contains_authorization_value(lower: &str) -> bool {
    lower.contains("authorization:") || lower.contains("bearer ")
}

fn is_authorization_header_name(argument: &str) -> bool {
    matches!(
        argument
            .trim_matches(['\'', '"', '(', ')', '[', ']', ',', ';'])
            .to_ascii_lowercase()
            .as_str(),
        "authorization" | "authorization:"
    )
}

fn contains_url_credentials(argument: &str) -> bool {
    argument.split_whitespace().any(|token| {
        let token = token
            .trim_matches(['\'', '"', '(', ')', '[', ']', ',', ';'])
            .strip_prefix("--url=")
            .unwrap_or(token);
        let Some((scheme, remainder)) = token.split_once("://") else {
            return false;
        };
        if scheme.is_empty()
            || !scheme.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            })
        {
            return false;
        }
        let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
        authority
            .split_once('@')
            .is_some_and(|(userinfo, _)| userinfo.contains(':'))
    })
}

fn contains_private_key_marker(lower: &str) -> bool {
    lower.contains("-----begin private key-----")
        || lower.contains("-----begin rsa private key-----")
        || lower.contains("-----begin openssh private key-----")
}

fn contains_opaque_secret(argument: &str) -> bool {
    argument.split_whitespace().any(|token| {
        let token = token.trim_matches(['\'', '"', '(', ')', '[', ']', ',', ';']);
        is_opaque_secret_token(token)
    })
}

fn is_opaque_secret_token(token: &str) -> bool {
    let known_prefix = [
        "sk-",
        "pk-",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "akia",
    ];
    if known_prefix
        .iter()
        .any(|prefix| token.to_ascii_lowercase().starts_with(prefix))
    {
        return token.len() >= 16;
    }

    if token.len() < 24 || token.contains(['/', '\\', '.', '=']) {
        return false;
    }

    let has_lower = token
        .chars()
        .any(|character| character.is_ascii_lowercase());
    let has_upper = token
        .chars()
        .any(|character| character.is_ascii_uppercase());
    let has_digit = token.chars().any(|character| character.is_ascii_digit());
    let has_symbol = token
        .chars()
        .any(|character| matches!(character, '-' | '_'));
    let distinct = token
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count()
        >= 3
        && distinct >= 12
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
