use super::*;

fn command(shell: &str, script: &str) -> Vec<String> {
    match ExecShellKind::from_name(shell) {
        ExecShellKind::Cmd => vec!["cmd.exe".into(), "/c".into(), script.into()],
        ExecShellKind::PowerShell => vec![
            "pwsh.exe".into(),
            "-NoProfile".into(),
            "-Command".into(),
            script.into(),
        ],
        ExecShellKind::Bash | ExecShellKind::Sh | ExecShellKind::Zsh => {
            vec![shell.into(), "-c".into(), script.into()]
        }
        ExecShellKind::Unknown => vec!["unknown".into(), script.into()],
    }
}

fn classify(shell: &str, script: &str) -> ExecClassification {
    observe_exec_command("call-1", &command(shell, script), "/repo", shell).classification()
}

#[test]
fn dogfood_matrix_classifies_known_commands() {
    for (command, expected) in [
        ("rg --files", ExecClassification::ReadOnly),
        ("git status", ExecClassification::ReadOnly),
        ("git diff --check", ExecClassification::ReadOnly),
        ("cargo test", ExecClassification::Unknown),
        ("cargo fmt -- --check", ExecClassification::ReadOnly),
        ("composer test", ExecClassification::Unknown),
        ("php artisan test", ExecClassification::Unknown),
        ("npm test", ExecClassification::Unknown),
        ("git reset --hard", ExecClassification::GitMutation),
        ("git clean -fd", ExecClassification::GitMutation),
        ("rm -rf build", ExecClassification::PotentialWrite),
        (
            "Remove-Item -Recurse build",
            ExecClassification::PotentialWrite,
        ),
        ("del output.txt", ExecClassification::PotentialWrite),
        ("curl https://example.test", ExecClassification::Network),
        ("ssh host", ExecClassification::Network),
        ("npm install", ExecClassification::PackageInstall),
        ("composer install", ExecClassification::PackageInstall),
        ("cargo install ripgrep", ExecClassification::PackageInstall),
        ("sudo cargo test", ExecClassification::PrivilegeEscalation),
        (
            "Stop-Process -Name codex",
            ExecClassification::ProcessControl,
        ),
    ] {
        assert_eq!(classify("bash", command), expected, "{command}");
    }
}

#[test]
fn shell_wrappers_require_nested_command_analysis() {
    assert_eq!(
        classify("powershell", "Get-ChildItem"),
        ExecClassification::ReadOnly
    );
    assert_eq!(
        classify("powershell", "Remove-Item -Recurse build"),
        ExecClassification::PotentialWrite
    );
    assert_eq!(classify("cmd", "dir"), ExecClassification::ReadOnly);
    assert_eq!(
        classify("cmd", "del output.txt"),
        ExecClassification::PotentialWrite
    );
    assert_eq!(classify("bash", "ls"), ExecClassification::ReadOnly);
    assert_eq!(
        classify("bash", "rm -rf build"),
        ExecClassification::PotentialWrite
    );
}

#[test]
fn compound_commands_and_unknown_wrappers_are_not_read_only() {
    assert_eq!(
        classify("bash", "rg foo > result.txt"),
        ExecClassification::PotentialWrite
    );
    assert_eq!(
        classify("bash", "rg foo | head"),
        ExecClassification::Unknown
    );
    assert_eq!(
        classify("bash", "powershell -Command ls"),
        ExecClassification::Unknown
    );
    assert_eq!(
        classify("unknown", "rg --files"),
        ExecClassification::Unknown
    );
}

#[test]
fn observations_are_bounded_and_redact_secret_like_arguments() {
    let command = vec![
        "bash".to_string(),
        "-c".to_string(),
        "curl -H 'Authorization: Bearer do-not-record'".to_string(),
        "--token=do-not-record".to_string(),
        "x".repeat(512 + 20),
    ];
    let observation = observe_exec_command("request-1", &command, "/repo", "bash");
    assert_eq!(observation.args()[1], "<redacted-secret>");
    assert_eq!(observation.args()[2], "<redacted-secret>");
    assert!(observation.args()[3].len() <= 512);
    assert!(observation.args().iter().map(String::len).sum::<usize>() <= 4096);
    assert!(!observation.diagnostic_line().contains("do-not-record"));
}

#[test]
fn diagnostics_redact_validated_secret_forms() {
    let cases = [
        ("DB_PASS=hunter2", "hunter2"),
        ("db_password=secret123", "secret123"),
        ("--password value", "value"),
        ("--password=value", "value"),
        ("Authorization: Bearer abc123", "abc123"),
        ("Bearer very-secret-token", "very-secret-token"),
        ("user:password", "password"),
        ("https://user:password@example.com/path", "password"),
        ("OPENAI_API_KEY=sk-live-a1b2c3d4e5f6g7h8i9j0", "sk-live"),
        ("GITHUB_TOKEN=ghp_example-secret-value", "ghp_example"),
        ("AWS_SECRET_ACCESS_KEY=secret-material", "secret-material"),
        (
            "DATABASE_URL=postgres://user:password@example.com/db",
            "password",
        ),
        ("REDIS_URL=redis://:password@example.com/0", "password"),
        (
            "sk-live-a1b2c3d4e5f6g7h8i9j0",
            "sk-live-a1b2c3d4e5f6g7h8i9j0",
        ),
        (
            "-----BEGIN PRIVATE KEY----- secret-material",
            "secret-material",
        ),
    ];

    for (argument, secret) in cases {
        let command = vec!["bash".to_string(), "-c".to_string(), argument.to_string()];
        let diagnostic =
            observe_exec_command("call-1", &command, "/repo", "bash").diagnostic_line();
        assert!(!diagnostic.contains(secret), "secret leaked for {argument}");
    }
}

#[test]
fn diagnostics_redact_split_and_quoted_secret_assignments() {
    let commands = [
        vec![
            "bash".to_string(),
            "-c".to_string(),
            "curl".to_string(),
            "-u".to_string(),
            "user:password".to_string(),
        ],
        vec![
            "bash".to_string(),
            "-c".to_string(),
            "'TOKEN=quoted-secret'".to_string(),
        ],
        vec![
            "pwsh".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "$env:API_KEY='powershell-secret'".to_string(),
        ],
        vec![
            "cmd.exe".to_string(),
            "/c".to_string(),
            "set API_KEY=cmd-secret".to_string(),
        ],
    ];
    let secrets = [
        "password",
        "quoted-secret",
        "powershell-secret",
        "cmd-secret",
    ];

    for (command, secret) in commands.into_iter().zip(secrets) {
        let diagnostic =
            observe_exec_command("call-1", &command, "/repo", "bash").diagnostic_line();
        assert!(!diagnostic.contains(secret), "secret leaked: {secret}");
    }
}

#[test]
fn diagnostics_redact_authorization_header_split_across_arguments() {
    let command = vec![
        "bash".to_string(),
        "-c".to_string(),
        "curl".to_string(),
        "-H".to_string(),
        "Authorization:".to_string(),
        "Bearer".to_string(),
        "low-entropy-secret".to_string(),
    ];
    let diagnostic = observe_exec_command("call-1", &command, "/repo", "bash").diagnostic_line();

    assert!(!diagnostic.contains("low-entropy-secret"));
}

#[test]
fn classifier_is_conservative_for_bypass_like_shapes() {
    for (shell, script, expected) in [
        (
            "bash",
            "sudo sh -c 'rm -rf build'",
            ExecClassification::PrivilegeEscalation,
        ),
        (
            "bash",
            "bash -lc \"curl https://example.test\"",
            ExecClassification::Network,
        ),
        (
            "powershell",
            "powershell -Command \"Invoke-WebRequest https://example.test\"",
            ExecClassification::Network,
        ),
        (
            "bash",
            "git -C repo reset --hard",
            ExecClassification::Unknown,
        ),
        ("bash", "env X=1 git push", ExecClassification::GitMutation),
        ("bash", "command git push", ExecClassification::GitMutation),
        (
            "bash",
            "/usr/bin/curl https://example.test",
            ExecClassification::Network,
        ),
        (
            "bash",
            "\"C:\\\\Program Files\\\\Git\\\\bin\\\\git.exe\" push",
            ExecClassification::Unknown,
        ),
        ("bash", "rg foo | head", ExecClassification::Unknown),
        (
            "bash",
            "rg foo && rm -rf build",
            ExecClassification::PotentialWrite,
        ),
        (
            "bash",
            "echo $(cat secret.txt)",
            ExecClassification::Unknown,
        ),
        (
            "bash",
            "cat <<EOF\nsecret\nEOF",
            ExecClassification::Unknown,
        ),
    ] {
        assert_eq!(classify(shell, script), expected, "{script}");
    }
}

#[test]
fn diagnostics_escape_control_characters_without_losing_safe_arguments() {
    let command = vec![
        "bash".to_string(),
        "-c".to_string(),
        "rg --files".to_string(),
        "src/main.rs\n\t\u{1b}[31m".to_string(),
        "--version".to_string(),
    ];
    let observation = observe_exec_command("call-1", &command, "/repo", "bash");
    let diagnostic = observation.diagnostic_line();

    assert_eq!(observation.classification(), ExecClassification::ReadOnly);
    assert!(diagnostic.contains("src/main.rs"));
    assert!(diagnostic.contains("--version"));
    assert_eq!(diagnostic.lines().count(), 1);
    assert!(!diagnostic.contains('\n'));
    assert!(!diagnostic.contains('\r'));
    assert!(!diagnostic.contains('\u{1b}'));
}

#[test]
fn diagnostics_sanitize_metadata_and_keep_one_line_output() {
    let command = vec![
        "bash".to_string(),
        "-c".to_string(),
        "rg --files".to_string(),
    ];
    let diagnostic = observe_exec_command(
        "request\nOPENAI_API_KEY=metadata-secret",
        &command,
        "DATABASE_URL=postgres://user:cwd-secret@example.test/db\n",
        "bash\n",
    )
    .diagnostic_line();

    assert!(!diagnostic.contains("metadata-secret"));
    assert!(!diagnostic.contains("cwd-secret"));
    assert_eq!(diagnostic.lines().count(), 1);
    assert!(!diagnostic.contains('\n'));
    assert!(!diagnostic.contains('\r'));
}

#[test]
fn diagnostic_mode_is_disabled_by_default() {
    assert!(!diagnostics_enabled());
}
