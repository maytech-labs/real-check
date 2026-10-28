// SPDX-License-Identifier: LicenseRef-REAL-1.0

//! Repo automation, run with `cargo xtask <task>`.

mod notices;

use std::process::{Command, ExitCode};

const USAGE: &str = "\
cargo xtask <task>

Tasks:
  check    Everything CI runs: fmt, clippy, tests, third-party notices, self-check
  notices  Regenerate THIRD-PARTY-NOTICES.md from Cargo.lock
";

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("check") => check(),
        Some("notices") => notices::run(std::env::args().skip(2).collect()),
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Runs the same steps as CI, stopping at the first failure.
fn check() -> ExitCode {
    let steps: &[&[&str]] = &[
        &["fmt", "--all", "--check"],
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        &["test", "--workspace"],
        &["xtask", "notices", "--check"],
        &["run", "--quiet", "--bin", "real-check", "--", "repo", "."],
    ];
    for args in steps {
        eprintln!("==> cargo {}", args.join(" "));
        let ok = Command::new(env!("CARGO"))
            .args(*args)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("cargo {} failed", args[0]);
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
