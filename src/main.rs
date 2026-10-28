// SPDX-License-Identifier: LicenseRef-REAL-1.0

mod policy;
mod repo;
mod report;
mod sbom;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use policy::Policy;
use report::Report;

const CONFIG_FILE: &str = ".real-check.toml";

/// Checks a repository and its dependencies for compatibility with the
/// Reciprocal Ethical AI License (REAL) 1.0.
///
/// Results reflect the licensor's reading of REAL 1.0 and are not legal advice.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the repository and dependency checks.
    Check {
        #[command(flatten)]
        common: Common,
        #[command(flatten)]
        repo: RepoArgs,
        #[command(flatten)]
        deps: DepsArgs,
    },
    /// Check the license file, package manifests and SPDX headers.
    Repo {
        #[command(flatten)]
        common: Common,
        #[command(flatten)]
        repo: RepoArgs,
    },
    /// Check dependency licenses from an SBOM, generated with syft if not given.
    Deps {
        #[command(flatten)]
        common: Common,
        #[command(flatten)]
        deps: DepsArgs,
    },
    /// Classify SPDX license expressions against the policy.
    Classify {
        /// License expressions, e.g. "MIT OR GPL-3.0-only".
        #[arg(required = true)]
        licenses: Vec<String>,
        /// Policy file layered over the built-in policy.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Print the built-in policy, as a starting point for a .real-check.toml.
    Policy,
}

#[derive(Args)]
struct Common {
    /// Repository root.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Policy file layered over the built-in policy [default: <path>/.real-check.toml].
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Fail on warnings as well as errors.
    #[arg(long)]
    strict: bool,
}

#[derive(Args)]
struct RepoArgs {
    /// Skip the SPDX header check on source files.
    #[arg(long)]
    no_headers: bool,
}

#[derive(Args)]
struct DepsArgs {
    /// CycloneDX or SPDX JSON SBOM to check instead of running syft.
    #[arg(long)]
    sbom: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("real-check: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Returns whether the checks passed.
fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::Check { common, repo, deps } => {
            let policy = load_policy(&common)?;
            let mut report = check_repo(&common.path, &policy, &repo);
            let deps = check_deps(&common.path, &policy, &deps)?;
            report.findings.extend(deps.findings);
            report.packages_scanned = deps.packages_scanned;
            emit(&report, &common)
        }
        Command::Repo { common, repo } => {
            let policy = load_policy(&common)?;
            emit(&check_repo(&common.path, &policy, &repo), &common)
        }
        Command::Deps { common, deps } => {
            let policy = load_policy(&common)?;
            emit(&check_deps(&common.path, &policy, &deps)?, &common)
        }
        Command::Classify { licenses, policy } => {
            let policy = Policy::load(policy.as_deref())?;
            let mut passed = true;
            for license in licenses {
                let c = policy.classify(&license);
                passed &= c.verdict == policy::Verdict::Allow;
                let verdict = serde_json::to_value(c.verdict)?;
                println!(
                    "{:<8} {license}: {}",
                    verdict.as_str().unwrap_or_default(),
                    c.reason
                );
            }
            Ok(passed)
        }
        Command::Policy => {
            print!("{}", policy::DEFAULT_POLICY);
            Ok(true)
        }
    }
}

fn load_policy(common: &Common) -> Result<Policy> {
    let default = common.path.join(CONFIG_FILE);
    let path = common
        .policy
        .clone()
        .or_else(|| default.exists().then_some(default));
    Policy::load(path.as_deref())
}

fn check_repo(root: &Path, policy: &Policy, args: &RepoArgs) -> Report {
    repo::check(
        root,
        policy,
        &repo::Options {
            headers: !args.no_headers,
        },
    )
}

fn check_deps(root: &Path, policy: &Policy, args: &DepsArgs) -> Result<Report> {
    let text = match &args.sbom {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading SBOM {}", path.display()))?,
        None => sbom::generate(root)?,
    };
    Ok(sbom::check(&sbom::parse(&text)?, policy))
}

fn emit(report: &Report, common: &Common) -> Result<bool> {
    let mut out = std::io::stdout().lock();
    match common.format {
        Format::Text => report.write_text(&mut out)?,
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, report)?;
            println!();
        }
    }
    Ok(!report.failed(common.strict))
}
