// SPDX-License-Identifier: LicenseRef-REAL-1.0

use std::fs;
use std::io::Read;
use std::path::Path;

use crate::policy::{Policy, Verdict};
use crate::report::{Finding, Level, Report};

pub const REAL_SPDX_ID: &str = "LicenseRef-REAL-1.0";
const CANONICAL: &str = include_str!("../license/REAL-1.0.md");
const LICENSE_FILES: &[&str] = &[
    "LICENSE.md",
    "LICENSE",
    "LICENSE.txt",
    "LICENCE.md",
    "LICENCE",
    "LICENCE.txt",
    "COPYING",
];
const PLACEHOLDERS: &[&str] = &["[Year]", "[Your Name or Organization]"];
const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cjs", "clj", "cpp", "cs", "css", "cxx", "dart", "erl", "ex", "exs", "go", "h",
    "hpp", "hs", "java", "js", "jsx", "kt", "kts", "lua", "m", "mjs", "ml", "mm", "nim", "php",
    "pl", "py", "r", "rb", "rs", "scala", "scss", "sh", "sql", "svelte", "swift", "ts", "tsx",
    "vue", "zig", "zsh",
];

pub struct Options {
    pub headers: bool,
}

pub fn check(root: &Path, policy: &Policy, options: &Options) -> Report {
    let mut report = Report::default();
    check_license_file(root, &mut report);
    check_manifests(root, policy, &mut report);
    if options.headers {
        check_headers(root, policy, &mut report);
    }
    report
}

fn check_license_file(root: &Path, report: &mut Report) {
    let found: Vec<(&str, String)> = LICENSE_FILES
        .iter()
        .filter_map(|name| {
            fs::read_to_string(root.join(name))
                .ok()
                .map(|text| (*name, text))
        })
        .collect();
    let Some((name, text)) = found.iter().find(|(_, text)| is_real(text)) else {
        report.findings.push(match found.first() {
            Some((name, _)) => Finding::new(
                Level::Error,
                "license-not-real",
                "License file is not the Reciprocal Ethical AI License.",
            )
            .at(*name),
            None => Finding::new(
                Level::Error,
                "license-missing",
                "No license file found; copy REAL's LICENSE.md into the repository root.",
            ),
        });
        return;
    };

    let version = version(text);
    if version.as_deref() != Some("1.0") {
        report.findings.push(
            Finding::new(
                Level::Warning,
                "license-version",
                format!(
                    "License declares REAL version {}; text was not compared against 1.0.",
                    version.as_deref().unwrap_or("(none)")
                ),
            )
            .at(*name),
        );
    } else if let Some((expected, actual)) = first_difference(CANONICAL, text) {
        report.findings.push(
            Finding::new(
                Level::Error,
                "license-modified",
                format!(
                    "License text differs from REAL 1.0; expected \"{expected}\", found \"{actual}\"."
                ),
            )
            .at(*name),
        );
    }

    for placeholder in PLACEHOLDERS.iter().filter(|p| text.contains(*p)) {
        report.findings.push(
            Finding::new(
                Level::Error,
                "copyright-placeholder",
                format!("Replace the {placeholder} placeholder in the copyright line."),
            )
            .at(*name),
        );
    }
    if !text
        .lines()
        .any(|l| strip_markup(l).starts_with("copyright"))
    {
        report.findings.push(
            Finding::new(
                Level::Warning,
                "copyright-missing",
                "License has no copyright line.",
            )
            .at(*name),
        );
    }
    for (other, _) in found.iter().filter(|(n, t)| n != name && !is_real(t)) {
        report.findings.push(
            Finding::new(
                Level::Warning,
                "license-conflict",
                format!("Another license file is present alongside {name}."),
            )
            .at(*other),
        );
    }
}

fn is_real(text: &str) -> bool {
    text.lines()
        .find(|l| !l.trim().is_empty())
        .is_some_and(|l| l.contains("Reciprocal Ethical AI License"))
}

fn version(text: &str) -> Option<String> {
    let title = text.lines().find(|l| !l.trim().is_empty())?;
    let rest = &title[title.find("Version")? + "Version".len()..];
    rest.split_whitespace().next().map(str::to_string)
}

/// Lowercased line with markdown emphasis, heading markers and typographic
/// punctuation normalized away.
fn strip_markup(line: &str) -> String {
    line.trim_start_matches(|c: char| c == '#' || c == '>' || c.is_whitespace())
        .chars()
        .filter(|c| !matches!(c, '*' | '_' | '`'))
        .map(|c| match c {
            '—' | '–' => '-',
            '“' | '”' => '"',
            '‘' | '’' => '\'',
            c => c.to_ascii_lowercase(),
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// License words, ignoring formatting and the copyright line(s).
fn words(text: &str) -> Vec<String> {
    text.lines()
        .map(strip_markup)
        .filter(|l| !l.starts_with("copyright"))
        .flat_map(|l| l.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .collect()
}

fn first_difference(expected: &str, actual: &str) -> Option<(String, String)> {
    let expected = words(expected);
    let actual = words(actual);
    let i = expected.iter().zip(&actual).position(|(a, b)| a != b);
    let i = match i {
        Some(i) => i,
        None if expected.len() == actual.len() => return None,
        None => expected.len().min(actual.len()),
    };
    let excerpt = |w: &[String]| {
        let start = i.saturating_sub(4);
        let end = (i + 6).min(w.len());
        if start >= end {
            "(end of text)".to_string()
        } else {
            w[start..end].join(" ")
        }
    };
    Some((excerpt(&expected), excerpt(&actual)))
}

fn check_manifests(root: &Path, policy: &Policy, report: &mut Report) {
    if let Some(json) = read_json(&root.join("package.json")) {
        let declared = json.get("license").and_then(|v| v.as_str());
        let points_to_file = declared.is_some_and(|d| d.starts_with("SEE LICENSE IN"));
        check_declared(policy, report, "package.json", declared, points_to_file);
    }
    if let Some(toml) = read_toml(&root.join("Cargo.toml"))
        && let Some(package) = toml.get("package")
    {
        let declared = package.get("license").and_then(|v| v.as_str());
        let points_to_file = package.get("license-file").is_some();
        check_declared(policy, report, "Cargo.toml", declared, points_to_file);
    }
    if let Some(toml) = read_toml(&root.join("pyproject.toml"))
        && let Some(project) = toml.get("project")
    {
        let license = project.get("license");
        let declared = license.and_then(|l| l.as_str().or_else(|| l.get("text")?.as_str()));
        let points_to_file = license.is_some_and(|l| l.get("file").is_some())
            || project.get("license-files").is_some();
        check_declared(policy, report, "pyproject.toml", declared, points_to_file);
    }
}

fn check_declared(
    policy: &Policy,
    report: &mut Report,
    manifest: &str,
    declared: Option<&str>,
    points_to_file: bool,
) {
    if points_to_file {
        return;
    }
    let Some(declared) = declared else {
        report.findings.push(
            Finding::new(
                Level::Warning,
                "manifest-license",
                format!("No license declared; set it to \"{REAL_SPDX_ID}\" or point it at the license file."),
            )
            .at(manifest),
        );
        return;
    };
    if policy.classify(declared).license != REAL_SPDX_ID {
        report.findings.push(
            Finding::new(
                Level::Error,
                "manifest-license",
                format!("Declares \"{declared}\" but the repository is licensed under REAL 1.0; use \"{REAL_SPDX_ID}\"."),
            )
            .at(manifest),
        );
    }
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

fn read_toml(path: &Path) -> Option<toml::Table> {
    fs::read_to_string(path).ok()?.parse().ok()
}

fn check_headers(root: &Path, policy: &Policy, report: &mut Report) {
    let mut scanned = 0;
    let mut missing = Vec::new();
    for entry in ignore::WalkBuilder::new(root).build().flatten() {
        let path = entry.path();
        let is_source = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SOURCE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()));
        if !is_source || !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        scanned += 1;
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        let Some(id) = spdx_header(path) else {
            missing.push(relative);
            continue;
        };
        let c = policy.classify(&id);
        if c.license == REAL_SPDX_ID {
            continue;
        }
        let level = match c.verdict {
            Verdict::Allow => continue,
            Verdict::Review => Level::Warning,
            Verdict::Deny | Verdict::Unknown => Level::Error,
        };
        report.findings.push(
            Finding::new(
                level,
                "file-license",
                format!("File is licensed {id}: {}", c.reason),
            )
            .at(relative),
        );
    }
    if !missing.is_empty() {
        missing.sort();
        let examples = missing
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = if missing.len() > 5 { ", ..." } else { "" };
        report.findings.push(Finding::new(
            Level::Warning,
            "spdx-header-missing",
            format!(
                "{} source files lack an \"SPDX-License-Identifier: {REAL_SPDX_ID}\" header ({examples}{more}).",
                missing.len()
            ),
        ));
    }
    report.files_scanned = Some(scanned);
}

fn spdx_header(path: &Path) -> Option<String> {
    let mut head = Vec::with_capacity(4096);
    fs::File::open(path)
        .ok()?
        .take(4096)
        .read_to_end(&mut head)
        .ok()?;
    let head = String::from_utf8_lossy(&head);
    let marker = "SPDX-License-Identifier:";
    let line = head.lines().find(|l| l.contains(marker))?;
    let id = &line[line.find(marker)? + marker.len()..];
    let id = id
        .trim()
        .trim_end_matches("*/")
        .trim_end_matches("-->")
        .trim();
    Some(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempRepo(std::path::PathBuf);

    impl TempRepo {
        fn new(name: &str) -> TempRepo {
            let dir =
                std::env::temp_dir().join(format!("real-check-repo-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TempRepo(dir)
        }

        fn write(&self, path: &str, contents: &str) -> &TempRepo {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
            self
        }

        fn rules(&self) -> Vec<&'static str> {
            let report = check(&self.0, &Policy::builtin(), &Options { headers: true });
            let mut rules: Vec<_> = report.findings.iter().map(|f| f.rule).collect();
            rules.sort();
            rules
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn filled_license() -> String {
        CANONICAL.replace("[Year] [Your Name or Organization]", "2026 Example Org")
    }

    #[test]
    fn embedded_license_matches_upstream() {
        // Set REAL_LICENSE_PATH to a checkout's LICENSE.md to verify the bundled copy.
        let Ok(path) = std::env::var("REAL_LICENSE_PATH") else {
            return;
        };
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, CANONICAL, "run: cp {path} license/REAL-1.0.md");
    }

    #[test]
    fn clean_repository_passes() {
        let repo = TempRepo::new("clean");
        repo.write("LICENSE.md", &filled_license())
            .write(
                "src/main.rs",
                "// SPDX-License-Identifier: LicenseRef-REAL-1.0\nfn main() {}\n",
            )
            .write("package.json", r#"{"license": "LicenseRef-REAL-1.0"}"#);
        assert!(repo.rules().is_empty(), "{:?}", repo.rules());
    }

    #[test]
    fn formatting_differences_are_ignored() {
        let reformatted = filled_license()
            .replace(
                "Reciprocal Ethical AI License (REAL) — Version 1.0",
                "# Reciprocal Ethical AI License (REAL) - Version 1.0",
            )
            .replace("1. Definitions", "## 1. Definitions")
            .replace("\"Software\" means", "**\"Software\"** means");
        assert_eq!(first_difference(CANONICAL, &reformatted), None);
    }

    #[test]
    fn missing_license() {
        let repo = TempRepo::new("missing");
        assert_eq!(repo.rules(), vec!["license-missing"]);
    }

    #[test]
    fn other_license() {
        let repo = TempRepo::new("other");
        repo.write("LICENSE", "MIT License\n\nCopyright (c) 2026 Someone\n");
        assert_eq!(repo.rules(), vec!["license-not-real"]);
    }

    #[test]
    fn placeholder_and_modification() {
        let repo = TempRepo::new("modified");
        repo.write(
            "LICENSE.md",
            &CANONICAL.replace("Weapons & Harm", "Weapons"),
        );
        assert_eq!(
            repo.rules(),
            vec![
                "copyright-placeholder",
                "copyright-placeholder",
                "license-modified"
            ]
        );
    }

    #[test]
    fn manifest_and_headers() {
        let repo = TempRepo::new("manifest");
        repo.write("LICENSE.md", &filled_license())
            .write("Cargo.toml", "[package]\nname = \"x\"\nlicense = \"MIT\"\n")
            .write("src/lib.rs", "pub fn f() {}\n")
            .write(
                "vendor/gpl.c",
                "/* SPDX-License-Identifier: GPL-2.0-only */\n",
            )
            .write("vendor/mit.c", "// SPDX-License-Identifier: MIT\n");
        assert_eq!(
            repo.rules(),
            vec!["file-license", "manifest-license", "spdx-header-missing"]
        );
    }
}
