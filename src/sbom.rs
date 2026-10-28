// SPDX-License-Identifier: LicenseRef-REAL-1.0

use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::policy::{Policy, Verdict};
use crate::report::{Finding, Level, Report};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    /// SPDX expression or license name; `None` when the SBOM declares nothing.
    pub license: Option<String>,
}

impl Package {
    fn label(&self) -> String {
        match (&self.purl, &self.version) {
            (Some(purl), _) => purl.clone(),
            (None, Some(version)) => format!("{}@{version}", self.name),
            (None, None) => self.name.clone(),
        }
    }
}

/// Generates a CycloneDX SBOM for `root` with syft.
pub fn generate(root: &Path) -> Result<String> {
    let output = Command::new("syft")
        .arg("scan")
        .arg(format!("dir:{}", root.display()))
        .args(["--output", "cyclonedx-json", "--quiet"])
        .output();
    let output = match output {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("syft is not installed; install it (brew install syft) or pass --sbom FILE")
        }
        Err(e) => return Err(e).context("running syft"),
    };
    if !output.status.success() {
        bail!(
            "syft failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("syft output is not UTF-8")
}

/// Parses a CycloneDX or SPDX JSON document.
pub fn parse(text: &str) -> Result<Vec<Package>> {
    let doc: Value = serde_json::from_str(text).context("SBOM is not valid JSON")?;
    let mut packages = if doc.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        let mut packages = Vec::new();
        cyclonedx_components(doc.get("components"), &mut packages);
        packages
    } else if doc.get("spdxVersion").is_some() {
        spdx_packages(&doc)
    } else {
        bail!("unrecognized SBOM format; expected CycloneDX or SPDX JSON");
    };
    packages.sort();
    packages.dedup();
    Ok(packages)
}

fn cyclonedx_components(components: Option<&Value>, out: &mut Vec<Package>) {
    for c in components.and_then(Value::as_array).into_iter().flatten() {
        if c.get("type").and_then(Value::as_str) != Some("file") {
            let licenses: Vec<String> = c
                .get("licenses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|l| {
                    let s = l.get("expression").or_else(|| {
                        let license = l.get("license")?;
                        license.get("id").or_else(|| license.get("name"))
                    })?;
                    s.as_str().map(str::to_string)
                })
                .collect();
            out.push(Package {
                name: str_field(c, "name").unwrap_or_default(),
                version: str_field(c, "version"),
                purl: str_field(c, "purl"),
                license: combine(licenses),
            });
        }
        cyclonedx_components(c.get("components"), out);
    }
}

fn spdx_packages(doc: &Value) -> Vec<Package> {
    let described: HashSet<&str> = doc
        .get("documentDescribes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    doc.get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| {
            !p.get("SPDXID")
                .and_then(Value::as_str)
                .is_some_and(|id| described.contains(id))
        })
        .map(|p| {
            let assertion = |key| str_field(p, key).filter(|v| v != "NOASSERTION" && v != "NONE");
            let purl = p
                .get("externalRefs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|r| r.get("referenceType").and_then(Value::as_str) == Some("purl"))
                .and_then(|r| str_field(r, "referenceLocator"));
            Package {
                name: str_field(p, "name").unwrap_or_default(),
                version: str_field(p, "versionInfo"),
                purl,
                license: assertion("licenseConcluded").or_else(|| assertion("licenseDeclared")),
            }
        })
        .collect()
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Several license entries on one component are treated as all applying.
fn combine(licenses: Vec<String>) -> Option<String> {
    let unique: BTreeSet<String> = licenses.into_iter().collect();
    match unique.len() {
        0 => None,
        1 => unique.into_iter().next(),
        _ => Some(
            unique
                .iter()
                .map(|l| format!("({l})"))
                .collect::<Vec<_>>()
                .join(" AND "),
        ),
    }
}

pub fn check(packages: &[Package], policy: &Policy) -> Report {
    let mut report = Report {
        packages_scanned: Some(packages.len()),
        ..Report::default()
    };
    for package in packages {
        let license = package.license.as_deref().unwrap_or("");
        let c = policy.classify(license);
        if c.verdict == Verdict::Allow {
            continue;
        }
        let shown = if license.is_empty() {
            "no license".to_string()
        } else {
            license.to_string()
        };
        if let Some(e) = policy.exception_for(&package.name, package.purl.as_deref()) {
            report.findings.push(
                Finding::new(
                    Level::Info,
                    "dependency-exception",
                    format!("{shown}: excepted ({})", e.reason),
                )
                .at(package.label()),
            );
            continue;
        }
        let (level, rule) = match c.verdict {
            Verdict::Allow => unreachable!(),
            Verdict::Review => (Level::Warning, "dependency-review"),
            Verdict::Deny => (Level::Error, "dependency-incompatible"),
            Verdict::Unknown => (Level::Error, "dependency-unknown"),
        };
        let detail = if c.license != license && !c.license.is_empty() {
            format!("{shown} ({}): {}", c.license, c.reason)
        } else {
            format!("{shown}: {}", c.reason)
        };
        report
            .findings
            .push(Finding::new(level, rule, detail).at(package.label()));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    const CYCLONEDX: &str = r#"{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "metadata": {"component": {"name": "root", "type": "file"}},
      "components": [
        {"type": "library", "name": "serde", "version": "1.0.0", "purl": "pkg:cargo/serde@1.0.0",
         "licenses": [{"expression": "MIT OR Apache-2.0"}]},
        {"type": "library", "name": "readline", "version": "8.2", "purl": "pkg:deb/readline@8.2",
         "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
        {"type": "library", "name": "dual", "version": "1",
         "licenses": [{"license": {"id": "MIT"}}, {"license": {"name": "MPL-2.0"}}],
         "components": [{"type": "library", "name": "nested", "version": "2"}]},
        {"type": "file", "name": "/some/file"}
      ]
    }"#;

    const SPDX: &str = r#"{
      "spdxVersion": "SPDX-2.3",
      "documentDescribes": ["SPDXRef-root"],
      "packages": [
        {"SPDXID": "SPDXRef-root", "name": "root", "licenseConcluded": "NOASSERTION"},
        {"SPDXID": "SPDXRef-a", "name": "left-pad", "versionInfo": "1.3.0",
         "licenseConcluded": "NOASSERTION", "licenseDeclared": "WTFPL",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0"}]},
        {"SPDXID": "SPDXRef-b", "name": "mystery", "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION"}
      ]
    }"#;

    #[test]
    fn parses_cyclonedx() {
        let packages = parse(CYCLONEDX).unwrap();
        let names: Vec<_> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["dual", "nested", "readline", "serde"]);
        assert_eq!(packages[0].license.as_deref(), Some("(MIT) AND (MPL-2.0)"));
        assert_eq!(packages[1].license, None);
    }

    #[test]
    fn parses_spdx() {
        let packages = parse(SPDX).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].license.as_deref(), Some("WTFPL"));
        assert_eq!(packages[0].purl.as_deref(), Some("pkg:npm/left-pad@1.3.0"));
        assert_eq!(packages[1].license, None);
    }

    #[test]
    fn rejects_other_json() {
        assert!(parse(r#"{"hello": "world"}"#).is_err());
    }

    #[test]
    fn classifies_dependencies() {
        let report = check(&parse(CYCLONEDX).unwrap(), &Policy::builtin());
        let mut rules: Vec<_> = report
            .findings
            .iter()
            .map(|f| (f.rule, f.location.clone().unwrap()))
            .collect();
        rules.sort();
        assert_eq!(
            rules,
            vec![
                (
                    "dependency-incompatible",
                    "pkg:deb/readline@8.2".to_string()
                ),
                ("dependency-review", "dual@1".to_string()),
                ("dependency-unknown", "nested@2".to_string()),
            ]
        );
        assert_eq!(report.packages_scanned, Some(4));
    }
}
