// SPDX-License-Identifier: LicenseRef-REAL-1.0

//! Rust crate licenses from `cargo metadata`. Cargo.lock records no
//! licenses and syft can't look them up, so its SBOMs leave every crate
//! without one.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::report::{Finding, Level};
use crate::sbom::Package;

/// Fills in crate licenses and drops the scanned repository's own crates,
/// for every Cargo workspace under `root` with a Cargo.lock. Returns a
/// warning for each workspace cargo can't read.
pub fn fill(root: &Path, packages: &mut Vec<Package>) -> Vec<Finding> {
    let mut warnings = Vec::new();
    let mut licenses = HashMap::new();
    let mut own = HashSet::new();
    for lockfile in lockfiles(root) {
        let manifest = lockfile.with_file_name("Cargo.toml");
        let metadata = match metadata(&manifest) {
            Ok(metadata) => metadata,
            Err(error) => {
                let relative = manifest.strip_prefix(root).unwrap_or(&manifest);
                warnings.push(
                    Finding::new(
                        Level::Warning,
                        "cargo-metadata",
                        format!("Couldn't run cargo metadata ({error}); crate licenses came from the local registry cache where available."),
                    )
                    .at(relative.display().to_string()),
                );
                own.extend(own_package(&manifest));
                continue;
            }
        };
        let workspace: HashSet<&str> = metadata["workspace_members"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for package in metadata["packages"].as_array().into_iter().flatten() {
            let (Some(name), Some(version)) =
                (package["name"].as_str(), package["version"].as_str())
            else {
                continue;
            };
            let key = (name.to_string(), version.to_string());
            if package["id"]
                .as_str()
                .is_some_and(|id| workspace.contains(id))
            {
                own.insert(key);
            } else if let Some(license) = package["license"].as_str() {
                licenses.insert(key, license.to_string());
            }
        }
    }
    packages.retain(|p| {
        let is_crate = p
            .purl
            .as_deref()
            .is_none_or(|purl| purl.starts_with("pkg:cargo/"));
        !(is_crate && own.contains(&key(p)))
    });
    for p in packages.iter_mut() {
        let is_crate = p
            .purl
            .as_deref()
            .is_some_and(|purl| purl.starts_with("pkg:cargo/"));
        if is_crate && p.licenses.is_empty() {
            let license = licenses.get(&key(p)).cloned();
            p.licenses.extend(license.or_else(|| cached_license(p)));
        }
    }
    warnings
}

/// The `[package]` a manifest declares, if it has one.
fn own_package(manifest: &Path) -> Option<(String, String)> {
    let manifest: toml::Table = std::fs::read_to_string(manifest).ok()?.parse().ok()?;
    let package = manifest.get("package")?;
    let version = package
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0");
    Some((
        package.get("name")?.as_str()?.to_string(),
        version.to_string(),
    ))
}

/// The license in a downloaded crate's Cargo.toml, for when cargo metadata
/// can't run, such as with a stale Cargo.lock.
fn cached_license(p: &Package) -> Option<String> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))?;
    let dir = format!("{}-{}", p.name, p.version.as_deref()?);
    std::fs::read_dir(home.join("registry/src"))
        .ok()?
        .flatten()
        .find_map(|registry| {
            let text =
                std::fs::read_to_string(registry.path().join(&dir).join("Cargo.toml")).ok()?;
            let manifest: toml::Table = text.parse().ok()?;
            Some(
                manifest
                    .get("package")?
                    .get("license")?
                    .as_str()?
                    .to_string(),
            )
        })
}

/// Cargo.lock files with a Cargo.toml beside them, skipping ignored paths
/// such as `target/`.
fn lockfiles(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = ignore::WalkBuilder::new(root)
        .build()
        .flatten()
        .map(|e| e.into_path())
        .filter(|p| p.file_name().is_some_and(|n| n == "Cargo.lock"))
        .filter(|p| p.with_file_name("Cargo.toml").exists())
        .collect();
    found.sort();
    found
}

fn key(p: &Package) -> (String, String) {
    (p.name.clone(), p.version.clone().unwrap_or_default())
}

fn metadata(manifest: &Path) -> Result<Value, String> {
    // --locked, so a missing or stale Cargo.lock is reported rather than rewritten.
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .map_err(|e| format!("can't run cargo: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(stderr
            .lines()
            .find(|l| l.starts_with("error"))
            .unwrap_or(&stderr)
            .trim()
            .to_string());
    }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("bad cargo metadata: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, version: &str, purl: Option<&str>) -> Package {
        Package {
            name: name.into(),
            version: Some(version.into()),
            purl: purl.map(str::to_string),
            licenses: vec![],
        }
    }

    #[test]
    fn fills_this_crates_dependencies() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut packages = vec![
            package("real-check", env!("CARGO_PKG_VERSION"), None),
            package("anyhow", "1.0.104", Some("pkg:cargo/anyhow@1.0.104")),
            package("left-pad", "1.3.0", Some("pkg:npm/left-pad@1.3.0")),
        ];
        assert!(fill(root, &mut packages).is_empty());
        let names: Vec<_> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["anyhow", "left-pad"]);
        assert_eq!(packages[0].licenses, vec!["MIT OR Apache-2.0"]);
        assert!(packages[1].licenses.is_empty());
    }

    #[test]
    fn reads_the_registry_cache() {
        // anyhow is one of this crate's dependencies, so building it downloaded it.
        let anyhow = package("anyhow", "1.0.104", Some("pkg:cargo/anyhow@1.0.104"));
        assert_eq!(
            cached_license(&anyhow).as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(cached_license(&package("not-a-crate", "0.0.0", None)), None);
    }

    #[test]
    fn finds_nested_workspaces() {
        let dir = std::env::temp_dir().join(format!("real-check-cargo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tools/app")).unwrap();
        std::fs::write(dir.join("tools/app/Cargo.toml"), "").unwrap();
        std::fs::write(dir.join("tools/app/Cargo.lock"), "").unwrap();
        std::fs::write(dir.join("Cargo.lock"), "").unwrap();
        assert_eq!(lockfiles(&dir), vec![dir.join("tools/app/Cargo.lock")]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ignores_roots_without_cargo() {
        let dir = std::env::temp_dir().join(format!("real-check-nocargo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut packages = vec![package("x", "1", None)];
        assert!(fill(&dir, &mut packages).is_empty());
        assert_eq!(packages.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
