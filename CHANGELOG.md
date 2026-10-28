# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Releasing is pushing a tag: the release workflow sets the version, dates this changelog, and commits that to `main` before building.

## 0.1.1 - 2026-10-27

### Fixed

- Rust crates no longer all show as having no license. Their licenses come from `cargo metadata`, for every Cargo workspace in the repository, or from the local registry cache when that can't run.
- The scanned project's own packages and GitHub Actions used in workflows are no longer checked as dependencies.
- syft now looks up licenses online (`--offline` turns that off) and skips `target/` directories, which made scans of Rust repositories take minutes.
- Several license entries on one package are classified one by one, so names such as `3-Clause BSD License` are recognized. Common license names used by Maven and npm packages are now recognized too.

## 0.1.0 - 2026-10-27

The first release: checks a repository and its dependencies for compatibility with the Reciprocal Ethical AI License (REAL) 1.0.

- `real-check repo`: the license file matches REAL 1.0 with its placeholders filled in, package manifests declare it, and source files carry SPDX headers.
- `real-check deps`: classifies dependency licenses from a CycloneDX or SPDX SBOM, generated with syft when none is given.
- `real-check classify` and `real-check policy`, and a `.real-check.toml` layered over the built-in policy.
- Install with `brew install maytech-labs/tap/real-check`.
