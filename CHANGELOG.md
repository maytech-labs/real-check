# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## 0.1.0 - 2026-10-27

The first release: checks a repository and its dependencies for compatibility with the Reciprocal Ethical AI License (REAL) 1.0.

- `real-check repo`: the license file matches REAL 1.0 with its placeholders filled in, package manifests declare it, and source files carry SPDX headers.
- `real-check deps`: classifies dependency licenses from a CycloneDX or SPDX SBOM, generated with syft when none is given.
- `real-check classify` and `real-check policy`, and a `.real-check.toml` layered over the built-in policy.
- Install with `brew install maytech-labs/tap/real-check`.
