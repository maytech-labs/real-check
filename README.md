# real-check

Checks that a repository and its dependencies are compatible with the Reciprocal Ethical AI License (REAL) 1.0.

> Results reflect the licensor's reading of REAL 1.0. They are not legal advice.

## Install

```sh
brew install maytech-labs/tap/real-check
```

Or from source: `cargo install --git https://github.com/maytech-labs/real-check`.

`real-check deps` and `real-check check` read dependency licenses from an SBOM. Without `--sbom`, they generate one with [syft](https://github.com/anchore/syft), which the brew formula installs. `real-check repo` needs nothing else.

## Dependencies

- syft looks up licenses that lockfiles don't record, online. `--offline` turns that off, at the cost of many more unknown licenses.
- Rust crate licenses come from `cargo metadata` for every Cargo workspace in the repository, or from the local registry cache when that can't run, for example because `Cargo.lock` is out of date. `real-check` never rewrites a lockfile.
- The scanned project's own packages, GitHub Actions (which run in CI and aren't distributed), and `target/` directories are left out.
- npm devDependencies aren't in syft's SBOM, so they aren't checked.

## Usage

```sh
real-check check [PATH]            # repository and dependency checks
real-check repo [PATH]             # license file, manifests, SPDX headers
real-check deps [PATH] --sbom bom.json
real-check classify "MIT OR GPL-3.0-only"
real-check policy > .real-check.toml
```

Common flags: `--format json`, `--strict` (fail on warnings), `--policy FILE`. `deps` and `check` also take `--sbom FILE` and `--offline`.

Exit codes: `0` passed, `1` errors found (or warnings with `--strict`), `2` the tool could not run.

## Checks

| Rule | Level | Meaning |
|---|---|---|
| `license-missing` | error | No `LICENSE.md`/`LICENSE`/`COPYING` in the root |
| `license-not-real` | error | The license file is some other license |
| `license-modified` | error | Text differs from REAL 1.0 (formatting and the copyright line are ignored) |
| `license-version` | warning | A REAL version other than 1.0; text not compared |
| `license-conflict` | warning | Another, non-REAL license file sits alongside it |
| `copyright-placeholder` | error | `[Year]` or `[Your Name or Organization]` left in place |
| `copyright-missing` | warning | No copyright line |
| `manifest-license` | error/warning | `package.json`, `Cargo.toml` or `pyproject.toml` declares another license, or none |
| `spdx-header-missing` | warning | Source files without `SPDX-License-Identifier: LicenseRef-REAL-1.0` (skip with `--no-headers`) |
| `file-license` | error/warning | A source file declares an incompatible or questionable license |
| `dependency-incompatible` | error | Dependency license denied by the policy (e.g. GPL, CC-BY-SA) |
| `dependency-review` | warning | Dependency needs a human look (e.g. LGPL, MPL) |
| `dependency-unknown` | error | No license declared, or one the policy does not cover |
| `dependency-exception` | info | Dependency excepted by the policy |
| `cargo-metadata` | warning | `cargo metadata` failed for a workspace; crate licenses came from the registry cache |

## Policy

The built-in policy is [`policy/default.toml`](policy/default.toml). A `.real-check.toml` in the scanned root (or `--policy FILE`) is layered over it: its rules are evaluated first, its aliases are added, and it may list exceptions. Set `replace_defaults = true` to use only your own rules.

```toml
[[rule]]
verdict = "allow"
licenses = ["LGPL-2.1-only"]
reason = "Dynamically linked and replaceable."

[[exception]]
package = "pkg:npm/some-package"   # name or purl prefix
reason = "Build-time only; not distributed."
```

For SPDX expressions, `OR` takes the most permissive branch and `AND` the most restrictive. When an SBOM lists several licenses for one component, all of them are treated as applying.

## Development

`license/REAL-1.0.md` is a copy of [`LICENSE.md`](https://github.com/maytech-labs/real-license/blob/main/LICENSE.md) from the license repository. To check it hasn't drifted:

```sh
REAL_LICENSE_PATH=../real-license/LICENSE.md cargo test
```

`cargo xtask check` runs everything CI does. `cargo xtask notices` regenerates `THIRD-PARTY-NOTICES.md` after dependencies change.

## Releasing

Add changes to `CHANGELOG.md` under **Unreleased** as they land. To release, tag `main`'s latest commit and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. The release workflow sets the version in `Cargo.toml` and `Cargo.lock`, dates the changelog section, commits that to `main`, and moves the tag onto it. Then it builds macOS and Linux binaries, publishes the GitHub release, and updates the formula in [maytech-labs/homebrew-tap](https://github.com/maytech-labs/homebrew-tap) using the `HOMEBREW_TAP_TOKEN` secret.

## License

[REAL 1.0](LICENSE.md)
