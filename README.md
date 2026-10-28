# real-check

Checks that a repository and its dependencies are compatible with the Reciprocal Ethical AI License (REAL) 1.0.

> Results reflect the licensor's reading of REAL 1.0. They are not legal advice.

## Install

```sh
cargo install --git https://github.com/maytech-labs/real-check
```

Dependency scanning uses [syft](https://github.com/anchore/syft) to build an SBOM (`brew install syft`), or reads one you already have.

## Usage

```sh
real-check check [PATH]            # repository and dependency checks
real-check repo [PATH]             # license file, manifests, SPDX headers
real-check deps [PATH] --sbom bom.json
real-check classify "MIT OR GPL-3.0-only"
real-check policy > .real-check.toml
```

Common flags: `--format json`, `--strict` (fail on warnings), `--policy FILE`.

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

## License

[REAL 1.0](LICENSE.md)
