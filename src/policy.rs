// SPDX-License-Identifier: LicenseRef-REAL-1.0

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_POLICY: &str = include_str!("../policy/default.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Review,
    Deny,
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub verdict: Verdict,
    pub licenses: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Exception {
    /// Package name, or a purl prefix such as `pkg:npm/left-pad`.
    pub package: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    /// When set in a user policy, the built-in rules and aliases are dropped.
    #[serde(default)]
    pub replace_defaults: bool,
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    #[serde(default, rename = "exception")]
    pub exceptions: Vec<Exception>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub verdict: Verdict,
    /// The license identifier that decided the verdict.
    pub license: String,
    pub reason: String,
}

impl Policy {
    pub fn builtin() -> Policy {
        toml::from_str(DEFAULT_POLICY).expect("built-in policy is valid")
    }

    /// Loads the built-in policy, layered under a user policy if one is given.
    /// User rules are evaluated before the built-in ones.
    pub fn load(user: Option<&Path>) -> Result<Policy> {
        let mut policy = Policy::builtin();
        let Some(path) = user else {
            return Ok(policy);
        };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading policy {}", path.display()))?;
        let user: Policy =
            toml::from_str(&text).with_context(|| format!("parsing policy {}", path.display()))?;
        if user.replace_defaults {
            return Ok(user);
        }
        policy.aliases.extend(user.aliases);
        policy.rules.splice(0..0, user.rules);
        policy.exceptions = user.exceptions;
        Ok(policy)
    }

    pub fn exception_for(&self, name: &str, purl: Option<&str>) -> Option<&Exception> {
        self.exceptions
            .iter()
            .find(|e| e.package == name || purl.is_some_and(|p| p.starts_with(&e.package)))
    }

    /// Classifies a license string, which may be an SPDX expression or a
    /// license name listed in `aliases`.
    pub fn classify(&self, raw: &str) -> Classification {
        let raw = raw.trim();
        if raw.is_empty()
            || raw.eq_ignore_ascii_case("NOASSERTION")
            || raw.eq_ignore_ascii_case("NONE")
        {
            return Classification {
                verdict: Verdict::Unknown,
                license: raw.to_string(),
                reason: "No license declared.".into(),
            };
        }
        if let Some(id) = self.alias(raw) {
            return self.classify_id(id);
        }
        match parse(raw) {
            Ok(expr) => self.eval(&expr),
            Err(_) => Classification {
                verdict: Verdict::Unknown,
                license: raw.to_string(),
                reason: "Not a recognized SPDX expression or license name.".into(),
            },
        }
    }

    fn alias(&self, name: &str) -> Option<&str> {
        self.aliases
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn eval(&self, expr: &Expr) -> Classification {
        match expr {
            Expr::Id(id) => self.classify_id(id),
            Expr::And(a, b) => std::cmp::max_by_key(self.eval(a), self.eval(b), |c| c.verdict),
            Expr::Or(a, b) => std::cmp::min_by_key(self.eval(a), self.eval(b), |c| c.verdict),
        }
    }

    fn classify_id(&self, id: &str) -> Classification {
        let id = self.alias(id).unwrap_or(id);
        for rule in &self.rules {
            if rule.licenses.iter().any(|p| glob(p, id)) {
                return Classification {
                    verdict: rule.verdict,
                    license: id.to_string(),
                    reason: rule.reason.clone(),
                };
            }
        }
        Classification {
            verdict: Verdict::Unknown,
            license: id.to_string(),
            reason: "License is not covered by the policy.".into(),
        }
    }
}

/// Case-insensitive match where `*` matches any run of characters.
fn glob(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let text = text.to_ascii_lowercase();
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[derive(Debug, PartialEq)]
enum Expr {
    Id(String),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

/// Parses an SPDX license expression. `WITH` exceptions are dropped, so the
/// base license decides the verdict.
fn parse(input: &str) -> Result<Expr> {
    let spaced = input.replace('(', " ( ").replace(')', " ) ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut pos = 0;
    let expr = parse_or(&tokens, &mut pos)?;
    if pos != tokens.len() {
        bail!("unexpected token {:?}", tokens[pos]);
    }
    Ok(expr)
}

fn is_op(token: &str, op: &str) -> bool {
    token.eq_ignore_ascii_case(op)
}

fn parse_or(tokens: &[&str], pos: &mut usize) -> Result<Expr> {
    let mut left = parse_and(tokens, pos)?;
    while tokens.get(*pos).is_some_and(|t| is_op(t, "OR")) {
        *pos += 1;
        left = Expr::Or(Box::new(left), Box::new(parse_and(tokens, pos)?));
    }
    Ok(left)
}

fn parse_and(tokens: &[&str], pos: &mut usize) -> Result<Expr> {
    let mut left = parse_with(tokens, pos)?;
    while tokens.get(*pos).is_some_and(|t| is_op(t, "AND")) {
        *pos += 1;
        left = Expr::And(Box::new(left), Box::new(parse_with(tokens, pos)?));
    }
    Ok(left)
}

fn parse_with(tokens: &[&str], pos: &mut usize) -> Result<Expr> {
    let atom = parse_atom(tokens, pos)?;
    if tokens.get(*pos).is_some_and(|t| is_op(t, "WITH")) {
        *pos += 1;
        parse_id(tokens, pos)?;
    }
    Ok(atom)
}

fn parse_atom(tokens: &[&str], pos: &mut usize) -> Result<Expr> {
    if tokens.get(*pos) == Some(&"(") {
        *pos += 1;
        let inner = parse_or(tokens, pos)?;
        if tokens.get(*pos) != Some(&")") {
            bail!("missing closing parenthesis");
        }
        *pos += 1;
        return Ok(inner);
    }
    Ok(Expr::Id(parse_id(tokens, pos)?))
}

fn parse_id(tokens: &[&str], pos: &mut usize) -> Result<String> {
    let Some(token) = tokens.get(*pos) else {
        bail!("unexpected end of expression");
    };
    let valid = token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '+' | ':'));
    if !valid || ["AND", "OR", "WITH"].iter().any(|op| is_op(token, op)) {
        bail!("invalid license identifier {token:?}");
    }
    *pos += 1;
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(expr: &str) -> Verdict {
        Policy::builtin().classify(expr).verdict
    }

    #[test]
    fn classifies_single_licenses() {
        assert_eq!(verdict("MIT"), Verdict::Allow);
        assert_eq!(verdict("mit"), Verdict::Allow);
        assert_eq!(verdict("Apache-2.0"), Verdict::Allow);
        assert_eq!(verdict("LicenseRef-REAL-1.0"), Verdict::Allow);
        assert_eq!(verdict("MPL-2.0"), Verdict::Review);
        assert_eq!(verdict("LGPL-2.1-or-later"), Verdict::Review);
        assert_eq!(verdict("GPL-3.0-only"), Verdict::Deny);
        assert_eq!(verdict("GPL-2.0+"), Verdict::Deny);
        assert_eq!(verdict("AGPL-3.0-or-later"), Verdict::Deny);
        assert_eq!(verdict("CC-BY-SA-4.0"), Verdict::Deny);
        assert_eq!(verdict("CC-BY-NC-4.0"), Verdict::Deny);
        assert_eq!(verdict("BigScience-OpenRAIL-M"), Verdict::Review);
        assert_eq!(verdict("Totally-Made-Up"), Verdict::Unknown);
        assert_eq!(verdict("NOASSERTION"), Verdict::Unknown);
        assert_eq!(verdict(""), Verdict::Unknown);
    }

    #[test]
    fn evaluates_expressions() {
        assert_eq!(verdict("MIT OR Apache-2.0"), Verdict::Allow);
        assert_eq!(verdict("GPL-3.0-only OR MIT"), Verdict::Allow);
        assert_eq!(verdict("MIT AND GPL-3.0-only"), Verdict::Deny);
        assert_eq!(
            verdict("(MIT OR GPL-3.0-only) AND MPL-2.0"),
            Verdict::Review
        );
        assert_eq!(verdict("mit or apache-2.0"), Verdict::Allow);
        assert_eq!(
            verdict("GPL-2.0-only WITH Classpath-exception-2.0"),
            Verdict::Deny
        );
        assert_eq!(verdict("Apache-2.0 WITH LLVM-exception"), Verdict::Allow);
        assert_eq!(verdict("(MIT"), Verdict::Unknown);
    }

    #[test]
    fn reports_deciding_license() {
        let c = Policy::builtin().classify("MIT AND (GPL-3.0-only OR AGPL-3.0-only)");
        assert_eq!(c.verdict, Verdict::Deny);
        assert!(c.license.contains("GPL-3.0-only"));
    }

    #[test]
    fn resolves_aliases() {
        assert_eq!(verdict("MIT License"), Verdict::Allow);
        assert_eq!(verdict("Apache License, Version 2.0"), Verdict::Allow);
        assert_eq!(
            verdict("Reciprocal Ethical AI License (REAL) 1.0"),
            Verdict::Allow
        );
    }

    #[test]
    fn glob_matching() {
        assert!(glob("GPL-*", "GPL-3.0-only"));
        assert!(!glob("GPL-*", "LGPL-3.0-only"));
        assert!(glob("*RAIL*", "CreativeML-OpenRAIL-M"));
        assert!(glob("MIT", "mit"));
        assert!(!glob("MIT", "MIT-0"));
    }

    #[test]
    fn user_rules_take_precedence() {
        let dir = std::env::temp_dir().join(format!("real-check-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(
            &path,
            r#"
[[rule]]
verdict = "allow"
licenses = ["LGPL-2.1-only"]
reason = "Dynamically linked."

[[exception]]
package = "pkg:npm/foo"
reason = "Vendored separately."
"#,
        )
        .unwrap();
        let policy = Policy::load(Some(&path)).unwrap();
        assert_eq!(policy.classify("LGPL-2.1-only").verdict, Verdict::Allow);
        assert_eq!(policy.classify("GPL-3.0-only").verdict, Verdict::Deny);
        assert!(
            policy
                .exception_for("foo", Some("pkg:npm/foo@1.0.0"))
                .is_some()
        );
        assert!(policy.exception_for("bar", None).is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
