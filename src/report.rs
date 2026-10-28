// SPDX-License-Identifier: LicenseRef-REAL-1.0

use std::io::Write;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub level: Level,
    pub rule: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl Finding {
    pub fn new(level: Level, rule: &'static str, message: impl Into<String>) -> Finding {
        Finding {
            level,
            rule,
            message: message.into(),
            location: None,
        }
    }

    pub fn at(mut self, location: impl Into<String>) -> Finding {
        self.location = Some(location.into());
        self
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packages_scanned: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_scanned: Option<usize>,
}

impl Report {
    pub fn count(&self, level: Level) -> usize {
        self.findings.iter().filter(|f| f.level == level).count()
    }

    pub fn failed(&self, strict: bool) -> bool {
        self.count(Level::Error) > 0 || (strict && self.count(Level::Warning) > 0)
    }

    pub fn write_text(&self, out: &mut impl Write) -> std::io::Result<()> {
        let mut findings = self.findings.clone();
        findings.sort_by(|a, b| b.level.cmp(&a.level).then(a.rule.cmp(b.rule)));
        for f in &findings {
            let level = match f.level {
                Level::Error => "error",
                Level::Warning => "warning",
                Level::Info => "info",
            };
            match &f.location {
                Some(loc) => writeln!(out, "{level:<8} {:<22} {loc}: {}", f.rule, f.message)?,
                None => writeln!(out, "{level:<8} {:<22} {}", f.rule, f.message)?,
            }
        }
        if !findings.is_empty() {
            writeln!(out)?;
        }
        let mut scanned = Vec::new();
        if let Some(n) = self.files_scanned {
            scanned.push(format!("{n} source files"));
        }
        if let Some(n) = self.packages_scanned {
            scanned.push(format!("{n} packages"));
        }
        writeln!(
            out,
            "errors: {}, warnings: {}, info: {} ({} scanned)",
            self.count(Level::Error),
            self.count(Level::Warning),
            self.count(Level::Info),
            scanned.join(", "),
        )
    }
}
