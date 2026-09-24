//! The settings table against the two places that repeat it: the workflow
//! that runs the suite, and the crate's README. Read as text; no network.

use std::collections::BTreeSet;

use ceremony_tests::settings::{
    Need,
    VARIABLES,
};

/// The CI jobs that run rungs: the sections those rungs read, and the gate
/// outputs the job waits on. Google's job has none: it runs on a dispatch
/// alone and fails on a missing setting.
const JOBS: &[(&str, &[&str], &[&str])] = &[
    ("refusals", &["github-app"], &["go"]),
    (
        "full",
        &["github-app", "github-account"],
        &["go", "account"],
    ),
    ("x", &["x-app", "x-account", "x-session"], &["x"]),
    (
        "google",
        &["google-app", "google-account", "google-session"],
        &[],
    ),
];

/// The sections each gate output checks.
const GATES: &[(&str, &[&str])] = &[
    ("go", &["github-app"]),
    ("account", &["github-account"]),
    ("x", &["x-app", "x-account", "x-session"]),
];

/// The section and need the table gives `name`.
fn variable(name: &str) -> Option<(&'static str, Need)> {
    VARIABLES.iter().find(|v| v.0 == name).map(|v| (v.1, v.2))
}

fn read(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn workflow() -> String {
    read("../.github/workflows/ceremony.yml")
}

/// The variables `sections` require.
fn required(sections: &[&str]) -> BTreeSet<String> {
    VARIABLES
        .iter()
        .filter(|v| sections.contains(&v.1) && v.2 == Need::Required)
        .map(|v| v.0.to_owned())
        .collect()
}

/// The lines of job `name`, from its key under `jobs:` to the next job's.
fn job<'a>(workflow: &'a str, name: &str) -> Vec<&'a str> {
    let jobs = workflow
        .split_once("\njobs:\n")
        .expect("the workflow has jobs")
        .1;
    let header = format!("  {name}:");
    let mut lines = jobs.lines().skip_while(|line| *line != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("the workflow has a job {name}"));
    std::iter::once(first)
        .chain(lines.take_while(|line| {
            !(line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':'))
        }))
        .collect()
}

/// An `env:` entry's key, if `line` is one: an upper-case name and a colon.
fn env_key(line: &str) -> Option<&str> {
    let (key, _) = line.trim_start().split_once(':')?;
    (!key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
    .then_some(key)
}

/// Every name the workflow reads as `secrets.NAME` or `vars.NAME`.
fn referenced(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for prefix in ["secrets.", "vars."] {
        for (at, _) in text.match_indices(prefix) {
            let name: String = text[at + prefix.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            names.insert(name);
        }
    }
    names
}

#[test]
fn every_name_the_workflow_reads_is_a_setting_under_its_own_name() {
    let workflow = workflow();
    for name in referenced(&workflow) {
        assert!(
            variable(&name).is_some(),
            "the workflow reads {name}, which the settings do not list"
        );
    }
    for line in workflow.lines() {
        let Some(key) = env_key(line) else { continue };
        let value = line.split_once(':').expect("a key").1.trim();
        let read = referenced(value);
        if !read.is_empty() {
            assert_eq!(
                read,
                BTreeSet::from([key.to_owned()]),
                "{key} carries the setting of its own name"
            );
        }
    }
}

#[test]
fn each_gate_checks_exactly_what_its_sections_require() {
    let workflow = workflow();
    let gate = job(&workflow, "gate");
    for (output, sections) in GATES {
        let prefix = format!("available {output} ");
        let line = gate
            .iter()
            .map(|line| line.trim())
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("the gate sets {output}"));
        // Each `"$NAME"` the line quotes, the command substitution aside.
        let checked: BTreeSet<String> = line
            .split("\"$")
            .skip(1)
            .filter_map(|rest| rest.split_once('"'))
            .map(|(name, _)| name)
            .filter(|name| env_key(&format!("{name}:")).is_some())
            .map(str::to_owned)
            .collect();
        assert_eq!(checked, required(sections), "the gate's {output} check");
    }
}

#[test]
fn each_job_is_given_what_its_rungs_require_and_waits_on_its_gates() {
    let workflow = workflow();
    for (name, sections, gates) in JOBS {
        let lines = job(&workflow, name);
        let given: BTreeSet<String> = lines
            .iter()
            .filter_map(|line| env_key(line))
            .map(str::to_owned)
            .collect();
        let absent: Vec<_> = required(sections).difference(&given).cloned().collect();
        assert!(absent.is_empty(), "job {name} is not given {absent:?}");
        for key in &given {
            let (section, _) = variable(key).unwrap_or_else(|| {
                panic!("job {name} sets {key}, which the settings do not list")
            });
            assert!(
                sections.contains(&section) || section == "tooling",
                "job {name} sets {key}, of the {section} section its rungs do not read"
            );
        }
        let condition = lines.join("\n");
        for gate in *gates {
            assert!(
                condition.contains(&format!("needs.gate.outputs.{gate} == 'true'")),
                "job {name} waits on the gate's {gate}"
            );
        }
        if gates.is_empty() {
            assert!(!condition.contains("needs"), "job {name} has no gate");
        }
    }
}

#[test]
fn the_readme_lists_every_setting_as_the_table_does() {
    let readme = read("README.md");
    let rows: Vec<&str> = readme.lines().filter(|l| l.starts_with("| `")).collect();
    for &(name, section, need) in VARIABLES {
        let start = format!("| `{name}` |");
        let row = rows
            .iter()
            .find(|row| row.starts_with(&start))
            .unwrap_or_else(|| panic!("the README's settings table lists {name}"));
        let need = match need {
            Need::Required => "required".to_owned(),
            Need::Optional => "optional".to_owned(),
            Need::InsteadOf(of) => format!("instead of `{of}`"),
        };
        assert!(
            row.starts_with(&format!("{start} {section} | {need} |")),
            "the README lists {name} as in {section}, {need}: {row}"
        );
    }
    for row in rows {
        let name = row[3..].split('`').next().expect("a name");
        assert!(
            variable(name).is_some(),
            "the README lists {name}, which the settings do not"
        );
    }
}
