//! CLI consumer of the shared deny-pattern disposition fixture.
//!
//! The CLI delegates `deny` validation to the shared
//! `microsandbox_types::validate_deny_list` (via the SDK/runtime), so it must
//! produce the same disposition as every other SDK for the fixture matrix.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    pattern: String,
    readonly: bool,
    expect: String,
}

/// Locate the shared fixture by walking up from this crate's manifest directory
/// until a directory containing `sdk/rust/tests/fixtures/deny/patterns.json` is
/// found. Resolving from the workspace root this way fails clearly if the
/// fixture moves, instead of relying on a fixed `../../` depth.
fn fixture_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for dir in manifest.ancestors() {
        let candidate = dir.join("sdk/rust/tests/fixtures/deny/patterns.json");
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "shared deny fixture not found in any ancestor of {}",
        manifest.display()
    );
}

fn fixture_cases() -> Vec<Case> {
    let path = fixture_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn deny_pattern_fixture_dispositions_match_shared_validator() {
    let cases = fixture_cases();
    assert!(!cases.is_empty(), "fixture must not be empty");

    for case in cases {
        let result = microsandbox_types::validate_deny_list(&[case.pattern.clone()], case.readonly);
        match case.expect.as_str() {
            "accept" => assert!(
                result.is_ok(),
                "expected accept for pattern {:?} readonly={}: got {:?}",
                case.pattern,
                case.readonly,
                result.err()
            ),
            "reject" => assert!(
                result.is_err(),
                "expected reject for pattern {:?} readonly={}",
                case.pattern,
                case.readonly
            ),
            other => panic!("unknown fixture expectation {other:?}"),
        }
    }
}
