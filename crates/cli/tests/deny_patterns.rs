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

fn fixture_cases() -> Vec<Case> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/rust/tests/fixtures/deny/patterns.json");
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
