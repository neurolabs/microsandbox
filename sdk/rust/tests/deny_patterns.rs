//! Shared cross-SDK deny-pattern disposition fixture.
//!
//! `microsandbox_types::fixtures::DENY_FIXTURE_JSON` embeds the single source of
//! the pattern -> disposition matrix. Every language SDK loads it and asserts
//! that its own validation path produces the same `accept`/`reject` disposition,
//! so a pattern accepted by one SDK is accepted (or refused) by all of them.

use serde::Deserialize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One row of the shared deny-pattern fixture.
#[derive(Debug, Deserialize)]
struct Case {
    /// The `deny` pattern under test.
    pattern: String,
    /// Whether the mount carrying the pattern is read-only.
    readonly: bool,
    /// The expected disposition: `accept` or `reject`.
    expect: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Load the shared deny-pattern fixture.
fn fixture_cases() -> Vec<Case> {
    serde_json::from_str(microsandbox_types::fixtures::DENY_FIXTURE_JSON)
        .expect("parse shared deny fixture")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

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
