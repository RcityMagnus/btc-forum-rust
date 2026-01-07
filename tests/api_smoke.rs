use axum::http::StatusCode;
use btc_forum_rust::auth::AuthClaims;
use serde_json::json;

// Placeholder smoke test to ensure crate builds tests harness
#[test]
fn claims_debuggable() {
    let claims = AuthClaims {
        sub: "tester".into(),
        exp: 0,
        iat: 0,
        session_id: None,
        role: None,
        permissions: None,
    };
    assert_eq!(claims.sub, "tester");
}

#[test]
fn status_ok_constant() {
    assert_eq!(StatusCode::OK, StatusCode::from_u16(200).unwrap());
}

#[test]
fn json_macro_works() {
    let val = json!({"hello": "world"});
    assert_eq!(val["hello"], "world");
}
