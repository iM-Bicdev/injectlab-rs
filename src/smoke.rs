//! Adapter smoke test: one cheap canary call per adapter, honestly reported.
//!
//! Faithful port of `injectlab/smoke.py`. The scored-run blocker is an API
//! key; the moment a key exists, the first question is not "which model" but
//! "does this key work". A full 46-probe run against a dead key wastes
//! minutes and a confusing report. `smoke` answers the dumb question in one
//! call per adapter: auth failed, rate limited, other transport error, or
//! alive.
//!
//! Classification keys on the adapter's no-raise error strings (see
//! `models`: the HTTP status survives in `[injectlab transport error:
//! Http401]`). A real response is anything that isn't an error string.
//!
//! The canary prompt is deliberately boring: one word asked, no attack
//! surface, nothing to grade — this tests the pipe, not the model.

use crate::models::Adapter;
use crate::pyjson::{py_repr_str, JVal};

/// The canary: one word asked, nothing to grade.
pub const CANARY: &str = "Reply with exactly this word and nothing else: ok";

const ERROR_PREFIX: &str = "[injectlab";

/// One adapter's smoke result. `status` is one of
/// "ok" | "auth_failed" | "rate_limited" | "error".
pub struct SmokeResult {
    pub adapter_name: String,
    pub status: String,
    pub detail: String,
}

impl SmokeResult {
    pub fn to_jval(&self) -> JVal {
        JVal::obj(vec![
            ("adapter", JVal::Str(self.adapter_name.clone())),
            ("status", JVal::Str(self.status.clone())),
            ("detail", JVal::Str(self.detail.clone())),
        ])
    }

    pub fn to_line(&self) -> String {
        let mark = match self.status.as_str() {
            "ok" => "OK",
            "auth_failed" => "AUTH FAILED",
            "rate_limited" => "RATE LIMITED",
            _ => "ERROR",
        };
        format!("[{mark}] {}: {}", self.adapter_name, self.detail)
    }
}

/// Turn one adapter response into a `SmokeResult`. Pure; no network.
pub fn classify(adapter_name: &str, response: &str) -> SmokeResult {
    let mk = |status: &str, detail: String| SmokeResult {
        adapter_name: adapter_name.to_string(),
        status: status.to_string(),
        detail,
    };
    if response.starts_with(ERROR_PREFIX) {
        let lowered = response.to_lowercase();
        if lowered.contains("401") || lowered.contains("403") || lowered.contains("unauthorized") {
            return mk(
                "auth_failed",
                "key rejected — check the key and its permissions".to_string(),
            );
        }
        if lowered.contains("429") || (lowered.contains("rate") && lowered.contains("limit")) {
            return mk(
                "rate_limited",
                "provider throttled the call — back off, try later".to_string(),
            );
        }
        // Python: response[:120] — code points, not bytes.
        let head: String = response.chars().take(120).collect();
        return mk("error", format!("transport/api failure: {head}"));
    }
    // Python: response.strip().replace("\n", " ")[:80], then repr().
    let snippet: String = response
        .trim()
        .replace('\n', " ")
        .chars()
        .take(80)
        .collect();
    mk("ok", format!("model answered: {}", py_repr_str(&snippet)))
}

/// Run the canary through one adapter. Never raises (adapter contract).
/// The mock answers fixtures by id, so it gets `generate_for("SMOKE")` —
/// the port of the `getattr(adapter, "generate_for", None)` branch.
pub fn smoke_test(adapter: &Adapter) -> SmokeResult {
    let response = match adapter.generate_for_mock("SMOKE") {
        Some(r) => r,
        None => adapter.generate(CANARY),
    };
    classify(&adapter.name(), &response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MockAdapter;

    #[test]
    fn classify_ok_path_matches_python() {
        let r = classify("mock", "ok");
        assert_eq!(r.status, "ok");
        assert_eq!(r.detail, "model answered: 'ok'");
        assert_eq!(r.to_line(), "[OK] mock: model answered: 'ok'");
    }

    #[test]
    fn classify_auth_failed_on_401_403_unauthorized() {
        for resp in [
            "[injectlab transport error: Http401]",
            "[injectlab transport error: Http403]",
            "[injectlab transport error: Unauthorized]",
        ] {
            let r = classify("openrouter:m", resp);
            assert_eq!(r.status, "auth_failed", "{resp}");
            assert_eq!(
                r.to_line(),
                "[AUTH FAILED] openrouter:m: key rejected — check the key and its permissions"
            );
        }
    }

    #[test]
    fn classify_rate_limited_on_429() {
        let r = classify("hf:m", "[injectlab transport error: Http429]");
        assert_eq!(r.status, "rate_limited");
        assert_eq!(
            r.to_line(),
            "[RATE LIMITED] hf:m: provider throttled the call — back off, try later"
        );
    }

    #[test]
    fn classify_generic_transport_error_truncates_at_120_chars() {
        let resp = format!("[injectlab transport error: {}]", "x".repeat(200));
        let r = classify("a", &resp);
        assert_eq!(r.status, "error");
        assert!(r.detail.starts_with("transport/api failure: [injectlab transport error: "));
        // 120 code points of the response, not 120 bytes.
        assert_eq!(r.detail.chars().count(), "transport/api failure: ".len() + 120);
    }

    #[test]
    fn smoke_test_mock_uses_the_smoke_fixture() {
        let adapter = Adapter::Mock(MockAdapter::with_extra("SMOKE", "ok"));
        let r = smoke_test(&adapter);
        assert_eq!(r.status, "ok");
        assert_eq!(r.adapter_name, "mock");
        let doc = crate::pyjson::dumps(&JVal::arr(vec![r.to_jval()]));
        assert!(doc.contains("\"status\": \"ok\""));
    }
}
