//! Minimal JSON-RPC over HTTPS (blocking; call it from a background thread).

use std::time::Duration;

use serde_json::{json, Value};

use crate::TxError;

pub fn json_rpc(url: &str, method: &str, params: Value) -> Result<Value, TxError> {
    let url = url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")) {
        return Err(TxError::Input("RPC URL must use https:// (plain http is only allowed for localhost)".into()));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(25)))
        .http_status_as_error(false)
        .build()
        .into();
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let mut resp = agent
        .post(url)
        .send_json(&body)
        .map_err(|e| TxError::Network(format!("couldn't reach the RPC ({e})")))?;
    let status = resp.status().as_u16();
    let v: Value = resp
        .body_mut()
        .read_json()
        .map_err(|_| TxError::Network(format!("RPC answered HTTP {status} without JSON")))?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        let msg = err["message"].as_str().map(String::from).unwrap_or_else(|| err.to_string());
        return Err(TxError::Rpc(msg));
    }
    v.get("result").cloned().ok_or_else(|| TxError::Rpc(format!("{method}: response has no result")))
}
