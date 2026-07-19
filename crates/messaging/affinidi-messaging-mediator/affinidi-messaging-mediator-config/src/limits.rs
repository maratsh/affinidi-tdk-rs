//! Raw `[limits]` config schema.
//!
//! The resolved `LimitsConfig` (typed numbers) and the
//! `LimitsConfigRaw → LimitsConfig` conversion stay in the mediator.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsConfigRaw {
    pub attachments_max_count: String,
    pub crypto_operations_per_message: String,
    pub deleted_messages: String,
    pub forward_task_queue: String,
    pub http_size: String,
    pub listed_messages: String,
    pub local_max_acl: String,
    pub message_expiry_seconds: String,
    pub message_size: String,
    pub queued_send_messages_soft: String,
    pub queued_send_messages_hard: String,
    pub queued_receive_messages_soft: String,
    pub queued_receive_messages_hard: String,
    pub to_keys_per_recipient: String,
    pub to_recipients: String,
    pub ws_size: String,
    pub access_list_limit: String,
    pub oob_invite_ttl: String,
    #[serde(default = "default_rate_limit_per_ip")]
    pub rate_limit_per_ip: String,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: String,
    #[serde(default = "default_max_websocket_connections")]
    pub max_websocket_connections: String,
    #[serde(default = "default_max_websocket_connections_per_did")]
    pub max_websocket_connections_per_did: String,
    #[serde(default = "default_did_rate_limit_per_second")]
    pub did_rate_limit_per_second: String,
    #[serde(default = "default_did_rate_limit_burst")]
    pub did_rate_limit_burst: String,
    /// Comma/whitespace-separated CIDR list of TRUSTED reverse proxies (e.g. the
    /// bunny CDN edge range). `X-Forwarded-For` is honored for per-IP rate
    /// limiting ONLY when the immediate socket peer is inside one of these ranges;
    /// otherwise the socket peer IP is used and XFF is ignored. **Empty by default
    /// (never trust XFF blindly)** — leaving it empty preserves socket-peer-only
    /// behavior. Set it only after confirming the edge appends a trustworthy XFF.
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: String,
}

fn default_rate_limit_per_ip() -> String {
    "100".to_string()
}
fn default_rate_limit_burst() -> String {
    "50".to_string()
}
fn default_max_websocket_connections() -> String {
    "10000".to_string()
}
fn default_max_websocket_connections_per_did() -> String {
    "100".to_string()
}
fn default_did_rate_limit_per_second() -> String {
    "0".to_string()
}
fn default_did_rate_limit_burst() -> String {
    "10".to_string()
}
fn default_trusted_proxies() -> String {
    String::new()
}
