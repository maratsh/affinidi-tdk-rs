//! Per-IP rate limiting middleware using the governor crate.
//!
//! Applies a token bucket rate limiter keyed by client IP address.
//! Configurable via `rate_limit_per_ip` and `rate_limit_burst` in LimitsConfig.

use axum::{
    body::Body,
    extract::ConnectInfo,
    response::{IntoResponse, Response},
};
use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock},
    state::keyed::DashMapStateStore,
};
use http::{HeaderValue, Request, StatusCode, header};
use ipnet::IpNet;
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
};
use tower::{Layer, Service};
use tracing::warn;

type KeyedLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

/// Is `ip` inside any of the trusted-proxy networks?
fn ip_is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

/// Resolve the client IP to rate-limit on, given the immediate socket `peer`, the
/// raw `X-Forwarded-For` header (if any), and the operator's `trusted` proxy set.
///
/// Security model — **never trust `X-Forwarded-For` blindly**:
/// - If `trusted` is empty, or the socket `peer` is NOT a trusted proxy, the peer
///   IP is used and XFF is ignored entirely. A client hitting the origin directly
///   (bypassing the CDN) therefore cannot spoof its rate-limit key.
/// - Only when the peer IS a trusted proxy do we consult XFF, walking the chain
///   **right-to-left** (nearest proxy first) and skipping entries that are
///   themselves trusted proxies; the first untrusted entry is the real client.
///   This is robust *provided the trusted edge appends* the observed client IP
///   (so an attacker-supplied value sits to the left and is never reached).
/// - Any malformed entry, or a chain of only-trusted entries, fails **safe** to
///   the peer IP (a shared bucket) — never to an attacker-chosen value.
pub(crate) fn resolve_client_ip(peer: IpAddr, xff: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    if trusted.is_empty() || !ip_is_trusted(peer, trusted) {
        return peer;
    }
    let Some(xff) = xff else { return peer };
    for hop in xff.rsplit(',') {
        let hop = hop.trim();
        match hop.parse::<IpAddr>() {
            Ok(ip) if ip_is_trusted(ip, trusted) => continue, // a proxy hop; keep walking left
            Ok(ip) => return ip,                              // first untrusted = client
            Err(_) => return peer,                            // malformed → fail safe to peer
        }
    }
    peer
}

/// Shared rate limiter state
#[derive(Clone)]
pub struct RateLimiterState {
    limiter: Option<Arc<KeyedLimiter>>,
    trusted_proxies: Arc<Vec<IpNet>>,
}

impl RateLimiterState {
    /// Create a new rate limiter. If `per_second` is 0, rate limiting is disabled.
    /// `trusted_proxies` gates `X-Forwarded-For` client-IP extraction (empty =
    /// socket-peer only).
    pub fn new(per_second: u32, burst: u32, trusted_proxies: Vec<IpNet>) -> Self {
        let trusted_proxies = Arc::new(trusted_proxies);
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Self {
                limiter: None,
                trusted_proxies,
            };
        };
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(per_second).allow_burst(burst);
        Self {
            limiter: Some(Arc::new(RateLimiter::keyed(quota))),
            trusted_proxies,
        }
    }
}

/// Tower Layer that applies per-IP rate limiting
#[derive(Clone)]
pub struct RateLimitLayer {
    state: RateLimiterState,
}

impl RateLimitLayer {
    pub fn new(state: RateLimiterState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Tower Service that checks the rate limiter before forwarding requests
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    state: RateLimiterState,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let Some(limiter) = &self.state.limiter else {
            // Rate limiting disabled
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await });
        };

        // Socket peer IP from ConnectInfo (the immediate hop — the CDN edge when
        // fronted by one).
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());

        let Some(peer) = peer else {
            warn!("No client IP available; rejecting request (rate limiting requires client IP)");
            return Box::pin(async move {
                Ok((
                    StatusCode::FORBIDDEN,
                    "Rate limiting requires client IP; request rejected.",
                )
                    .into_response())
            });
        };

        // Resolve the key: peer IP, unless a TRUSTED proxy fronted the request and
        // supplied a usable X-Forwarded-For (never trusted from an untrusted peer).
        // `x-forwarded-for` is non-standard, so not a `http::header` constant.
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());
        let ip = resolve_client_ip(peer, xff, &self.state.trusted_proxies);

        // Deploy-time diagnostic (DEBUG only): reveals the socket peer the origin
        // sees (the CDN edge, when fronted), the raw XFF the edge supplied, and the
        // resolved key. Used to discover bunny's edge IP range for `trusted_proxies`
        // and to confirm the edge appends a trustworthy XFF. Server-side log only.
        tracing::debug!(
            peer = %peer,
            xff = ?xff,
            trusted_proxies = self.state.trusted_proxies.len(),
            resolved_key = %ip,
            "per-IP rate-limit key resolution",
        );

        if let Err(not_until) = limiter.check_key(&ip) {
            warn!("Rate limit exceeded for IP: {}", ip);
            metrics::counter!(super::metrics::names::RATE_LIMITED_TOTAL).increment(1);
            // Accurate Retry-After: governor reports the instant the next token
            // is available; round up to whole seconds (min 1), per RFC 7231.
            let retry_after = not_until
                .wait_time_from(DefaultClock::default().now())
                .as_secs()
                .max(1);
            return Box::pin(async move {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Please try again later.",
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                Ok(response)
            });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn nets(cidrs: &[&str]) -> Vec<IpNet> {
        cidrs.iter().map(|c| c.parse().unwrap()).collect()
    }

    #[test]
    fn no_trusted_proxies_uses_peer_and_ignores_xff() {
        // The default posture: an empty trust list means XFF is never consulted,
        // even if present — the socket peer is the key.
        let trusted = nets(&[]);
        assert_eq!(
            resolve_client_ip(ip("203.0.113.9"), Some("1.2.3.4"), &trusted),
            ip("203.0.113.9"),
        );
    }

    #[test]
    fn untrusted_peer_cannot_spoof_via_xff() {
        // Attacker hits the origin directly (peer not in the trusted CDN range)
        // and sets X-Forwarded-For to a victim IP — must be ignored.
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("203.0.113.9"), Some("198.51.100.7"), &trusted),
            ip("203.0.113.9"),
            "XFF from an untrusted peer must never be honored",
        );
    }

    #[test]
    fn trusted_peer_takes_appended_client_ip() {
        // The CDN edge (trusted) appends the real client IP as the rightmost hop.
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.1.2.3"), Some("198.51.100.7"), &trusted),
            ip("198.51.100.7"),
        );
    }

    #[test]
    fn trusted_peer_skips_trusted_hops_right_to_left() {
        // Chain: client, then two trusted proxy hops appended on the right.
        // Walk right-to-left, skip trusted, first untrusted = client.
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.9.9.9"), Some("198.51.100.7, 10.0.0.1, 10.0.0.2"), &trusted),
            ip("198.51.100.7"),
        );
    }

    #[test]
    fn attacker_prepended_value_is_never_reached() {
        // Attacker sets XFF to a victim IP; the trusted edge APPENDS the real
        // client to the right. Right-to-left resolution takes the real client and
        // never reaches the spoofed leftmost value.
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), Some("198.51.100.7, 203.0.113.42"), &trusted),
            ip("203.0.113.42"),
            "the appended (rightmost untrusted) client wins; spoofed left value ignored",
        );
    }

    #[test]
    fn malformed_xff_fails_safe_to_peer() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), Some("not-an-ip"), &trusted),
            ip("10.0.0.1"),
        );
    }

    #[test]
    fn trusted_peer_no_xff_uses_peer() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), None, &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn all_trusted_chain_falls_back_to_peer() {
        // Degenerate: every XFF entry is a trusted proxy → fail safe to peer
        // (a shared bucket) rather than to an attacker-chosen value.
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), Some("10.0.0.2, 10.0.0.3"), &trusted),
            ip("10.0.0.1"),
        );
    }

    #[test]
    fn ipv6_trusted_proxy_range_matches() {
        let trusted = nets(&["2001:db8::/32"]);
        assert_eq!(
            resolve_client_ip(ip("2001:db8::1"), Some("198.51.100.7"), &trusted),
            ip("198.51.100.7"),
        );
        // ...and an untrusted v6 peer cannot spoof.
        assert_eq!(
            resolve_client_ip(ip("2001:dead::1"), Some("198.51.100.7"), &trusted),
            ip("2001:dead::1"),
        );
    }
}
