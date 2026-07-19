//! Per-DID rate limiting for authenticated endpoints.
//!
//! Unlike the per-IP rate limiter (which runs as Tower middleware), this limiter
//! operates at the application level because the DID is only known after JWT
//! validation. Handlers call `check()` with the authenticated DID hash to
//! determine whether the request should proceed.

use affinidi_messaging_sdk::protocols::mediator::accounts::AccountType;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use std::{num::NonZeroU32, sync::Arc};

/// Whether the per-DID rate limiter should be consulted for a session.
///
/// Two classes of session are EXEMPT (see `handle_inbound`):
/// - **Admin/RootAdmin/Mediator** (`AccountType::is_admin`) — the reconcile
///   wrapper issues bursts of short-TTL (~3s) admin messages on boot replay;
///   throttling them would let the messages expire and break provisioning.
/// - **Empty `did_hash`** — the anonymous inter-mediator relay session
///   (`ANON-INBOUND`) carries no DID; keying a per-DID limiter on `""` would
///   pool all relay/anonymous traffic into one bucket. That path is bounded by
///   per-IP limiting + relay-peer allow-listing + the recipient consent gate.
pub(crate) fn per_did_rate_limit_applies(account_type: AccountType, did_hash: &str) -> bool {
    !account_type.is_admin() && !did_hash.is_empty()
}

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

/// Application-level rate limiter keyed by DID hash.
#[derive(Clone)]
pub struct DidRateLimiter {
    limiter: Option<Arc<KeyedLimiter>>,
}

impl DidRateLimiter {
    /// Create a new per-DID rate limiter.
    ///
    /// If `per_second` is 0, rate limiting is disabled and `check()` always
    /// returns `true`.
    pub fn new(per_second: u32, burst: u32) -> Self {
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Self { limiter: None };
        };
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(per_second).allow_burst(burst);
        Self {
            limiter: Some(Arc::new(RateLimiter::keyed(quota))),
        }
    }

    /// Check whether the given DID hash is within its rate limit.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check(&self, did_hash: &str) -> bool {
        match &self.limiter {
            None => true,
            Some(limiter) => limiter.check_key(&did_hash.to_owned()).is_ok(),
        }
    }

    /// Drop rate-limit state for DIDs that have caught up (no longer rate-limited).
    ///
    /// The keyed store grows one entry per distinct DID hash, and under the
    /// open-but-hardened admission posture the key space is **attacker-controlled**
    /// (any not-blocked DID auto-creates), so an unbounded store is a memory-DoS
    /// vector — precisely under the abuse this limiter exists to bound. A periodic
    /// call to this (see the sweep in `server.rs`) reclaims idle keys. No-op when
    /// rate limiting is disabled.
    pub fn retain_recent(&self) {
        if let Some(limiter) = &self.limiter {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
    }

    /// Number of DID keys currently tracked (0 when disabled). For observability
    /// of the keyed-store size (memory-DoS guard).
    pub fn len(&self) -> usize {
        self.limiter.as_ref().map(|l| l.len()).unwrap_or(0)
    }

    /// True when no keys are tracked (or rate limiting is disabled).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_limiter_always_allows() {
        let limiter = DidRateLimiter::new(0, 10);
        for _ in 0..1000 {
            assert!(limiter.check("did:example:123"));
        }
    }

    #[test]
    fn enabled_limiter_eventually_rejects() {
        // 1 request per second, burst of 2
        let limiter = DidRateLimiter::new(1, 2);
        let did = "did:example:456";

        // First two should succeed (burst)
        assert!(limiter.check(did));
        assert!(limiter.check(did));

        // Third should be rejected (burst exhausted, no time has passed)
        assert!(!limiter.check(did));
    }

    #[test]
    fn different_dids_have_independent_limits() {
        let limiter = DidRateLimiter::new(1, 1);

        assert!(limiter.check("did:example:aaa"));
        assert!(!limiter.check("did:example:aaa"));

        // Different DID should still be allowed
        assert!(limiter.check("did:example:bbb"));
    }

    #[test]
    fn retain_recent_bounds_the_keyed_store() {
        // High rate so every check passes and simply registers a key; the point
        // is the store must not grow without bound under many distinct DIDs.
        let limiter = DidRateLimiter::new(1_000_000, 1_000_000);
        for i in 0..500 {
            assert!(limiter.check(&format!("did:example:{i}")));
        }
        assert!(limiter.len() > 0, "keys should be tracked before reclaim");
        // All keys are immediately caught up (well under quota), so a reclaim
        // must be able to drop them — the memory-DoS guard.
        limiter.retain_recent();
        assert_eq!(
            limiter.len(),
            0,
            "retain_recent must reclaim idle keys (memory-DoS guard)"
        );
    }

    #[test]
    fn disabled_limiter_reports_empty_and_noops_retain() {
        let limiter = DidRateLimiter::new(0, 10);
        assert!(limiter.is_empty());
        assert_eq!(limiter.len(), 0);
        limiter.retain_recent(); // must not panic when disabled
        assert!(limiter.is_empty());
    }

    #[test]
    fn exemption_predicate_covers_admin_and_relay() {
        let some_hash = "abc123";
        // Admin tiers are exempt (provisioning safety) regardless of did_hash.
        assert!(!per_did_rate_limit_applies(AccountType::Admin, some_hash));
        assert!(!per_did_rate_limit_applies(AccountType::RootAdmin, some_hash));
        assert!(!per_did_rate_limit_applies(AccountType::Mediator, some_hash));
        // Anonymous relay session carries an empty did_hash → exempt.
        assert!(!per_did_rate_limit_applies(AccountType::Standard, ""));
        // A normal authenticated user IS subject to the limit.
        assert!(per_did_rate_limit_applies(AccountType::Standard, some_hash));
        // Unknown tier with a real DID is also subject to it (fail-closed to limited).
        assert!(per_did_rate_limit_applies(AccountType::Unknown, some_hash));
    }
}
