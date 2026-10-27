//! In-process "does `<provider>` user `<subject>` publish this SSH key?"
//! resolver, ported from ZBTerm `engine/identity/resolver.js` — the *cache
//! semantics* only (TTLs, in-flight dedupe, cache-first, stale-on-failure).
//!
//! ZBTerm's worker has no HTTP client, so `resolver.js` round-trips every
//! lookup across the shell seam (`identity:resolve-request` /
//! `identity.resolveResult`) and its `pending`/`inflight` maps exist mostly
//! to manage that round trip (request ids, per-request timers, `close()`
//! rejecting outstanding seam requests). This core resolves in-process — the
//! seam disappears with K9 — so this module calls its `fetch` closure
//! directly instead of emitting an event, and dedupes concurrent callers
//! with a `Mutex`/`Condvar` rather than a promise map. `DEFAULT_TIMEOUT_MS`
//! is kept only for parity/documentation: with no seam round trip to bound,
//! nothing here applies it (the underlying fetch — `identity::github` for
//! the `github` provider — already carries its own request timeout).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::github::{self, PublishedKey};
use super::providers::{self, GITHUB};
use super::store::IdentityStore;
use crate::error::{Code, Error};

/// `POSITIVE_TTL_MS` (resolver.js): `6 * 60 * 60 * 1000`.
pub const POSITIVE_TTL_MS: u64 = 6 * 60 * 60 * 1000;
/// `NEGATIVE_TTL_MS` (resolver.js): `10 * 60 * 1000`.
pub const NEGATIVE_TTL_MS: u64 = 10 * 60 * 1000;
/// `DEFAULT_TIMEOUT_MS` (resolver.js) — see this module's doc comment: kept
/// for parity, not applied to anything in-process.
pub const DEFAULT_TIMEOUT_MS: u64 = 10000;
/// `STATUSES` (resolver.js).
const STATUSES: [&str; 2] = ["ok", "not-found"];

/// Where a `ResolveAnswer` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A fresh cache hit, no fetch attempted.
    Cache,
    /// The fetch failed but a (possibly stale) cache entry was served
    /// instead — never a refusal.
    CacheStale,
    /// A fetch just succeeded.
    Remote,
}

/// `resolve`'s resolved shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveAnswer {
    pub status: String,
    pub keys: Vec<PublishedKey>,
    pub fetched_at: u64,
    pub source: Source,
}

/// What a `fetch` closure returns: the raw provider answer, before TTL/cache
/// bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchAnswer {
    pub status: String,
    pub keys: Vec<PublishedKey>,
}

type FetchFn = dyn Fn(&str, &str) -> Result<FetchAnswer, Error> + Send + Sync;
type NowFn = dyn Fn() -> u64 + Send + Sync;

fn default_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// `fetchImpl` bypasses the shell seam entirely (resolver.js) — here, the
/// *only* fetch path, since there is no seam. Only `github` needs one in
/// v1 (`needsResolver`); any other provider id reaching this is a
/// programming error upstream (the registry never sets `needsResolver` for
/// `unknown`).
fn default_fetch(provider: &str, subject: &str) -> Result<FetchAnswer, Error> {
    match provider {
        GITHUB => {
            let answer = github::fetch_keys(subject, None, None)?;
            Ok(FetchAnswer {
                status: answer.status,
                keys: answer.keys,
            })
        }
        other => Err(Error::new(
            Code::ENet,
            format!("identity resolver has no fetch implementation for provider: {other}"),
        )),
    }
}

/// Options for `IdentityResolver::new`. Every field defaults as
/// `resolver.js`'s constructor does.
#[derive(Default)]
pub struct ResolverOptions {
    pub store: Option<IdentityStore>,
    pub positive_ttl_ms: Option<u64>,
    pub negative_ttl_ms: Option<u64>,
    pub now: Option<Box<NowFn>>,
    pub fetch: Option<Box<FetchFn>>,
}

struct Inflight {
    done: Mutex<Option<Result<ResolveAnswer, Error>>>,
    cond: Condvar,
}

/// `IdentityResolver` (resolver.js) — see this module's doc comment for what
/// changed in the in-process port.
pub struct IdentityResolver {
    store: Option<IdentityStore>,
    positive_ttl_ms: u64,
    negative_ttl_ms: u64,
    now: Box<NowFn>,
    fetch: Box<FetchFn>,
    inflight: Mutex<HashMap<String, Arc<Inflight>>>,
    closed: AtomicBool,
}

impl IdentityResolver {
    pub fn new(opts: ResolverOptions) -> Self {
        IdentityResolver {
            store: opts.store,
            positive_ttl_ms: opts.positive_ttl_ms.unwrap_or(POSITIVE_TTL_MS),
            negative_ttl_ms: opts.negative_ttl_ms.unwrap_or(NEGATIVE_TTL_MS),
            now: opts.now.unwrap_or_else(|| Box::new(default_now_ms)),
            fetch: opts.fetch.unwrap_or_else(|| Box::new(default_fetch)),
            inflight: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        }
    }

    /// `resolve(provider, subject)` (resolver.js), `refresh: false`.
    pub fn resolve(&self, provider: &str, subject: &str) -> Result<ResolveAnswer, Error> {
        self.resolve_with_refresh(provider, subject, false)
    }

    /// `resolve(provider, subject, {refresh: true})` (resolver.js): skips
    /// the fresh-cache short circuit and dedupes under its own
    /// `#refresh`-suffixed key, so a refresh never joins — and is never
    /// satisfied by — a plain lookup already in flight.
    pub fn resolve_with_refresh(
        &self,
        provider: &str,
        subject: &str,
        refresh: bool,
    ) -> Result<ResolveAnswer, Error> {
        let entry = providers::get_provider(provider)?;
        let normalized = entry.validate_subject(Some(subject))?;
        let key = if refresh {
            format!("{}/{normalized}#refresh", entry.id)
        } else {
            format!("{}/{normalized}", entry.id)
        };

        // Concurrent callers for the same key share one in-flight result
        // (resolver.js's `inflight` map, one promise per key).
        if let Some(existing) = self.inflight.lock().unwrap().get(&key).cloned() {
            return wait_for(&existing);
        }

        let inflight_entry = Arc::new(Inflight {
            done: Mutex::new(None),
            cond: Condvar::new(),
        });
        {
            let mut map = self.inflight.lock().unwrap();
            if let Some(existing) = map.get(&key).cloned() {
                drop(map);
                return wait_for(&existing);
            }
            map.insert(key.clone(), inflight_entry.clone());
        }

        let result = self.resolve_uncached(entry.id, &normalized, refresh);

        {
            let mut done = inflight_entry.done.lock().unwrap();
            *done = Some(result.clone());
            inflight_entry.cond.notify_all();
        }
        {
            let mut map = self.inflight.lock().unwrap();
            if map
                .get(&key)
                .is_some_and(|cur| Arc::ptr_eq(cur, &inflight_entry))
            {
                map.remove(&key);
            }
        }
        result
    }

    fn resolve_uncached(
        &self,
        provider: &str,
        subject: &str,
        refresh: bool,
    ) -> Result<ResolveAnswer, Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::new(Code::ENet, "ZBTerm engine is shutting down"));
        }
        let cached = self.read_cache(provider, subject);
        if let Some(record) = &cached
            && !refresh
            && !self.is_stale(record)
        {
            return Ok(ResolveAnswer {
                status: record.status.clone(),
                keys: record.keys.clone(),
                fetched_at: record.fetched_at,
                source: Source::Cache,
            });
        }

        match (self.fetch)(provider, subject).and_then(normalize_answer) {
            Ok(answer) => {
                let fetched_at = (self.now)();
                self.write_cache(provider, subject, &answer, fetched_at);
                Ok(ResolveAnswer {
                    status: answer.status,
                    keys: answer.keys,
                    fetched_at,
                    source: Source::Remote,
                })
            }
            Err(err) => match cached {
                // A live lookup failed. A stale answer is better than none —
                // reported via `source`, never a refusal.
                Some(record) => Ok(ResolveAnswer {
                    status: record.status,
                    keys: record.keys,
                    fetched_at: record.fetched_at,
                    source: Source::CacheStale,
                }),
                None => Err(err),
            },
        }
    }

    fn is_stale(&self, record: &super::store::ProviderCacheRecord) -> bool {
        let ttl = if record.status == "not-found" {
            self.negative_ttl_ms
        } else {
            self.positive_ttl_ms
        };
        let now = (self.now)();
        if record.fetched_at > now {
            // A future-dated entry is never "fresh" (mirrors resolver.js's
            // `age >= 0` check).
            return true;
        }
        (now - record.fetched_at) >= ttl
    }

    fn read_cache(
        &self,
        provider: &str,
        subject: &str,
    ) -> Option<super::store::ProviderCacheRecord> {
        self.store
            .as_ref()?
            .read_provider_cache(provider, subject)
            .ok()?
    }

    fn write_cache(&self, provider: &str, subject: &str, answer: &FetchAnswer, fetched_at: u64) {
        if let Some(store) = &self.store {
            let _ = store.write_provider_cache(
                provider,
                subject,
                &answer.status,
                &answer.keys,
                fetched_at,
            );
        }
    }

    /// `close` (resolver.js). No async work outstanding in this in-process
    /// port can be preempted mid-flight, so this only makes every *later*
    /// `resolve` (including one that would otherwise have deduped onto an
    /// in-flight call) fail immediately, rather than rejecting a call
    /// already running on another thread.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// A trait so `verify::verify_peer_identity` can take either a real
/// `IdentityResolver` or a test stub.
pub trait Resolve {
    fn resolve(&self, provider: &str, subject: &str) -> Result<ResolveAnswer, Error>;
}

impl Resolve for IdentityResolver {
    fn resolve(&self, provider: &str, subject: &str) -> Result<ResolveAnswer, Error> {
        IdentityResolver::resolve(self, provider, subject)
    }
}

fn wait_for(entry: &Arc<Inflight>) -> Result<ResolveAnswer, Error> {
    let mut guard = entry.done.lock().unwrap();
    while guard.is_none() {
        guard = entry.cond.wait(guard).unwrap();
    }
    guard.clone().expect("guarded by the while loop above")
}

/// `normalizeAnswer` (resolver.js): rejects an unknown status outright
/// (never cached).
fn normalize_answer(answer: FetchAnswer) -> Result<FetchAnswer, Error> {
    if !STATUSES.contains(&answer.status.as_str()) {
        return Err(Error::new(
            Code::ENet,
            format!(
                "Identity key lookup returned an unknown status: {}",
                answer.status
            ),
        ));
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;

    fn temp_store() -> (zxterm_testkit::ScratchHome, IdentityStore) {
        let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
        let store = IdentityStore::new(home.path().join("account").join("identity"));
        store.ready().expect("ready");
        (home, store)
    }

    fn key(n: u8) -> PublishedKey {
        PublishedKey {
            key_type: "ssh-ed25519".into(),
            blob_base64: format!("AAAA{n}"),
            fingerprint: format!("SHA256:{n}"),
        }
    }

    #[test]
    fn a_remote_answer_is_cached_and_a_fresh_resolver_serves_it_without_fetching() {
        let (_home, store) = temp_store();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let k = key(1);
        let k_clone = k.clone();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store.clone()),
            fetch: Some(Box::new(move |_p, _s| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(FetchAnswer {
                    status: "ok".into(),
                    keys: vec![k_clone.clone()],
                })
            })),
            ..Default::default()
        });

        let remote = resolver.resolve("github", "Octocat").expect("resolve");
        assert_eq!(remote.status, "ok");
        assert_eq!(remote.source, Source::Remote);
        assert_eq!(remote.keys, vec![k.clone()]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let second_store = IdentityStore::new(store.root().to_path_buf());
        let second_calls = Arc::new(AtomicUsize::new(0));
        let second_calls_clone = second_calls.clone();
        let fresh = IdentityResolver::new(ResolverOptions {
            store: Some(second_store),
            fetch: Some(Box::new(move |_p, _s| {
                second_calls_clone.fetch_add(1, Ordering::SeqCst);
                panic!("a fresh resolver over the same dir must not fetch");
            })),
            ..Default::default()
        });
        let cached = fresh.resolve("github", "octocat").expect("resolve cached");
        assert_eq!(cached.source, Source::Cache);
        assert_eq!(cached.keys, vec![k]);
        assert_eq!(second_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_positive_entry_past_its_ttl_is_refetched() {
        let (_home, store) = temp_store();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let k = key(1);
        let k_clone = k.clone();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store),
            positive_ttl_ms: Some(0),
            fetch: Some(Box::new(move |_p, _s| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(FetchAnswer {
                    status: "ok".into(),
                    keys: vec![k_clone.clone()],
                })
            })),
            ..Default::default()
        });
        resolver
            .resolve("github", "octocat")
            .expect("first resolve");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let again = resolver
            .resolve("github", "octocat")
            .expect("second resolve");
        assert_eq!(again.source, Source::Remote);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn refresh_ignores_a_fresh_cache_entry_and_rewrites_it() {
        let (_home, store) = temp_store();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let extra = Arc::new(Mutex::new(false));
        let extra_clone = extra.clone();
        let base = key(1);
        let added = key(2);
        let base_clone = base.clone();
        let added_clone = added.clone();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store),
            fetch: Some(Box::new(move |_p, _s| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                let mut keys = vec![base_clone.clone()];
                if *extra_clone.lock().unwrap() {
                    keys.push(added_clone.clone());
                }
                Ok(FetchAnswer {
                    status: "ok".into(),
                    keys,
                })
            })),
            ..Default::default()
        });

        resolver.resolve("github", "octocat").expect("first");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let cached = resolver.resolve("github", "octocat").expect("cached");
        assert_eq!(cached.source, Source::Cache);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        *extra.lock().unwrap() = true;
        let forced = resolver
            .resolve_with_refresh("github", "octocat", true)
            .expect("refresh");
        assert_eq!(forced.source, Source::Remote);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(forced.keys, vec![base, added]);
    }

    #[test]
    fn a_not_found_answer_is_negatively_cached_for_its_own_ttl() {
        let (_home, store) = temp_store();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store),
            fetch: Some(Box::new(move |_p, _s| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(FetchAnswer {
                    status: "not-found".into(),
                    keys: vec![],
                })
            })),
            ..Default::default()
        });
        let missing = resolver.resolve("github", "ghost").expect("resolve");
        assert_eq!(missing.status, "not-found");
        assert_eq!(missing.source, Source::Remote);
        let cached = resolver.resolve("github", "ghost").expect("resolve again");
        assert_eq!(cached.source, Source::Cache);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_negative_entry_past_its_ttl_is_refetched() {
        let (_home, store) = temp_store();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store),
            negative_ttl_ms: Some(0),
            fetch: Some(Box::new(move |_p, _s| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(FetchAnswer {
                    status: "not-found".into(),
                    keys: vec![],
                })
            })),
            ..Default::default()
        });
        resolver.resolve("github", "ghost").expect("first");
        std::thread::sleep(std::time::Duration::from_millis(5));
        resolver.resolve("github", "ghost").expect("second");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_resolves_for_the_same_subject_share_one_fetch() {
        let (_home, store) = temp_store();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let k = key(1);
        let k_clone = k.clone();
        let resolver = Arc::new(IdentityResolver::new(ResolverOptions {
            store: Some(store),
            fetch: Some(Box::new(move |_p, _s| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(30));
                Ok(FetchAnswer {
                    status: "ok".into(),
                    keys: vec![k_clone.clone()],
                })
            })),
            ..Default::default()
        }));
        let barrier = Arc::new(Barrier::new(2));

        let r1 = resolver.clone();
        let b1 = barrier.clone();
        let t1 = std::thread::spawn(move || {
            b1.wait();
            r1.resolve("github", "octocat")
        });
        let r2 = resolver.clone();
        let b2 = barrier.clone();
        let t2 = std::thread::spawn(move || {
            b2.wait();
            r2.resolve("github", "octocat")
        });
        let a = t1.join().unwrap().expect("resolve 1");
        let b = t2.join().unwrap().expect("resolve 2");
        assert_eq!(a.keys, vec![k.clone()]);
        assert_eq!(b.keys, vec![k]);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one fetch for two concurrent resolves"
        );
        assert!(resolver.inflight.lock().unwrap().is_empty());
    }

    #[test]
    fn a_fetch_failure_with_no_cache_propagates_the_error() {
        let (_home, store) = temp_store();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store),
            fetch: Some(Box::new(|_p, _s| {
                Err(Error::new(Code::ENet, "github responded with HTTP 503"))
            })),
            ..Default::default()
        });
        let err = resolver.resolve("github", "octocat").unwrap_err();
        assert_eq!(err.code, Code::ENet);
        assert!(err.message.contains("HTTP 503"));
        assert!(resolver.inflight.lock().unwrap().is_empty());
        // A second attempt tries the fetch again rather than caching the
        // failure.
        let err2 = resolver.resolve("github", "octocat").unwrap_err();
        assert!(err2.message.contains("HTTP 503"));
    }

    #[test]
    fn a_stale_entry_is_served_when_the_live_lookup_fails() {
        let (_home, store) = temp_store();
        let k = key(1);
        let k_clone = k.clone();
        let good = IdentityResolver::new(ResolverOptions {
            store: Some(store.clone()),
            positive_ttl_ms: Some(0),
            fetch: Some(Box::new(move |_p, _s| {
                Ok(FetchAnswer {
                    status: "ok".into(),
                    keys: vec![k_clone.clone()],
                })
            })),
            ..Default::default()
        });
        good.resolve("github", "octocat").expect("prime cache");
        std::thread::sleep(std::time::Duration::from_millis(5));

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let broken = IdentityResolver::new(ResolverOptions {
            store: Some(store),
            positive_ttl_ms: Some(0),
            fetch: Some(Box::new(move |_p, _s| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Err(Error::new(Code::ENet, "offline"))
            })),
            ..Default::default()
        });
        let stale = broken.resolve("github", "octocat").expect("stale serve");
        assert_eq!(stale.source, Source::CacheStale);
        assert_eq!(stale.status, "ok");
        assert_eq!(stale.keys, vec![k]);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "it did try the network first"
        );
    }

    #[test]
    fn fetch_bypasses_the_store_entirely_when_no_store_is_configured() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let k = key(1);
        let k_clone = k.clone();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: None,
            fetch: Some(Box::new(move |p, s| {
                assert_eq!(p, "github");
                assert_eq!(s, "octocat");
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(FetchAnswer {
                    status: "ok".into(),
                    keys: vec![k_clone.clone()],
                })
            })),
            ..Default::default()
        });
        let result = resolver.resolve("github", "octocat").expect("resolve");
        assert_eq!(result.source, Source::Remote);
        assert_eq!(result.keys, vec![k]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_malformed_answer_is_rejected_rather_than_cached() {
        let (_home, store) = temp_store();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store.clone()),
            fetch: Some(Box::new(|_p, _s| {
                Ok(FetchAnswer {
                    status: "maybe".into(),
                    keys: vec![],
                })
            })),
            ..Default::default()
        });
        let err = resolver.resolve("github", "octocat").unwrap_err();
        assert!(err.message.contains("unknown status"));
        assert!(
            store
                .read_provider_cache("github", "octocat")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn close_makes_every_later_resolve_fail_immediately() {
        let (_home, store) = temp_store();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store),
            fetch: Some(Box::new(|_p, _s| {
                panic!("closed resolver must not fetch");
            })),
            ..Default::default()
        });
        resolver.close();
        let err = resolver.resolve("github", "octocat").unwrap_err();
        assert!(err.message.contains("shutting down"));
    }

    #[test]
    fn an_unknown_provider_or_invalid_subject_is_refused_before_any_fetch() {
        let (_home, store) = temp_store();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let resolver = IdentityResolver::new(ResolverOptions {
            store: Some(store),
            fetch: Some(Box::new(move |_p, _s| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                panic!("must not be called");
            })),
            ..Default::default()
        });
        assert!(resolver.resolve("gitlab", "octocat").is_err());
        assert!(resolver.resolve("github", "../../etc").is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
