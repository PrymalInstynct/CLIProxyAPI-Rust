//! Quota transitions and bounded secure notification delivery, inside the proxy process.
mod delivery;
pub mod state;
mod store;

use crate::{
    accounts::{Account, Credential, Provider},
    config::Config as AppConfig,
    state::App,
};
use chrono::Utc;
use futures::{StreamExt, stream};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use state::{Event, Subscription};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use store::{Log, MAX_PENDING, Pending, Store};

fn yes() -> bool {
    true
}
fn https_port() -> u16 {
    443
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub secrets_dir: Option<String>,
    pub ca_file: Option<String>,
    pub private_endpoints: Vec<PrivateEndpoint>,
    pub destinations: Vec<Destination>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PrivateEndpoint {
    pub host: String,
    #[serde(default = "https_port")]
    pub port: u16,
    pub cidrs: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Destination {
    pub id: String,
    pub format: Format,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub chat_id: Option<String>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Generic,
    Discord,
    Slack,
    Mattermost,
    Teams,
    Telegram,
}
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && id.as_bytes()[0] != b'-'
        && id.as_bytes()[id.len() - 1] != b'-'
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.destinations.len() > 8 || self.private_endpoints.len() > 16 {
            return Err("notifications: too many destinations or private endpoints".into());
        }
        let mut ids = BTreeSet::new();
        for d in &self.destinations {
            if !valid_id(&d.id) || !ids.insert(&d.id) {
                return Err("notifications: invalid or duplicate destination ID".into());
            }
            if d.format == Format::Telegram
                && d.chat_id.as_deref().is_none_or(|s| {
                    s.is_empty()
                        || s.len() > 64
                        || !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'@'))
                })
            {
                return Err("notifications: Telegram requires a valid chat-id".into());
            }
            if d.chat_id.as_ref().is_some_and(|s| s.len() > 64) {
                return Err("notifications: chat-id too long".into());
            }
        }
        if self.secrets_dir.as_ref().is_some_and(|s| s.is_empty() || s.len() > 4096) {
            return Err("notifications: invalid secrets-dir".into());
        }
        if self.ca_file.as_ref().is_some_and(|s| s.is_empty() || s.len() > 4096) {
            return Err("notifications: invalid ca-file".into());
        }
        for entry in &self.private_endpoints {
            if entry.port == 0
                || entry.host.is_empty()
                || entry.host.len() > 253
                || !entry
                    .host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
                || entry.cidrs.is_empty()
                || entry.cidrs.len() > 16
            {
                return Err("notifications: invalid private endpoint".into());
            }
            for cidr in &entry.cidrs {
                let Some((ip, bits)) = cidr.split_once('/') else {
                    return Err("notifications: invalid private endpoint CIDR".into());
                };
                let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
                    return Err("notifications: invalid private endpoint CIDR".into());
                };
                let Ok(bits) = bits.parse::<u32>() else {
                    return Err("notifications: invalid private endpoint CIDR".into());
                };
                if bits == 0 || bits > if ip.is_ipv4() { 32 } else { 128 } {
                    return Err("notifications: invalid private endpoint CIDR".into());
                }
            }
        }
        Ok(())
    }
}
struct Inner {
    store: Option<Store>,
    error: Option<&'static str>,
    warning: Option<&'static str>,
    tests: BTreeMap<String, chrono::DateTime<Utc>>,
}
pub struct Service {
    inner: Mutex<Inner>,
    root: PathBuf,
    secrets: PathBuf,
    private_endpoints: Vec<PrivateEndpoint>,
    ca_file: Option<PathBuf>,
}
impl Service {
    pub fn new(cfg: &AppConfig) -> Self {
        let root = cfg.auth_dir();
        let secrets = cfg
            .notifications
            .secrets_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join(".notification-secrets"));
        Self {
            inner: Mutex::new(Inner { store: None, error: None, warning: None, tests: BTreeMap::new() }),
            root,
            secrets,
            private_endpoints: cfg.notifications.private_endpoints.clone(),
            ca_file: cfg.notifications.ca_file.as_ref().map(PathBuf::from),
        }
    }
    fn open(&self) -> Result<(), &'static str> {
        let mut inner = self.inner.lock();
        if inner.store.is_none() {
            match Store::open(&self.root) {
                Ok(store) => {
                    inner.store = Some(store);
                    inner.error = None;
                }
                Err(error) => {
                    inner.error = Some(error);
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    pub fn status(&self, app: &App) -> Value {
        let cfg = app.cfg();
        let inner = self.inner.lock();
        let destinations:Vec<_>=cfg.notifications.destinations.iter().map(|d|json!({"id":d.id,"format":d.format,"enabled":d.enabled,"credential_ready":delivery::credentials(&self.secrets,d).is_ok()})).collect();
        let mut supported = 0;
        let mut unsupported = 0;
        for account in app.pool.all() {
            if native(&account) { supported += 1 } else { unsupported += 1 }
        }
        json!({"enabled":cfg.notifications.enabled,"active":cfg.notifications.enabled&&inner.store.is_some()&&inner.error.is_none(),"error":inner.error,"warning":inner.warning,"pending":inner.store.as_ref().map_or(0,|s|s.journal.pending.len()),"destinations":destinations,"logs":inner.store.as_ref().map(|s|&s.journal.logs),"capabilities":{"supported":supported,"unsupported":unsupported},"private_endpoints_restart_required":true})
    }
    pub async fn test(&self, app: &App, id: &str) -> Result<Value, &'static str> {
        let cfg = app.cfg();
        if !cfg.notifications.enabled {
            return Err("notifications_disabled");
        }
        let d = cfg
            .notifications
            .destinations
            .iter()
            .find(|d| d.id == id && d.enabled)
            .ok_or("destination_unavailable")?
            .clone();
        self.open()?;
        {
            let mut inner = self.inner.lock();
            if inner.tests.get(id).is_some_and(|at| (Utc::now() - *at).num_seconds() < 30) {
                return Err("test_rate_limited");
            }
            inner.tests.retain(|_, at| (Utc::now() - *at).num_seconds() < 30);
            inner.tests.insert(id.into(), Utc::now());
        }
        let event = Event {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            event: "notification.test".into(),
            subscription: "000000000000000000000000".into(),
            provider: "claude".into(),
            window: "test".into(),
            model: None,
            observed_at: Utc::now(),
            resets_at: None,
            used: None,
            remaining_blockers: Vec::new(),
        };
        let outcome = delivery::send(&self.secrets, &self.private_endpoints, self.ca_file.as_deref(), &d, &event).await;
        let mut inner = self.inner.lock();
        if let Some(store) = inner.store.as_mut() {
            store.log(log(&d.id, &event, 1, &outcome, false));
            store.save()?;
        }
        if outcome.success { Ok(json!({"delivered":true,"http_status":outcome.status})) } else { Err(outcome.reason) }
    }
    pub fn reset_due(&self, acct: &Account, now: chrono::DateTime<Utc>) -> bool {
        let inner = self.inner.lock();
        let Some(store) = &inner.store else {
            return false;
        };
        let id = identity(acct, &store.journal.installation);
        store.journal.subscriptions.get(&id).is_some_and(|s| {
            s.windows
                .values()
                .any(|w| w.exhausted && w.reset.is_some_and(|reset| reset + chrono::Duration::seconds(5) <= now))
        })
    }
}
fn native(acct: &Account) -> bool {
    matches!(acct.provider, Provider::Claude | Provider::Codex)
        && matches!(&*acct.cred.read(),Credential::OAuth(o) if o.base_url.is_none())
}
fn identity(acct: &Account, salt: &str) -> String {
    let cred = acct.cred.read();
    let provider = acct.provider.as_str();
    let key = match &*cred {
        Credential::OAuth(o) => o.account_id.as_deref().filter(|s| !s.is_empty()).unwrap_or(&acct.id),
        _ => &acct.id,
    };
    let mut hash = Sha256::new();
    for part in [salt, provider, key] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    hex::encode(hash.finalize())[..24].into()
}
fn log(destination: &str, event: &Event, attempt: u8, outcome: &delivery::Outcome, retrying: bool) -> Log {
    Log {
        timestamp: Utc::now(),
        destination: destination.into(),
        event: event.event.clone(),
        subscription: Some(event.subscription.clone()),
        window: Some(event.window.clone()),
        attempt,
        outcome: if outcome.success {
            "delivered"
        } else if retrying {
            "retrying"
        } else {
            "terminal_failure"
        }
        .into(),
        http_status: outcome.status,
        detail: outcome.reason.into(),
    }
}
pub async fn worker(app: Arc<App>) {
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    let mut ready = BTreeSet::new();
    let mut fresh_after: BTreeMap<String, chrono::DateTime<Utc>> = BTreeMap::new();
    let mut enabled_since = app.started;
    let mut was_enabled = false;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let cfg = app.cfg();
        if !cfg.notifications.enabled {
            seen.clear();
            ready.clear();
            was_enabled = false;
            continue;
        }
        if !was_enabled {
            enabled_since = app.started;
            was_enabled = true;
        }
        if app.notifications.open().is_err() {
            continue;
        }
        let salt = app.notifications.inner.lock().store.as_ref().unwrap().journal.installation.clone();
        let accounts: Vec<_> = app.pool.all().into_iter().filter(|a| native(a)).collect();
        let mut present = BTreeSet::new();
        let mut enabled = BTreeSet::new();
        let mut snapshots = Vec::new();
        let mut sources = BTreeMap::new();
        for acct in accounts {
            let id = identity(&acct, &salt);
            present.insert(id.clone());
            let key = format!("{}:{}", acct.id, id);
            let mut st = acct.state.lock();
            if st.disabled {
                ready.remove(&id);
                fresh_after.insert(id, Utc::now());
                continue;
            }
            enabled.insert(id.clone());
            let latest = st.notification_evidence.sequence;
            if seen.get(&key).is_some_and(|previous| *previous > latest) {
                seen.remove(&key);
                ready.remove(&id);
            }
            let observations: Vec<_> = st
                .notification_evidence
                .observations
                .iter()
                .filter(|o| o.sequence > *seen.get(&key).unwrap_or(&0))
                .cloned()
                .collect();
            let after = *fresh_after.get(&id).unwrap_or(&enabled_since);
            let confirmation_needed = {
                let inner = app.notifications.inner.lock();
                inner.store.as_ref().and_then(|s| s.journal.subscriptions.get(&id)).is_some_and(|s| {
                    observations.iter().filter(|o| !o.authoritative).flat_map(|o| &o.windows).any(|w| {
                        w.used < 100.0
                            && s.windows.values().any(|old| old.exhausted && old.name == w.name && old.model == w.model)
                    })
                })
            };
            if observations.iter().any(|o| o.at >= after) {
                ready.insert(id.clone());
            }
            if !ready.contains(&id) || st.notification_evidence.overflow || confirmation_needed {
                st.quota.refreshed_at = None;
            }
            snapshots.push((
                key.clone(),
                id,
                acct.provider.as_str().to_string(),
                observations,
                st.notification_evidence.overflow,
                after,
            ));
            sources.insert(key, acct.clone());
        }
        seen.retain(|key, _| sources.contains_key(key));
        ready.retain(|id| present.contains(id));
        fresh_after.retain(|id, _| present.contains(id));
        let mut acknowledged = Vec::new();
        let jobs = {
            let mut inner = app.notifications.inner.lock();
            if snapshots.iter().any(|(_, _, _, _, overflow, _)| *overflow) {
                inner.warning = Some("observation_history_overflow_reconciling");
            }
            let store = inner.store.as_mut().unwrap();
            let before = store.journal.clone();
            let mut capacity = false;
            let old_subs = store.journal.subscriptions.len();
            let old_pending = store.journal.pending.len();
            store.journal.subscriptions.retain(|id, _| present.contains(id));
            // A disabled destination pauses its outbox; removal cancels it.
            store.journal.pending.retain(|p| {
                present.contains(&p.event.subscription)
                    && cfg.notifications.destinations.iter().any(|d| d.id == p.destination)
            });
            let mut dirty = old_subs != store.journal.subscriptions.len() || old_pending != store.journal.pending.len();
            for (_, id, provider, observations, _, after) in &snapshots {
                if observations.is_empty() {
                    continue;
                }
                if !store.journal.subscriptions.contains_key(id) && store.journal.subscriptions.len() >= 4096 {
                    capacity = true;
                    break;
                }
                let subscription = store
                    .journal
                    .subscriptions
                    .entry(id.clone())
                    .or_insert_with(|| Subscription { provider: provider.clone(), ..Default::default() });
                let mut events = Vec::new();
                for observation in observations.iter().filter(|o| o.at >= *after) {
                    events.extend(subscription.apply(id, observation));
                    dirty = true;
                }
                for event in events {
                    for d in cfg.notifications.destinations.iter().filter(|d| d.enabled) {
                        if store.journal.pending.len() >= MAX_PENDING {
                            capacity = true;
                            break;
                        }
                        store.journal.pending.push_back(Pending {
                            destination: d.id.clone(),
                            event: event.clone(),
                            attempt: 0,
                            next: Utc::now(),
                        });
                    }
                }
            }
            let mut cancelled = Vec::new();
            store.journal.pending.retain(|p| {
                let stale = store.journal.subscriptions.get(&p.event.subscription).is_some_and(|s| {
                    match p.event.event.as_str() {
                        "quota.exhausted" => !s
                            .windows
                            .values()
                            .any(|w| w.exhausted && w.name == p.event.window && w.model == p.event.model),
                        "quota.available" => s.windows.values().any(|w| w.exhausted),
                        "quota.window_recovered" => s
                            .windows
                            .values()
                            .any(|w| w.exhausted && w.name == p.event.window && w.model == p.event.model),
                        _ => false,
                    }
                });
                let expired = (Utc::now() - p.event.observed_at).num_hours() >= 48;
                if stale || expired {
                    cancelled.push(Log {
                        timestamp: Utc::now(),
                        destination: p.destination.clone(),
                        event: p.event.event.clone(),
                        subscription: Some(p.event.subscription.clone()),
                        window: Some(p.event.window.clone()),
                        attempt: p.attempt,
                        outcome: if expired { "expired" } else { "cancelled" }.into(),
                        http_status: None,
                        detail: if expired { "retention_expired" } else { "superseded" }.into(),
                    });
                    false
                } else {
                    true
                }
            });
            dirty |= !cancelled.is_empty();
            for entry in cancelled {
                store.log(entry);
            }
            let persistence = if capacity {
                Err("outbox_capacity_exceeded")
            } else if dirty {
                store.save()
            } else {
                Ok(())
            };
            if let Err(error) = persistence {
                store.journal = before;
                inner.error = Some(error);
            } else {
                for (account, _, _, observations, _, _) in &snapshots {
                    if let Some(last) = observations.last() {
                        seen.insert(account.clone(), last.sequence);
                        acknowledged.push((account.clone(), last.sequence));
                    }
                }
                inner.error = None;
            }
            // Existing durable jobs may drain even while new observations exceed capacity.
            let store = inner.store.as_ref().unwrap();
            let mut blocked = BTreeSet::new();
            let mut jobs = Vec::new();
            for p in &store.journal.pending {
                if !blocked.insert((p.destination.clone(), p.event.subscription.clone())) {
                    continue;
                }
                if jobs.len() == 4 {
                    break;
                }
                if p.next <= Utc::now()
                    && enabled.contains(&p.event.subscription)
                    && ready.contains(&p.event.subscription)
                    && let Some(destination) =
                        cfg.notifications.destinations.iter().find(|d| d.id == p.destination && d.enabled)
                {
                    jobs.push((p.clone(), destination.clone()));
                }
            }
            jobs
        };
        for (key, through) in acknowledged {
            if let Some(acct) = sources.get(&key) {
                let mut st = acct.state.lock();
                st.notification_evidence.observations.retain(|o| o.sequence > through);
                st.notification_evidence.overflow = false;
            }
        }
        // Requests run independently, bounded to four, and retain per-destination/subscription order.
        let results: Vec<_> = stream::iter(jobs)
            .map(|(p, d)| {
                let app = app.clone();
                async move {
                    let service = &app.notifications;
                    // A config change can pause a queued job before its network request starts.
                    let live = app.cfg();
                    let outcome = if live.notifications.enabled
                        && live.notifications.destinations.iter().any(|entry| entry.id == d.id && entry.enabled)
                    {
                        delivery::send(
                            &service.secrets,
                            &service.private_endpoints,
                            service.ca_file.as_deref(),
                            &d,
                            &p.event,
                        )
                        .await
                    } else {
                        delivery::Outcome {
                            success: false,
                            retry: true,
                            status: None,
                            reason: "paused",
                            retry_after: Some(30),
                        }
                    };
                    (p, outcome)
                }
            })
            .buffer_unordered(4)
            .collect()
            .await;
        if !results.is_empty() {
            let mut inner = app.notifications.inner.lock();
            let store = inner.store.as_mut().unwrap();
            let before = store.journal.clone();
            for (job, outcome) in results {
                if outcome.reason == "paused" {
                    continue;
                }
                let Some(index) = store
                    .journal
                    .pending
                    .iter()
                    .position(|p| p.destination == job.destination && p.event.id == job.event.id)
                else {
                    continue;
                };
                let attempt = job.attempt.saturating_add(1);
                let retry = outcome.retry && attempt < 8;
                store.log(log(&job.destination, &job.event, attempt, &outcome, retry));
                if retry {
                    let pending = &mut store.journal.pending[index];
                    pending.attempt = attempt;
                    let delay = outcome.retry_after.unwrap_or((15i64 << attempt.min(7)).min(3600))
                        + i64::from(rand::random::<u8>() % 11);
                    pending.next = Utc::now() + chrono::Duration::seconds(delay);
                } else {
                    store.journal.pending.remove(index);
                }
            }
            if let Err(error) = store.save() {
                store.journal = before;
                inner.error = Some(error);
            }
            app.broadcast("notifications", Value::Null);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("notifications-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn fixture(enabled: bool) -> (Temp, Arc<App>, Arc<Account>) {
        let temp = Temp::new();
        std::fs::write(temp.0.join("account.json"),json!({"type":"claude","account_id":"private-provider-account","email":"private-email-sentinel@example.test","access_token":"private-oauth-sentinel","expired":"2099-01-01T00:00:00Z"}).to_string()).unwrap();
        let cfg = AppConfig {
            auth_dir: temp.0.to_string_lossy().into(),
            notifications: Config {
                enabled,
                destinations: vec![Destination {
                    id: format!("test-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]),
                    format: Format::Generic,
                    enabled: true,
                    chat_id: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let app = App::new(cfg, temp.0.join("config.yaml"));
        let acct = app.pool.all()[0].clone();
        (temp, app, acct)
    }
    async fn until_logs(app: &App, count: usize) {
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if app.notifications.status(app)["logs"].as_array().is_some_and(|logs| logs.len() >= count) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn destination_validation_prevents_credential_namespace_escape() {
        for id in ["", "../secret", "A", "foo_bar", "-foo", "foo-", "é"] {
            assert!(!valid_id(id));
        }
        for id in ["discord", "ops-chat", "123"] {
            assert!(valid_id(id));
        }
        let bad = Config {
            destinations: vec![Destination {
                id: "telegram".into(),
                format: Format::Telegram,
                enabled: true,
                chat_id: None,
            }],
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }
    #[test]
    fn network_and_secret_policy_remain_startup_only_after_management_config_reload() {
        let (_temp, app, _) = fixture(false);
        let mut cfg = (*app.cfg()).clone();
        cfg.notifications.private_endpoints =
            vec![PrivateEndpoint { host: "internal.example".into(), port: 443, cidrs: vec!["10.0.0.0/8".into()] }];
        cfg.notifications.secrets_dir = Some("/arbitrary/management/path".into());
        cfg.notifications.ca_file = Some("/arbitrary/management/ca".into());
        app.set_config(cfg);
        assert!(app.notifications.private_endpoints.is_empty());
        assert!(app.notifications.ca_file.is_none());
        assert!(app.notifications.secrets.ends_with(".notification-secrets"));
    }
    #[tokio::test]
    async fn accepted_first_tick_headers_are_sent_and_evidence_overflow_recovers() {
        let (_temp, app, acct) = fixture(true);
        let headers = reqwest::header::HeaderMap::from_iter([(
            "anthropic-ratelimit-unified-5h-status".parse().unwrap(),
            "rejected".parse().unwrap(),
        )]);
        crate::quota::observe(&acct, &headers, acct.quota_epoch());
        let task = tokio::spawn(worker(app.clone()));
        until_logs(&app, 1).await;
        assert!(acct.state.lock().notification_evidence.observations.is_empty());
        // Missing test credentials fail locally; this test never reaches any webhook.
        let status = app.notifications.status(&app);
        assert_eq!(status["logs"][0]["detail"], "credential_unavailable");
        let serialized = status.to_string();
        assert!(!serialized.contains("private-email-sentinel"));
        assert!(!serialized.contains("private-oauth-sentinel"));
        assert!(!serialized.contains("private-provider-account"));
        {
            let mut st = acct.state.lock();
            let window = crate::quota::Window { name: "5h".into(), used: 100.0, resets_at: None, model: None };
            for _ in 0..140 {
                st.notification_evidence.observe(std::slice::from_ref(&window), false);
            }
            crate::quota::authoritative(&mut st, vec![crate::quota::Window { used: 0.0, ..window }], None);
        }
        until_logs(&app, 2).await;
        let status = app.notifications.status(&app);
        assert_eq!(status["logs"][1]["event"], "quota.available");
        assert!(status["error"].is_null());
        assert!(acct.state.lock().notification_evidence.observations.is_empty());
        task.abort();
        let _ = task.await;
    }
    #[tokio::test]
    async fn feature_off_does_not_capture_observations_or_create_notification_state() {
        let (temp, app, acct) = fixture(false);
        let headers = reqwest::header::HeaderMap::from_iter([(
            "anthropic-ratelimit-unified-5h-status".parse().unwrap(),
            "rejected".parse().unwrap(),
        )]);
        crate::quota::observe(&acct, &headers, acct.quota_epoch());
        assert!(acct.state.lock().notification_evidence.observations.is_empty());
        let task = tokio::spawn(worker(app.clone()));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!temp.0.join(".quota-notifications").exists());
        task.abort();
        let _ = task.await;
    }
}
