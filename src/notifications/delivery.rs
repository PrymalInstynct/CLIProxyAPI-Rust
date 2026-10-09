//! Isolated webhook transport. No OAuth headers, ambient proxies, redirects or raw error logging.
use super::{Destination, Format, PrivateEndpoint, state::Event, store::safe_file};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::{Value, json};
use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use url::Url;

pub struct Credentials {
    url: Url,
    bearer: Option<HeaderValue>,
}
// Intentionally no Debug/Serialize; the URL itself is a credential.
pub fn credentials(dir: &Path, d: &Destination) -> Result<Credentials, &'static str> {
    if !super::valid_id(&d.id) {
        return Err("invalid_destination");
    }
    let prefix = format!("CLIPROXYAPI_NOTIFY_{}", d.id.to_ascii_uppercase().replace('-', "_"));
    let read = |suffix: &str, extension: &str, required: bool| -> Result<Option<String>, &'static str> {
        match std::env::var(format!("{prefix}_{suffix}")) {
            Ok(value) => {
                if value.len() > 8192 {
                    return Err("credential_too_large");
                }
                Ok(Some(value.trim().into()))
            }
            Err(std::env::VarError::NotUnicode(_)) => Err("invalid_credential"),
            Err(std::env::VarError::NotPresent) => {
                let path = dir.join(format!("{}.{extension}", d.id));
                if !required && !path.try_exists().map_err(|_| "credential_unavailable")? {
                    return Ok(None);
                }
                // Reject symlinked directory components before opening the fixed filename.
                let mut component = std::path::PathBuf::new();
                for part in dir.components() {
                    component.push(part);
                    if std::fs::symlink_metadata(&component)
                        .map_err(|_| "credential_unavailable")?
                        .file_type()
                        .is_symlink()
                    {
                        return Err("insecure_credential_directory");
                    }
                }
                let mut value = String::new();
                safe_file(&path)?.take(8193).read_to_string(&mut value).map_err(|_| "invalid_credential")?;
                if value.len() > 8192 {
                    return Err("credential_too_large");
                }
                Ok(Some(value.trim().into()))
            }
        }
    };
    let url = Url::parse(&read("URL", "url", true)?.ok_or("credential_unavailable")?).map_err(|_| "invalid_url")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err("unsafe_url");
    }
    let bearer = read("BEARER_TOKEN", "bearer", false)?
        .map(|v| {
            if v.is_empty() {
                return Err("invalid_bearer");
            }
            let mut header = HeaderValue::from_str(&format!("Bearer {v}")).map_err(|_| "invalid_bearer")?;
            header.set_sensitive(true);
            Ok(header)
        })
        .transpose()?;
    Ok(Credentials { url, bearer })
}
pub struct Outcome {
    pub success: bool,
    pub retry: bool,
    pub status: Option<u16>,
    pub reason: &'static str,
    pub retry_after: Option<i64>,
}
impl Outcome {
    fn error(reason: &'static str, retry: bool) -> Self {
        Self { success: false, retry, status: None, reason, retry_after: None }
    }
}
fn text(e: &Event) -> String {
    let mut text = format!(
        "{}: {} subscription {} — {}{} (observed {} UTC).",
        e.event,
        e.provider,
        e.subscription,
        e.window,
        e.model.as_ref().map(|s| format!(" ({s})")).unwrap_or_default(),
        e.observed_at.format("%Y-%m-%d %H:%M:%S")
    );
    if let Some(reset) = e.resets_at {
        text.push_str(&format!(" Estimated reset {} UTC; confirmation required.", reset.format("%Y-%m-%d %H:%M:%S")));
    }
    if !e.remaining_blockers.is_empty() {
        text.push_str(&format!(" Still exhausted: {}.", e.remaining_blockers.join(", ")));
    }
    text
}
pub fn payload(d: &Destination, e: &Event) -> Value {
    let text = text(e);
    match d.format {
        Format::Generic => json!(e),
        Format::Discord => json!({"content":text,"allowed_mentions":{"parse":[]}}),
        Format::Slack => json!({"text":text,"mrkdwn":false,"unfurl_links":false,"unfurl_media":false}),
        Format::Mattermost => json!({"text":text}),
        Format::Teams => {
            json!({"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","contentUrl":null,"content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.2","body":[{"type":"TextBlock","text":text,"wrap":true}]}}]})
        }
        Format::Telegram => json!({"chat_id":d.chat_id,"text":text,"disable_web_page_preview":true}),
    }
}
pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((network, bits)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(network) = network.parse::<IpAddr>() else {
        return false;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    match (network, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private(),
        IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}
pub fn public(ip: IpAddr) -> bool {
    let ip = normalize(ip);
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            v.octets() != [168, 63, 129, 16]
                && !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_multicast()
                && !v.is_broadcast()
                && !v.is_unspecified()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0)
                && !(a == 192 && b == 0 && c == 2)
                && !(a == 192 && b == 88 && c == 99)
                && !(a == 198 && (b == 18 || b == 19))
                && !(a == 198 && b == 51 && c == 100)
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            // Only native global unicast; exclude transition/tunneling and documentation.
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0)
        }
    }
}
pub fn allowed(ip: IpAddr, host: &str, port: u16, endpoints: &[PrivateEndpoint]) -> bool {
    let ip = normalize(ip);
    if ip == "fd00:ec2::254".parse::<IpAddr>().unwrap() {
        return false;
    }
    if public(ip) {
        return true;
    }
    // Private RFC1918/ULA only: no metadata, loopback, link-local or special-use bypass.
    private(ip)
        && endpoints.iter().any(|entry| {
            entry.host.eq_ignore_ascii_case(host)
                && entry.port == port
                && entry.cidrs.iter().any(|c| cidr_contains(c, ip))
        })
}
async fn client(
    url: &Url,
    endpoints: &[PrivateEndpoint],
    ca_file: Option<&Path>,
) -> Result<reqwest::Client, &'static str> {
    let host = url.host_str().ok_or("unsafe_url")?;
    let port = url.port_or_known_default().ok_or("unsafe_url")?;
    let addresses: Vec<_> = match url.host().ok_or("unsafe_url")? {
        url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
        url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
        url::Host::Domain(_) => tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| "dns_timeout")?
            .map_err(|_| "dns_failed")?
            .take(33)
            .collect(),
    };
    if addresses.is_empty() || addresses.len() > 32 || addresses.iter().any(|a| !allowed(a.ip(), host, port, endpoints))
    {
        return Err("blocked_address");
    }
    let mut builder = isolated_builder().resolve_to_addrs(host, &addresses);
    if let Some(path) = ca_file {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| "ca_unavailable")?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1 << 20 {
            return Err("invalid_ca_file");
        }
        let file = std::fs::File::open(path).map_err(|_| "ca_unavailable")?;
        let mut bytes = Vec::new();
        file.take((1 << 20) + 1).read_to_end(&mut bytes).map_err(|_| "ca_unavailable")?;
        if bytes.len() > 1 << 20 {
            return Err("invalid_ca_file");
        }
        let certificates = reqwest::Certificate::from_pem_bundle(&bytes).map_err(|_| "invalid_ca_file")?;
        if certificates.is_empty() {
            return Err("invalid_ca_file");
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder.build().map_err(|_| "transport_unavailable")
}
fn isolated_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .gzip(false)
        .brotli(false)
        .deflate(false)
        .zstd(false)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
}
pub async fn send(
    dir: &Path,
    endpoints: &[PrivateEndpoint],
    ca_file: Option<&Path>,
    d: &Destination,
    e: &Event,
) -> Outcome {
    let secret = match credentials(dir, d) {
        Ok(secret) => secret,
        Err(reason) => return Outcome::error(reason, false),
    };
    let client = match client(&secret.url, endpoints, ca_file).await {
        Ok(client) => client,
        Err(reason) => return Outcome::error(reason, matches!(reason, "dns_timeout" | "dns_failed")),
    };
    dispatch(client, secret, d, e).await
}
async fn dispatch(client: reqwest::Client, mut secret: Credentials, d: &Destination, e: &Event) -> Outcome {
    if d.format == Format::Discord {
        secret.url.query_pairs_mut().append_pair("wait", "true");
    }
    let mut request = client.post(secret.url).json(&payload(d, e));
    if let Some(bearer) = secret.bearer {
        request = request.header(AUTHORIZATION, bearer);
    }
    let mut response = match request.send().await {
        Ok(response) => response,
        Err(_) => return Outcome::error("network_error", true),
    };
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok().or_else(|| DateTimeParser::seconds(v)))
        .map(|s| s.clamp(1, 3600));
    if !(200..300).contains(&status) {
        return Outcome {
            success: false,
            retry: matches!(status, 408 | 429 | 500 | 502 | 503 | 504),
            status: Some(status),
            reason: "http_rejected",
            retry_after,
        };
    }
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len() + chunk.len() > 65536 {
                    return Outcome { status: Some(status), ..Outcome::error("response_too_large", false) };
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return Outcome { status: Some(status), ..Outcome::error("response_read_failed", true) },
        }
    }
    let acknowledged = match d.format {
        Format::Slack | Format::Mattermost => std::str::from_utf8(&bytes).is_ok_and(|s| s.trim() == "ok"),
        Format::Telegram => serde_json::from_slice::<Value>(&bytes).is_ok_and(|v| v["ok"] == true),
        _ => true,
    };
    Outcome {
        success: acknowledged,
        retry: false,
        status: Some(status),
        reason: if acknowledged { "accepted" } else { "acknowledgement_failed" },
        retry_after: None,
    }
}
struct DateTimeParser;
impl DateTimeParser {
    fn seconds(value: &str) -> Option<i64> {
        chrono::DateTime::parse_from_rfc2822(value)
            .ok()
            .map(|at| (at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn isolated_transport_refuses_redirects_bounds_responses_and_checks_acknowledgements() {
        use axum::{
            Router,
            body::Body,
            http::{Response, StatusCode},
            routing::post,
        };
        use std::{
            future::IntoFuture,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
        };
        let hits = Arc::new(AtomicUsize::new(0));
        let target_hits = hits.clone();
        let router = Router::new()
            .route(
                "/redirect",
                post(|| async {
                    Response::builder().status(307).header("location", "/target").body(Body::empty()).unwrap()
                }),
            )
            .route(
                "/target",
                post(move || {
                    let hits = target_hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        "ok"
                    }
                }),
            )
            .route(
                "/limited",
                post(|| async {
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header("retry-after", "999999")
                        .body(Body::from("secret-body-sentinel"))
                        .unwrap()
                }),
            )
            .route("/large", post(|| async { vec![b'x'; 65537] }))
            .route("/slack", post(|| async { "ok" }))
            .route("/telegram", post(|| async { r#"{"ok":false,"description":"secret-body-sentinel"}"# }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(axum::serve(listener, router).into_future());
        // Internal mock transport only: production `send` always requires vetted HTTPS.
        let client = isolated_builder().https_only(false).build().unwrap();
        let event = Event {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            event: "quota.exhausted".into(),
            subscription: "0123456789abcdef01234567".into(),
            provider: "claude".into(),
            window: "5h".into(),
            model: None,
            observed_at: chrono::Utc::now(),
            resets_at: None,
            used: Some(100.0),
            remaining_blockers: vec!["5h".into()],
        };
        let mut destination = Destination { id: "test".into(), format: Format::Generic, enabled: true, chat_id: None };
        let credentials = |path: &str| Credentials {
            url: Url::parse(&format!("http://{address}/{path}?secret-url-sentinel")).unwrap(),
            bearer: None,
        };
        let redirect = dispatch(client.clone(), credentials("redirect"), &destination, &event).await;
        assert_eq!(redirect.status, Some(307));
        assert!(!redirect.retry);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        let limited = dispatch(client.clone(), credentials("limited"), &destination, &event).await;
        assert_eq!(limited.status, Some(429));
        assert!(limited.retry);
        assert_eq!(limited.retry_after, Some(3600));
        assert_eq!(limited.reason, "http_rejected");
        let oversized = dispatch(client.clone(), credentials("large"), &destination, &event).await;
        assert_eq!(oversized.reason, "response_too_large");
        assert!(!oversized.retry);
        destination.format = Format::Slack;
        assert!(dispatch(client.clone(), credentials("slack"), &destination, &event).await.success);
        destination.format = Format::Telegram;
        let refused = dispatch(client, credentials("telegram"), &destination, &event).await;
        assert_eq!(refused.reason, "acknowledgement_failed");
        assert!(!refused.success);
        server.abort();
        let _ = server.await;
    }
    #[test]
    fn special_addresses_and_mapped_ipv6_cannot_bypass_filter() {
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "10.1.2.3",
            "100.64.1.2",
            "192.0.2.1",
            "198.18.1.1",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2002:7f00:1::1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn private_allowlist_is_exact_host_port_and_subnet() {
        let allow = vec![PrivateEndpoint { host: "chat.example".into(), port: 443, cidrs: vec!["10.1.0.0/16".into()] }];
        assert!(allowed("10.1.2.3".parse().unwrap(), "chat.example", 443, &allow));
        for (ip, host, port) in [
            ("10.2.2.3", "chat.example", 443),
            ("10.1.2.3", "other.example", 443),
            ("10.1.2.3", "chat.example", 8443),
            ("127.0.0.1", "chat.example", 443),
            ("169.254.169.254", "chat.example", 443),
        ] {
            assert!(!allowed(ip.parse().unwrap(), host, port, &allow));
        }
    }
}
