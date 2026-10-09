# Quota notifications

Notifications report confirmed quota transitions for native Claude and Codex OAuth subscriptions. They are off by default. Other providers and API-key accounts do not have equivalent subscription quota monitoring.

The monitor observes the same quota data used by routing and periodically refreshes idle subscriptions. Request headers and Codex WebSocket events can confirm exhaustion. When they show a lower usage value for an exhausted window, the monitor requests a fresh usage poll; those request observations do not confirm recovery themselves. A recovery event requires a fresh authoritative usage response with headroom. The poll's request-start time prevents an older response from clearing a newer exhaustion observation. A reset timer passing, a missing window, or a failed refresh does not confirm recovery. Five-hour and weekly windows, including model-specific scopes where reported, are tracked separately. A recovered five-hour window can therefore be reported while weekly quota remains exhausted.

## Configure a destination

Set up a webhook in the destination service, then add a destination under **Config → Notifications**. YAML stores destination settings and safe credential references; the full webhook URL and bearer token are secrets and belong in the environment or secret directory described below.

The corresponding configuration is:

```yaml
notifications:
  enabled: true
  time-zone: America/Denver # notification timestamps; IANA time zone
  # Optional. Defaults to <auth-dir>/.notification-secrets.
  secrets-dir: /run/notification-secrets
  # Optional startup-only PEM CA bundle for private HTTPS services.
  ca-file: /run/certs/internal-webhook-ca.pem
  # Optional startup-only permission for one self-hosted private webhook.
  private-endpoints:
    - host: chat.example.net
      port: 443
      cidrs: [10.1.2.3/32]
  destinations:
    - id: ops-discord
      format: discord
      enabled: true
    - id: team-telegram
      format: telegram
      chat-id: "-1001234567890"
```

Destination IDs are unique lowercase names of up to 32 characters using `a-z`, `0-9` and hyphens; do not start or end an ID with a hyphen. You can configure at most eight destinations. Supported formats are `generic`, `discord`, `slack`, `mattermost`, `teams` and `telegram`. Telegram requires a `chat-id`. Keep the ID stable when rotating credentials so queued retries remain associated with the destination.

The dashboard lets you enable or disable notifications and individual destinations, edit destination IDs and formats, set Telegram chat IDs, and inspect a safe delivery log. **Send test** makes one delivery attempt and reports its result; it may take up to 20 seconds and is limited to one attempt per destination every 30 seconds. Status shows safe categories and HTTP status codes. It does not expose webhook URLs, tokens, remote response bodies, or raw network errors. Activity refreshes every five seconds while the section is open and can be filtered by destination.

## Names and time zones

Notification messages use the current sanitized account display name shown in Accounts. Depending on the credential, that name may be an email address, provider username, or credential filename fallback. Treat it as identifying information sent to each destination. The generic webhook payload adds `subscription_display_name`; its existing `subscription` field remains the installation-local opaque ID. The current name is resolved when sending and in the live status response when the account is available, and is never written to the durable outbox or journal. Test notifications are marked `notification.test` and contain no fabricated account identity or provider.

Choose an IANA time zone under **Config → Notifications → Notification time zone**, or select **Use browser time zone**. The default is `UTC`. The setting takes effect on save without a restart, and daylight-saving changes follow the selected zone automatically. Chat messages include local timestamps with their time-zone abbreviation and numeric UTC offset. Generic webhook JSON retains the UTC `observed_at` and `resets_at` fields and adds `time_zone`, `observed_at_local`, and `resets_at_local`; local RFC3339 values include the numeric offset, while `time_zone` carries the IANA name. Timestamp values in the journal remain UTC.

The management API exposes the same status and test action. `GET /api/notifications` returns sanitized notification status. `POST /api/notifications/{id}/test` makes one delivery attempt and returns its result. Both routes use the normal dashboard management authentication.

The test endpoint requires an empty JSON object, which the dashboard sends automatically. For example, from the server host:

```sh
curl -X POST http://127.0.0.1:8317/api/notifications/ops-discord/test \
  -H 'Authorization: Bearer <management-key>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

If the dashboard is localhost-only and no management key is configured, omit the Authorization header.

## Supply credentials

Choose either environment variables or secret files. The webhook URL itself is sensitive: many services embed a credential in its path or query string. Do not put URLs or tokens in YAML, dashboard fields, command-line arguments, or logs.

### Secret files (recommended for Docker)

Create one file for each destination. The filename is its destination ID followed by `.url`; an optional `.bearer` file supplies an Authorization bearer token:

```text
/run/notification-secrets/ops-discord.url
/run/notification-secrets/internal-alerts.url
/run/notification-secrets/internal-alerts.bearer
```

Files must be regular files, must not be symlinks, must be at most 8 KiB, and on Unix must be owned by the server's user or root with no group or world permissions. Do not change permissions on a read-only container secret mount; provision it with an accepted owner and mode. Changing the `secrets-dir` setting or private network permissions requires a restart.

For Docker Compose, mount a host directory read-only and set `secrets-dir` to its container path. The auth directory remains the persistent writable location for accounts and notification state:

```yaml
services:
  cli-proxy-api:
    volumes:
      - ./config.yaml:/CLIProxyAPI/config.yaml
      - ./auths:/root/.cli-proxy-api
      - ./notification-secrets:/run/notification-secrets:ro
```

Set the directory and secret file permissions on the host before starting the container. The notification state and durable delivery queue live under `auth-dir/.quota-notifications`, so keep the auth directory persistent and writable.

### Environment variables

Environment names use the uppercased destination ID, with hyphens changed to underscores:

```sh
CLIPROXYAPI_NOTIFY_OPS_DISCORD_URL='https://discord.com/api/webhooks/…'
CLIPROXYAPI_NOTIFY_INTERNAL_ALERTS_URL='https://alerts.example.net/hooks/quota'
CLIPROXYAPI_NOTIFY_INTERNAL_ALERTS_BEARER_TOKEN='…'
```

Environment values are inherited when the process starts. Avoid putting them directly in shell history or process-management screens; use your service manager's secret environment support. For Telegram, its bot token is part of the Bot API URL, so protect the entire URL as a secret.

## Create service webhooks

- **Generic:** point the destination URL at an HTTPS endpoint that accepts a versioned JSON event body. Optional bearer authentication uses the `.bearer` file or matching environment variable. The event includes an event ID, provider, opaque subscription ID, event type, scope, observed usage and estimated reset time when known. Build a receiver that accepts duplicate event IDs: delivery is at least once, and a timeout after remote acceptance can cause a retry.
- **Discord:** create an incoming webhook and use its generated URL as the secret. Messages disable allowed mentions. See [Discord webhook documentation](https://docs.discord.com/developers/resources/webhook).
- **Slack:** create an incoming webhook for the target channel and store its generated URL as the secret. See [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).
- **Mattermost:** create an incoming webhook for the target channel and store its generated URL as the secret. See [Mattermost incoming webhooks](https://docs.mattermost.com/integrations-guide/incoming-webhooks).
- **Teams:** create a Teams **Workflows** incoming webhook that accepts an Adaptive Card, then store its generated URL as the secret. Prefer a workflow owned by a service account so it remains available when a person leaves. See Microsoft's [incoming webhook workflow setup](https://support.microsoft.com/en-us/workflows/send-messages-in-teams-using-incoming-webhooks). Legacy Office 365 connector webhooks are not the supported setup.
- **Telegram:** create a bot with BotFather and set the target conversation's `chat-id` in the destination. The secret URL must use the `sendMessage` path, for example `https://api.telegram.org/bot<BOT_TOKEN>/sendMessage`. Store the complete URL in `<id>.url` or the matching environment variable. See the official [Telegram Bot API `sendMessage`](https://core.telegram.org/bots/api#sendmessage) reference.

## Network and privacy

Delivery uses HTTPS with certificate validation. To trust an internal certificate authority, set startup-only `ca-file` to a regular PEM bundle no larger than 1 MiB; symlinks and invalid or empty bundles are rejected. This adds trusted roots while keeping normal TLS certificate verification enabled. Changing the `ca-file` setting requires a restart; replacing the bundle file takes effect on the next delivery attempt. Redirects, environment proxy discovery, and notification proxy configuration are not used. Public webhook hostnames are resolved and checked before connection; private, loopback, link-local and metadata addresses are blocked by default. If a self-hosted service must use a private address, allow its exact hostname, port and destination CIDR through startup-only `private-endpoints` configuration. You can list at most 16 entries, with up to 16 CIDRs per entry; CIDRs must be nonempty and cannot be `/0`. Only private IPv4/ULA addresses can use these exceptions; loopback, link-local and metadata ranges stay blocked. Treat this as a network permission and restrict it to the webhook server's exact addresses. Changes require restarting the server.

The durable event and delivery journal contain no account display name, email, OAuth token, credential filename, provider response, request body, webhook URL or secret. The subscription ID is opaque and local to this installation. The live status response resolves a current display name for delivery activity without persisting it. Delivery records persist the sanitized credential-free event and destination IDs in the auth directory. Protect and back up that directory as application state; do not expose it as a public volume. Secret file contents are resolved for delivery and are not written to the notification journal or management responses.

The worker persists transitions and pending deliveries before sending, then retries temporary failures with bounded backoff (up to eight attempts). Pending events expire after 48 hours. A destination outage does not block proxy requests or deliveries to other destinations. Retried messages may arrive late and can be duplicated; terminal failures remain visible in delivery status for operator action. Disabling a destination pauses its pending deliveries; removing it discards them. Disabling a subscription also pauses delivery; re-enabling it waits for fresh quota confirmation before delivery resumes. Keep a single active instance using a given auth directory for notification monitoring and delivery.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| No notifications | Confirm both global notifications and the destination are enabled. Monitoring currently applies to enabled native Claude/Codex OAuth subscriptions. Check whether the quota response actually confirms exhaustion. |
| No recovery message after a reset time | The displayed provider reset is an estimate. Recovery waits for a successful fresh usage response that explicitly reports headroom; provider outages or missing windows keep the state unconfirmed. |
| Notifications are delayed | Idle subscriptions use periodic usage polling; provider errors back off. Check destination delivery status for queued retries or a terminal error. |
| Test delivery fails | Check the destination URL, secret file/env mapping, file ownership/mode, and destination's webhook configuration. For private endpoints, verify the exact host, port and CIDR allow rule. The UI intentionally omits remote response bodies and secret URLs. |
| TLS certificate verification fails | Check that the server name matches the webhook URL and the certificate chain is valid. For an internal CA, configure `notifications.ca-file` with a PEM bundle and restart after changing the setting. TLS verification stays enabled. |
| Secret changes have no effect | Check the exact environment variable name or `<id>.url`/`<id>.bearer` filename, then inspect credential readiness and delivery status. Environment variables require a process restart after rotation. |
| Duplicate message | Webhook delivery is at least once. A remote endpoint may accept a request immediately before the proxy loses its acknowledgement; generic receivers can deduplicate by event ID. |
| Notification monitoring is inactive on a second instance | Only one process can own the notification state directory. Run one active instance per shared auth volume. |
