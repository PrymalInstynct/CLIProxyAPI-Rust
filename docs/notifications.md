# Quota notifications

Notifications report confirmed quota transitions for native Claude and Codex OAuth subscriptions. They are off by default. Other providers and API-key accounts do not have equivalent subscription quota monitoring.

The monitor observes the same quota data used by routing and periodically refreshes idle subscriptions. Request headers and Codex WebSocket events can confirm exhaustion. When they show a lower usage value for an exhausted window, the monitor requests a fresh usage poll; those request observations do not confirm recovery themselves. A recovery event requires a fresh authoritative usage response with headroom. The poll's request-start time prevents an older response from clearing a newer exhaustion observation. A reset timer passing, a missing window, or a failed refresh does not confirm recovery. Five-hour and weekly windows, including model-specific scopes where reported, are tracked separately. A recovered five-hour window can therefore be reported while weekly quota remains exhausted.

## Configure a destination

Set up a webhook in the destination service, then add and save a destination under **Config → Notifications**. Enable secret entry as described below before choosing **Add credentials**. Enter the URL in the write-only **Webhook URL** field and, if needed, a token in **Bearer token (optional)**. Credentials are saved separately from YAML.

The corresponding configuration is:

```yaml
notifications:
  enabled: true
  time-zone: America/Denver # notification timestamps; IANA time zone
  provider-logos: true # Discord-only provider logo thumbnails; default true
  credential-ui-enabled: false # opt in before entering secrets in the dashboard
  credential-public-url: https://proxy.example.com # optional HTTPS origin; hot-applied; leave blank for localhost/native TLS
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

The dashboard lets you enable or disable notifications and individual destinations, edit destination IDs and formats, set Telegram chat IDs, toggle Discord **Provider logos**, and inspect a safe delivery log. Before entering a secret, open **Secret entry** under **Config → Notifications** and enable **Allow secret entry**. It is off by default, and existing managed or external credentials continue to deliver while it is off. When you enable it over HTTPS, the dashboard fills **Public dashboard URL** with the current origin if it is blank. Confirm that origin and **Save settings**; the setting applies immediately without a restart. You can use **Use current address** to fill it explicitly. The URL must be an HTTPS origin only: scheme and host, with no credentials, path, query, or fragment.

The public URL must match the browser's request origin for credential changes. The dashboard also requires HTTPS and same-origin access, and uses the management bearer header when a management key is configured. These checks do not attest that a reverse proxy really terminates TLS. As the deployment administrator, ensure the public endpoint uses valid HTTPS and that the proxy does not expose an insecure route to the dashboard or API. Direct localhost access and native server TLS can use a blank public URL.

After enabling secret entry, first save the destination, then choose **Add credentials** (or **Replace credentials**) and use **Save credentials**. Saving replaces the complete bundle; an empty bearer field clears any previous token. **Remove credentials** requires inline confirmation (**Remove** or **Keep credentials**). After a save request is sent, the password fields clear even if the server rejects it. Values are never returned to the browser, kept in browser storage, written to YAML, or logged. **Send test** makes one delivery attempt and reports its result; it may take up to 20 seconds and is limited to one attempt per destination every 30 seconds. The test previews both bundled provider logos. Status shows safe categories and HTTP status codes. It does not expose webhook URLs, tokens, remote response bodies, or raw network errors. Activity refreshes every five seconds while the section is open and can be filtered by destination.

The dashboard labels credentials **Configured**, **Externally managed**, or **Not configured**. The status API uses `credential_source` (`managed`, `external`, or `none`) and the booleans `credential_configured`, `credential_ready`, and `credential_editable`. The dashboard can write only `managed` credentials. Environment variables and manually provisioned secret files remain supported as `external` credentials and are read-only in the UI. An external source is authoritative: if it is malformed or unavailable, the proxy reports it as not ready and does not silently fall back to a managed copy.

## Names and time zones

Notification messages use the current sanitized account display name shown in Accounts. Depending on the credential, that name may be an email address, provider username, or credential filename fallback. Treat it as identifying information sent to each destination. The generic webhook payload adds `subscription_display_name`; its existing `subscription` field remains the installation-local opaque ID. The current name is resolved when sending and in the live status response when the account is available, and is never written to the durable outbox or journal. Test notifications are marked `notification.test` and contain no fabricated account identity or provider.

Choose an IANA time zone under **Config → Notifications → Notification time zone**, or select **Use browser time zone**. The default is `UTC`. The setting takes effect on save without a restart, and daylight-saving changes follow the selected zone automatically. Chat messages include local timestamps with their time-zone abbreviation and numeric UTC offset. Generic webhook JSON retains the UTC `observed_at` and `resets_at` fields and adds `time_zone`, `observed_at_local`, and `resets_at_local`; local RFC3339 values include the numeric offset, while `time_zone` carries the IANA name. Timestamp values in the journal remain UTC.

The management API exposes the same status and test action. `GET /api/notifications` returns sanitized notification status, including `credential_ui_enabled`, `credential_ui_ready`, a safe `credential_ui_reason`, and normalized `credential_public_url`. `POST /api/notifications/{id}/test` makes one delivery attempt and returns its result. Both routes use the normal dashboard management authentication.

The test endpoint requires an empty JSON object, which the dashboard sends automatically. For example, from the server host:

```sh
curl -X POST http://127.0.0.1:8317/api/notifications/ops-discord/test \
  -H 'Authorization: Bearer <management-key>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

If the dashboard is localhost-only and no management key is configured, omit the Authorization header.

## Credential storage and access

Managed credential bundles are stored as plaintext JSON at `auth-dir/.notification-credentials/<id>.json`, separately from `config.yaml`, in a private `0700` directory with `0600` files. Writes use a temporary file, atomic replacement, and filesystem sync. These permissions protect against other ordinary local users; they do not encrypt the credentials. The root user and anyone who can read host backups or snapshots can access them. Protect the auth directory and its backups accordingly. Many webhook URLs contain credentials in the path or query, so protect the complete URL.

Managed credential writes are supported on Unix systems with these file permissions. On Windows, writes fail closed because equivalent ACL protection is not implemented; use the environment-variable or external secret-file methods below.

The credential API accepts only a valid saved destination ID. `PUT /api/notifications/{id}/credentials` replaces the complete URL/token bundle; `DELETE /api/notifications/{id}/credentials` removes it and takes no body. PUT accepts same-origin JSON up to 20 KiB and returns only safe status. Its JSON fields are `url` and optional `bearer_token`; an empty or omitted token clears the prior token. Use the normal management `Authorization: Bearer` header when a management key is configured; query-string keys are not accepted. For example, use placeholders and a protected input method rather than putting real credentials in shell history:

```json
{"url":"https://webhook.example/REDACTED","bearer_token":"REDACTED"}
```

The browser requires JSON same-origin requests to prevent ordinary cross-origin form submissions from saving or deleting credentials.

Credential writes require secret entry to be enabled, an authenticated request, HTTPS in the browser, and a mandatory `Origin` matching the configured public dashboard origin. The `credential-ui-enabled` setting defaults to false. **Public dashboard URL** is a normalized HTTPS origin, not a webhook URL; the dashboard rejects values containing credentials, a path, query, or fragment. The origin check prevents cross-origin writes but is not proof that TLS is configured correctly at the proxy. The deployment administrator must configure and verify TLS termination and routing. Direct localhost access and native server TLS can leave the URL blank.

Advanced deployments can still use `notifications.credential-proxy-cidrs` to trust exact reverse-proxy peers for the previous forwarded-protocol setup. This list is optional compatibility configuration, startup-only, and requires a restart after edits. It is not part of the normal **Secret entry** setup. Never trust broad ranges or shared Docker gateway addresses. A direct HTTP request is accepted only from a loopback peer to `localhost` or a loopback IP Host, without forwarding headers.

Example for an advanced reverse-proxy compatibility setup:

```yaml
notifications:
  credential-proxy-cidrs:
    - 10.1.2.3/32
```

Configure only the actual proxy peer address. The CIDR does not describe the webhook server or the clients reaching the proxy.

## Advanced credential sources

Use managed credentials in the dashboard for the normal setup. Environment variables or mounted files are available when deployment tooling provisions secrets outside the UI. The webhook URL remains a secret and must never be placed in YAML, command-line arguments, browser storage, or logs.

### Secret files

For externally managed files, create one file for each destination. The filename is its destination ID followed by `.url`; an optional `.bearer` file supplies an Authorization bearer token:

```text
/run/notification-secrets/ops-discord.url
/run/notification-secrets/internal-alerts.url
/run/notification-secrets/internal-alerts.bearer
```

Files must be regular files, must not be symlinks, must be at most 8 KiB, and on Unix must be owned by the server's user or root with no group or world permissions. Do not change permissions on a read-only container secret mount; provision it with an accepted owner and mode. Changing the `secrets-dir` setting or private network permissions requires a restart.

For Docker Compose, mount the external secret directory read-only and set `secrets-dir` to its container path. The auth directory remains the persistent writable location for accounts, managed credentials, and notification state:

```yaml
services:
  cli-proxy-api:
    volumes:
      - ./config.yaml:/CLIProxyAPI/config.yaml
      - ./auths:/root/.cli-proxy-api
      - ./notification-secrets:/run/notification-secrets:ro
```

Set the directory and secret file permissions on the host before starting the container. The notification state and durable delivery queue live under `auth-dir/.quota-notifications`; managed credentials live separately under `auth-dir/.notification-credentials`. Keep the auth directory persistent and writable.

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
- **Discord:** create an incoming webhook and use its generated URL as the secret. Messages disable allowed mentions. When **Provider logos** is enabled (the default), the alert keeps its normal message content and adds a bundled 128×128 provider logo attachment displayed as a thumbnail with the provider label and color. Logos have transparent backgrounds, with orange Claude and green ChatGPT/Codex marks for light and dark themes; no public image host is used. The webhook avatar stays unchanged, so the post remains clearly a proxy notification. This toggle affects Discord only; other destinations keep their existing payload formats. See [Discord webhook documentation](https://docs.discord.com/developers/resources/webhook) and Discord's [file upload and embed reference](https://docs.discord.com/developers/reference#uploading-files).
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
| Discord provider thumbnail missing | Confirm **Provider logos** is enabled and run a test, which previews both provider logos. Check Discord's [file upload and embed reference](https://docs.discord.com/developers/reference#uploading-files) for attachment thumbnail behavior. |
| TLS certificate verification fails | Check that the server name matches the webhook URL and the certificate chain is valid. For an internal CA, configure `notifications.ca-file` with a PEM bundle and restart after changing the setting. TLS verification stays enabled. |
| Secret changes have no effect | Check the exact environment variable name or `<id>.url`/`<id>.bearer` filename, then inspect credential readiness and delivery status. Environment variables require a process restart after rotation. |
| Duplicate message | Webhook delivery is at least once. A remote endpoint may accept a request immediately before the proxy loses its acknowledgement; generic receivers can deduplicate by event ID. |
| Notification monitoring is inactive on a second instance | Only one process can own the notification state directory. Run one active instance per shared auth volume. |
