# TI-Mirror

**A lightweight, air-gapped Threat Intelligence mirror for Splunk ES.**

TI-Mirror is a self-hosted service that downloads free Threat Intelligence (TI) feeds from the internet, normalizes them at the edge, and serves them as static files to an air-gapped Splunk ES Search Head via HTTP. It eliminates the need for direct internet access on the Search Head, removes the dependency on heavy platforms like MISP or OpenCTI, and gives you full control over feed normalization and lifecycle.

---

## Why TI-Mirror?

Many SOC teams face a common dilemma: they need fresh Threat Intelligence in Splunk ES, but they cannot (or should not) expose their Search Head to the internet. Existing solutions often require deploying a full TI platform, which introduces significant operational overhead.

TI-Mirror solves this with a minimal, transparent architecture:

- **No direct internet on ES.** The Search Head only talks to an internal Nginx endpoint, restricted by IP ACL.
- **Normalization at the edge.** Feeds are cleaned (comments stripped, CSV columns extracted, iblocklist ranges parsed) before they ever reach ES.
- **Config-driven.** Adding a new feed is as simple as editing a YAML file — no code changes required.
- **Observable.** Every run produces structured metadata and logs, making it easy to monitor feed health.

---

## Architecture

```
Internet → TI-Mirror (Nginx + Python) → Splunk ES
           - Downloads feeds via update_feeds.py
           - Applies per-feed transforms
           - Serves via Nginx with IP ACL
           - Refreshes every 6 hours via cron
```

**Key design decisions:**

- **Atomic writes** prevent ES from reading partial files during refresh.
- **Per-feed transforms** (strip comments, extract CSV columns, parse ranges) are declared in `feeds.yaml`.
- **Deterministic parsing in ES.** Because feeds are normalized upstream, ES only needs simple parsing rules like `ip:$1` or `url:$1`.

---

## Features

- Supports 20+ free TI feeds (Feodo, Spamhaus DROP, CINS, DShield, URLhaus, SSLBL, I-BlockList, and more).
- Handles gzip and zip transports automatically.
- Per-feed transforms: comment stripping, CSV column extraction, range parsing.
- Structured metadata (`_metadata.json`) for every run.
- Log rotation with `copytruncate`.
- IP-based ACL restricts access to the Search Head only.

---

## Prerequisites

| Component | Requirement |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Python | 3.11+ |
| Web Server | Nginx |
| Splunk | ES 8.6.1 (or compatible) |
| Network | Air-gapped Search Head with HTTP access to TI-Mirror |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ti-mirror.git
cd ti-mirror
```

### 2. Install dependencies

```bash
sudo apt update
sudo apt install -y python3-pip python3-yaml nginx
pip3 install --break-system-packages -r requirements.txt
```

### 3. Configure feeds

Copy the example configuration and edit it:

```bash
cp config/feeds.example.yaml /opt/ti-mirror/feeds.yaml
sudo nano /opt/ti-mirror/feeds.yaml
```

> ⚠️ **Important — Production Values Required**
>
> The example configuration (`feeds.example.yaml`) uses placeholders such as:
>
> - `YOUR_ABUSECH_AUTH_KEY`
> - `YOUR_IBLOCKLIST_USERNAME`
> - `YOUR_IBLOCKLIST_PIN`
> - `YOUR_IBLOCKLIST_LIST_ID`
>
> **These placeholders must be replaced with real values before deployment.**
>
> - **abuse.ch Auth-Key:** Register at [auth.abuse.ch](https://auth.abuse.ch) to obtain your personal Auth-Key.
> - **I-BlockList credentials:** Register at [iblocklist.com](https://www.iblocklist.com) and use your personalized download URLs (which include your username, PIN, and list IDs).
>
> **Never commit `feeds.yaml` with real credentials to a public repository.** Keep it out of version control (see `.gitignore`).

### 4. Run the downloader

```bash
sudo python3 /opt/ti-mirror/update_feeds.py
```

Verify output:

```bash
ls -la /var/www/html/feeds/
cat /var/www/html/feeds/_metadata.json | python3 -m json.tool
```

### 5. Configure Nginx

Create `/etc/nginx/sites-available/ti-mirror` with the following configuration. Replace placeholders with your real values:

```nginx
server {
    listen 80;
    server_name 192.0.2.10 ti.example.local;   # ← Replace with real IP / FQDN

    location /feeds/ {
        allow 192.0.2.20;                       # ← Replace with Splunk SH IP
        deny all;

        alias /var/www/html/feeds/;
        autoindex on;
        autoindex_exact_size off;
        add_header Cache-Control "no-cache, must-revalidate";
    }

    location / {
        deny all;
    }
}
```

Enable and reload:

```bash
sudo ln -sf /etc/nginx/sites-available/ti-mirror /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

> ⚠️ **Production Note**
>
> In production, replace:
>
> - `192.0.2.10` with your TI-Mirror server IP.
> - `ti.example.local` with your internal DNS name.
> - `192.0.2.20` with the Splunk ES Search Head IP.
>
> The ACL (`allow ...; deny all;`) is critical: it ensures only the Search Head can fetch feeds.

### 6. Schedule automatic refresh

Add a cron job to refresh feeds every 6 hours:

```bash
sudo crontab -e
```

```cron
0 */6 * * * /usr/bin/python3 /opt/ti-mirror/update_feeds.py >> /var/log/ti-mirror-cron.log 2>&1
```

---

## Configuration

All feed configuration lives in `feeds.yaml`. Each feed supports the following options:

| Option | Description |
|---|---|
| `url` | Source URL |
| `filename` | Output filename in `/var/www/html/feeds/` |
| `enabled` | `true` / `false` |
| `transform` | List of transforms to apply (`strip_comments`, `extract_iblocklist`, `feodo_extract_ip`, etc.) |
| `decompress` | `none` / `gzip` / `zip` |
| `accept_encoding` | `identity` / `gzip` |
| `keep_raw` | Keep the original download as `.raw` |
| `notes` | Human-readable description |

**Available transforms:**

| Transform | Purpose |
|---|---|
| `strip_comments` | Remove lines starting with `#` |
| `strip_semicolon` | Remove lines starting with `;` |
| `strip_inline_semicolon` | Remove everything after `;` on a line |
| `extract_iblocklist` | Extract start IP from `name:start-end` |
| `feodo_extract_ip` | Extract `dst_ip` from Feodo CSV |
| `urlhaus_extract_url` | Extract URL from URLhaus CSV |

---

## Integrating with Splunk ES

For each feed, create a Data Source in Splunk ES:

```
Configure > Data Enrichment > Threat Intelligence Management
```

Use the following pattern. Replace the URL with your own TI-Mirror address.

**Example (IP feeds):**

| Field | Value |
|---|---|
| Name | `feodo_c2` |
| URL | `http://ti.example.local/feeds/feodo.csv` |
| Type | `IP_Intel` |
| Parsing | `ip:$1` |
| Weight | `80` |
| Interval | `21600` (6 hours) |
| Max Age | `-30d` |
| Threat Intelligence | ✓ |

> ⚠️ **Production Note**
>
> In production, replace `ti.example.local` with your TI-Mirror FQDN or IP. Make sure the Search Head can resolve and reach this address (via `/etc/hosts` or internal DNS).

---

## Security Notes

- **Never commit real credentials.** Use `feeds.example.yaml` as a template and keep your actual `feeds.yaml` out of version control.
- **Restrict access with ACL.** The Nginx configuration should only allow the Splunk Search Head IP.
- **Run as a dedicated user.** The downloader should run as a non-privileged user or via cron with appropriate permissions.
- **Audit your feeds.** Regularly review `_metadata.json` and logs for failed downloads.
- **Rotate credentials.** If you suspect a key leak, revoke it immediately at the provider (abuse.ch, iblocklist.com, etc.).

---

## Documentation

- [Full Runbook](docs/RUNBOOK.md) — step-by-step deployment guide.
- [Feed Configuration Reference](docs/FEEDS.md) — detailed explanation of all supported feeds and transforms.

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [abuse.ch](https://abuse.ch) for Feodo, URLhaus, SSLBL, and MalwareBazaar.
- [Spamhaus](https://www.spamhaus.org) for the DROP list.
- [CINS](https://cinsscore.com) for the CINS Army list.
- [SANS ISC](https://isc.sans.edu) for DShield.
- [I-BlockList](https://www.iblocklist.com) for curated IP lists.
- [MITRE](https://attack.mitre.org) for ATT&CK.
- [CISA](https://www.cisa.gov) for KEV.

---

## Third-Party Data Sources & Terms

The **code** in this repository is licensed under the **Apache License 2.0**. However, the **data** downloaded by this tool comes from third-party sources, each with its own terms of use. Users are responsible for reviewing and complying with these terms, especially for commercial use.

### abuse.ch (Feodo, URLhaus, SSLBL, MalwareBazaar, ThreatFox)
- **Terms:** Access is provided free of charge for **non-commercial / non-profit** purposes, subject to fair use (query limits) and authentication (Auth-Key required) [citation:14].
- **Commercial Use:** Organizations with commercial needs may require a paid subscription managed by Spamhaus. The community API is not licensed for use in commercial products/services [citation:2].
- **Action Required:** You must obtain your own Auth-Key from [auth.abuse.ch](https://auth.abuse.ch).

### Spamhaus DROP
- **Terms:** The DROP list is provided **free of charge** for filtering malicious traffic [citation:3][citation:9].
- **Restrictions:** The content is protected by copyright and database right. You may **not** use the "Spamhaus" name in any marketing, promotional, or commercial materials without permission [citation:3][citation:9].
- **Action Required:** No API key is needed for the DROP list itself.

### SANS ISC (DShield)
- **Terms:** Data is shared under a **Creative Commons Non-Commercial Share-Alike** license. You may use and share the data as long as you **do not resell it** and you **give credit** to SANS ISC [citation:4].
- **Action Required:** No API key is needed.

### CINS Army
- **Terms:** CINS provides its blocklist for use in firewalls and security devices. While no explicit formal license was found in the search, it is intended for free use by the security community.
- **Action Required:** No API key is needed.

### Other Feeds (I-BlockList, etc.)
- **Terms:** These sources have their own policies. Please refer to their respective websites for terms of use and licensing before deploying in a commercial environment.
- **I-BlockList:** A free account is required to obtain personalized download URLs.

---

**Built for SOC teams who value control, transparency, and air-gapped security.**
