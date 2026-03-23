# UniFi Insights Plus (formerly Unifi Log Insight)

Real-time log analysis for UniFi routers and gateways - captures syslog over UDP, parses firewall, DHCP, Wi-Fi, and system events, enriches them with GeoIP, ASN, threat intelligence, and reverse DNS, then serves everything through a live Dashboard.

Single Docker container. No external dependencies. Zero data collection.

> **For full documentation — installation, configuration, integrations, and more — visit [insightsplus.dev/docs](https://insightsplus.dev/docs).**

<p align="center">
<a href="#-features">Features</a> · <a href="#-prerequisites">Prerequisites</a> · <a href="#-app-screenshots">Screenshots</a>
</p>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Live Log Stream** | Auto-refreshing table with expandable details, copy-to-clipboard, and intelligent pause/resume |
| **Flow View** | Interactive Sankey flow graph and Zone Matrix showing how traffic moves between sources, services, and destinations. Click any node to cross-filter, drill into a host slide panel for per-IP breakdowns, and save/load custom views |
| **Threat Map** | Interactive world map showing where threats and blocked outbound traffic originate. Switch between heatmap and cluster views, filter by time range, and click any point to inspect individual logs |
| **Dashboard** | Traffic breakdowns, top blocked/allowed countries and IPs, top threats with ASN/city/rDNS/categories, top devices, services, DNS queries |
| **Filters** | Log type, time range, action, direction, VPN badge, interface, service, country, ASN, threat score, IP, rule name, text search |
| **IP Enrichment** | GeoIP (country, city, coordinates), ASN, reverse DNS via MaxMind GeoLite2 with scheduled auto-update and hot-reload |
| **AbuseIPDB Integration** | Threat scoring (23 categories, Tor detection, usage type), daily blacklist pre-seeding, automatic backfill |
| **Syslog Receiver** | UDP 514 listener parsing firewall, DHCP, Wi-Fi, DNS, and system events |
| **Multi-WAN & Direction** | Per-interface WAN IP mapping for failover/load-balanced setups. Auto-classifies traffic as inbound, outbound, inter-VLAN, local, or VPN |
| **VPN Detection** | Auto-detects VPN interfaces (WireGuard, OpenVPN, Teleport, Site Magic) with badge assignment, labels, and CIDRs |
| **UniFi Integration** | Network discovery, device name resolution, and firewall syslog management via **UniFi OS** (API key) or **self-hosted controllers** (username/password) |
| **Firewall Syslog Manager** | Zone matrix with bulk toggle — enable syslog on firewall rules without leaving the app (UniFi OS) |
| **AI Agent Integration** *(MCP)* | Connect Claude Desktop, Claude Code, Gemini CLI (or any http mcp client) via the [Model Context Protocol (MCP)](https://insightsplus.dev/docs) to query your network data & setup through natural conversation |
| **Device Names** | Friendly names from UniFi clients/devices with historical backfill |
| **Theming & Preferences** | Dark/light theme, country display format, IP subline (show ASN beneath IPs) |
| **Interface Labels** | Color-coded labels for traffic flow, applied retroactively to all logs |
| **CSV Export** | Download filtered results up to 100K rows |
| **Retention** | Configurable per log type (60-day default, 10-day DNS). Adjustable via Settings or env vars |
| **Backup & Restore** | Export/import all settings as JSON |
| **DNS Ready** | Full DNS query parsing ([requires configuration](https://insightsplus.dev/docs)) |
| **Mobile Responsive** | Collapsible filters, full-width table on small screens |
| **Setup Wizard** | Two paths: **UniFi API** (auto-detects WAN, VLANs, topology) or **Log Detection** (discovers interfaces from live traffic) |



## 📋 Prerequisites

- **Docker** and **Docker Compose**
- **UniFi Router** (or any UniFi gateway that supports remote syslog)
- **Zone-based firewall** (not legacy/classic). The Firewall Syslog Manager and firewall policy API require the zone-based policy engine. If you are still on the legacy/classic firewall, migrate via **Settings > Policy Engine** in your UniFi controller before setting up ULI.
- **MaxMind GeoLite2 account** ([free signup](https://www.maxmind.com/en/geolite2/signup)) - for GeoIP/ASN lookups
- **AbuseIPDB API key** ([free tier](https://www.abuseipdb.com/register?plan=free), optional) - for threat scoring

**Minimum host resources (estimated):**

- **CPU:** 2 cores/threads minimum (PostgreSQL + receiver + API run concurrently)
- **Disk:** 10 GB free for the database volume (`pgdata`) at minimum

These are baseline estimates for a small home network. Higher log volume or longer retention will require more disk.
> **Docker log rotation** is enabled by default in `docker-compose.yml` (10 MB max, 5 files). If you use a custom compose file, add a [`logging:` section](https://docs.docker.com/compose/compose-file/compose-file-v3/#logging) to prevent unbounded container log growth.

### Authentication (Optional)

ULI supports optional built-in authentication with session cookies and API tokens. When enabled, authentication requires **HTTPS** — the login and setup endpoints will reject requests over plain HTTP to protect credentials in transit.

**Quick start:**

1. Configure HTTPS on your reverse proxy first (authentication requires HTTPS).
2. Set `AUTH_ENABLED=true` in your `.env` or `docker-compose.yml` environment block and restart the container.
3. Open the ULI web UI over HTTPS — the Settings → Security page will show a "Create admin account" form.
4. Create the first admin user (username + password, min 8 characters). This enables authentication immediately.
5. Subsequent visits will require login. API tokens for MCP or external integrations can be created in Settings → MCP.

> For the full authentication reference (session management, token rotation, reverse proxy security, and audit logging), see [insightsplus.dev/docs/authentication](https://insightsplus.dev/docs/authentication).

**Production:** Place ULI behind a reverse proxy (nginx, Caddy, Traefik) that terminates TLS and sets `X-Forwarded-Proto: https`. ULI reads this header to determine the effective protocol. **Your reverse proxy must overwrite (not forward) any client-supplied `X-Forwarded-Proto` header** — otherwise an attacker can inject the header to bypass the HTTPS requirement. Examples:

```nginx
# nginx
proxy_set_header X-Forwarded-Proto $scheme;
```
```caddyfile
# Caddy (automatic — Caddy sets X-Forwarded-Proto by default)
reverse_proxy localhost:8090
```
```yaml
# Traefik (headers middleware — assumes Traefik terminates TLS)
labels:
  - "traefik.http.middlewares.uli-headers.headers.customrequestheaders.X-Forwarded-Proto=https"
```

**Local development:** The Vite dev server proxies API requests to `http://localhost:8000` without TLS. To develop with auth enabled, either:
- Use a local reverse proxy (e.g. `mkcert` + nginx) in front of the API, or
- Leave `AUTH_ENABLED=false` (the default) to bypass auth during development.

> **Docker log rotation** is enabled by default in `docker-compose.yml` (10 MB max, 5 files). If you use a custom compose file, add a [`logging:` section](https://docs.docker.com/compose/compose-file/compose-file-v3/#logging) to prevent unbounded container log growth.

## 📸 App Screenshots

#### Desktop

##### Log Stream
<img alt="Log Stream" src="docs/screenshots/log-stream.png" />

##### Expanded Log Detail
<img alt="Expanded Log Detail" src="docs/screenshots/expanded-log-detail.png" />

##### Dashboard
<img alt="Dashboard" src="docs/screenshots/dashboard.png" />

##### Dashboard — Top IPs
<img alt="Dashboard Top IPs" src="docs/screenshots/dashboard-top-ips.png" />

##### Flow View — Sankey Chart
<img alt="Flow View" src="docs/screenshots/flow-view.png" />

##### Flow View — Host Detail
<img alt="Flow View Detail" src="docs/screenshots/flow-view-detail.png" />

##### Flow View — Zone Matrix
<img alt="Flow View Zone Matrix" src="docs/screenshots/flow-view-zone-matrix.png" />

##### Threat Map — Heatmap
<img alt="Threat Map Heatmap" src="docs/screenshots/threat-map-heatmap.png" />

##### Threat Map — Clusters
<img alt="Threat Map Clusters" src="docs/screenshots/threat-map-clusters.png" />

##### Threat Map — Event Detail Sidebar
<img alt="Threat Map Event Detail Sidebar" src="docs/screenshots/threat-map-event-detail-sidebar.png" />

##### Firewall Syslog Matrix
<img alt="Firewall Syslog Matrix" src="docs/screenshots/firewall-syslog-matrix.png" />

##### Settings
<img alt="Settings" src="docs/screenshots/settings.png" />

##### Dark Mode
<img alt="Dark Mode" src="docs/screenshots/dark-mode.png" />

#### Mobile

##### Log Stream
<img alt="Main Mobile View" src="docs/screenshots/main-mobile-view.png" />

##### Flow View
<img alt="Mobile View" src="docs/screenshots/mobile-view.png" />

##### Dashboard
<img alt="Dashboard Mobile View" src="docs/screenshots/dashboard-mobile-view.png" />

##### Threat Map
<img alt="Map Mobile View" src="docs/screenshots/map-mobile-view.png" />

## 📄 License

Licensed under the [Business Source License 1.1](LICENSE) (BSL 1.1).

**You may** freely use, modify, and self-host UniFi Log Insight for non-commercial and internal business purposes.

**You may not** offer the Licensed Work to third parties on a hosted or embedded basis to compete with the Licensor's paid offerings without a commercial license.

Each version converts to **Apache License 2.0** four years after its release date.

Exceptions to the BSL terms may be granted on a case-by-case basis — contact the Licensor for inquiries.
