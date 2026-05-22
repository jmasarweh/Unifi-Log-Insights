# Insights Plus — Architecture Diagrams

## 1. Container Startup & Process Supervision

```mermaid
flowchart TD
    A["Docker Container Start"] --> B["entrypoint.sh"]

    B --> C{"DB_HOST is<br>local/empty?"}
    C -- "Yes (Embedded)" --> D["Init PostgreSQL 16"]
    C -- "No (External)" --> E["Disable embedded PG<br>autostart=false"]

    D --> D1["initdb -D /var/lib/postgresql/data"]
    D1 --> D2["Create user: unifi<br>Create DB: unifi_logs"]
    D2 --> D3["Load init.sql<br>(initial DDL, embedded only)"]
    D3 --> D4["Configure pg_hba.conf<br>synchronous_commit=off<br>shared_buffers=128MB"]
    D4 --> F

    E --> F{"MAXMIND<br>credentials?"}
    F -- Yes --> G["Write /etc/GeoIP.conf<br>Schedule cron: Wed+Sat 07:00<br>Initial download if missing"]
    F -- No --> H["GeoIP disabled"]
    G --> I
    H --> I["Set UVICORN_LOG_LEVEL<br>from LOG_LEVEL"]

    I --> J["exec supervisord"]

    J --> K["supervisord starts 4 processes"]

    K --> P1["Priority 10<br>PostgreSQL<br>:5432 (embedded only)"]
    K --> P2["Priority 20<br>Receiver (main.py)<br>UDP :514"]
    K --> P3["Priority 30<br>API (uvicorn)<br>:8000"]
    K --> P4["Priority 40<br>Cron<br>geoipupdate schedule"]

    P1 -.-> |"waits for PG"| P2
    P1 -.-> |"waits for PG"| P3

    style A fill:#4a90d9,color:#fff
    style J fill:#e67e22,color:#fff
    style P1 fill:#27ae60,color:#fff
    style P2 fill:#8e44ad,color:#fff
    style P3 fill:#2980b9,color:#fff
    style P4 fill:#7f8c8d,color:#fff
```

## 2. Receiver Startup Sequence

```mermaid
flowchart TD
    M["main()"] --> M1["build_conn_params()<br>from env vars"]
    M1 --> M2["wait_for_postgres()<br>max 30 retries, 2s delay"]
    M2 --> M3["db.connect()<br>ThreadedConnectionPool 2-10"]
    M3 --> M4["db._ensure_schema()<br>idempotent CREATE IF NOT EXISTS<br>(schema source of truth for both<br>embedded and external DB)"]
    M4 --> M5{"setup_complete<br>in system_config?"}

    M5 -- No --> M6["Auto-migrate:<br>set wan_interfaces=ppp0<br>set interface_labels={}"]
    M5 -- Yes --> M7
    M6 --> M7["parsers.reload_config_from_db()<br>WAN_INTERFACES, INTERFACE_LABELS, WAN_IPS"]

    M7 --> M8["db.detect_wan_ip()<br>from WAN_LOCAL rules"]
    M8 --> M9["db.detect_gateway_ips()<br>from log patterns"]
    M9 --> M10["UniFiAPI(db)<br>self-disables if not configured"]
    M10 --> M11["Enricher(db, unifi)<br>GeoIP + AbuseIPDB + rDNS"]
    M11 --> M12["SyslogReceiver(db, enricher)"]

    M12 --> SIG["Register Signal Handlers"]
    SIG --> SIG1["SIGTERM/SIGINT -> shutdown()"]
    SIG --> SIG2["SIGUSR1 -> reload_geoip()"]
    SIG --> SIG3["SIGUSR2 -> reload_config()"]

    SIG1 & SIG2 & SIG3 --> BG["Start Background Threads"]
    BG --> BG1["BackfillTask.start()<br>threat queue daemon"]
    BG --> BG2["unifi_api.start_polling()<br>client/device poll 5min"]
    BG --> BG3["BlacklistFetcher<br>initial pull after 30s"]
    BG --> BG4["run_scheduler()<br>stats, retention, blacklist"]

    BG1 & BG2 & BG3 & BG4 --> RUN["receiver.start()<br>UDP :514 — BLOCKING"]

    style M fill:#4a90d9,color:#fff
    style RUN fill:#e74c3c,color:#fff
    style SIG fill:#f39c12,color:#fff
```

## 3. Syslog Pipeline (UDP to Database)

```mermaid
flowchart TD
    UDP["UDP Packet<br>port 514"] --> RECV["SyslogReceiver.start()<br>dual-stack IPv4+IPv6<br>SO_RCVBUF=1MB"]
    RECV --> DECODE["Decode UTF-8<br>errors=replace"]
    DECODE --> PARSE["parse_log(raw_log)"]

    PARSE --> HDR["Match SYSLOG_HEADER regex<br>Month Day Time Host Body"]
    HDR --> TS["parse_syslog_timestamp()<br>TZ-aware, year rollover guard"]
    TS --> DETECT["detect_log_type(body)"]

    DETECT --> FW["firewall<br>SRC= DST= PROTO="]
    DETECT --> DNS["dns<br>dnsmasq, query, reply"]
    DETECT --> DHCP["dhcp<br>DHCPACK, dnsmasq-dhcp"]
    DETECT --> WIFI["wifi<br>stamgr, hostapd"]
    DETECT --> SYS["system<br>default"]

    FW --> PFW["parse_firewall()<br>rule, IPs, ports, MAC<br>derive_direction()<br>derive_action()"]
    DNS --> PDNS["parse_dns()<br>query, type, answer"]
    DHCP --> PDHCP["parse_dhcp()<br>event, interface, IP, MAC"]
    WIFI --> PWIFI["parse_wifi()<br>event, MAC"]
    SYS --> PSYS["parse_system()<br>raw_log only"]

    PFW & PDNS & PDHCP & PWIFI & PSYS --> VALID["Validate IPs and MACs"]
    VALID --> DISABLED{"log_type<br>disabled?"}
    DISABLED -- Yes --> DROP["stats.filtered++<br>Drop"]
    DISABLED -- No --> ENRICH["enricher.enrich(parsed)<br>see Enrichment diagram"]

    ENRICH --> BATCH["batch.append(enriched)"]
    BATCH --> CHECK{"len >= 50<br>OR timeout >= 2s?"}
    CHECK -- No --> WAIT["Wait for next packet"]
    CHECK -- Yes --> FLUSH["_flush_batch()"]
    FLUSH --> INSERT["db.insert_logs_batch()<br>execute_batch with 47 columns<br>row-by-row fallback on error"]
    INSERT --> DONE["stats.inserted += N"]

    WAIT --> UDP

    style UDP fill:#4a90d9,color:#fff
    style DROP fill:#e74c3c,color:#fff
    style DONE fill:#27ae60,color:#fff
    style ENRICH fill:#8e44ad,color:#fff
```

## 4. Enrichment Decision Tree

```mermaid
flowchart TD
    START["enricher.enrich(parsed)"] --> WAN["Auto-exclude WAN IPs<br>Refresh from DB:<br>wan_ips + gateway_ips"]

    WAN --> DEV{"UniFi API<br>enabled?"}
    DEV -- Yes --> SRCDEV["Resolve src device name<br>unifi.resolve_name(src_ip, mac)"]
    SRCDEV --> DSTDEV["Resolve dst device name<br>unifi.resolve_name(dst_ip)"]
    DEV -- No --> FWCHECK

    DSTDEV --> FWCHECK{"Firewall log +<br>zone_index format?"}
    FWCHECK -- Yes --> POLICY["firewall_policy_matcher<br>.resolve_rule_action()<br>Override rule_action"]
    FWCHECK -- No --> REMOTE
    POLICY --> REMOTE

    REMOTE["Determine remote IP"] --> R1{"src_ip<br>public?"}
    R1 -- Yes --> R2{"dst_ip<br>public?"}
    R1 -- No --> R3{"dst_ip<br>public?"}
    R2 -- Yes --> ESRC["ip_to_enrich = src_ip<br>prefer source"]
    R2 -- No --> ESRC2["ip_to_enrich = src_ip"]
    R3 -- Yes --> EDST["ip_to_enrich = dst_ip"]
    R3 -- No --> SKIP["No public IP<br>Skip enrichment"]

    ESRC & ESRC2 & EDST --> GEO["GeoIP + ASN Lookup<br>geoip.lookup(ip)<br>MaxMind GeoLite2"]
    GEO --> GEOOUT["geo_country, geo_city<br>geo_lat, geo_lon<br>asn_number, asn_name"]

    GEOOUT --> RDNS["Reverse DNS<br>rdns.lookup(ip)<br>socket.gethostbyaddr"]
    RDNS --> RDNSOUT["rdns hostname<br>cached 24h"]

    RDNSOUT --> THREAT{"log_type = firewall<br>AND rule_action = block?"}
    THREAT -- No --> DONE["Return enriched dict"]
    THREAT -- Yes --> ABUSE["AbuseIPDB Lookup<br>3-tier cache"]

    ABUSE --> T1{"Memory cache<br>TTLCache 24h?"}
    T1 -- Hit --> DONE
    T1 -- Miss --> T2{"DB ip_threats<br>under 4 days old?"}
    T2 -- Hit --> PROMOTE["Promote to<br>memory cache"]
    PROMOTE --> DONE
    T2 -- Miss --> T3{"Rate limit<br>budget?"}
    T3 -- Exhausted --> QUEUE["enqueue_threat_backfill(ip)<br>for deferred lookup"]
    T3 -- Available --> API["API call<br>abuseipdb.com/api/v2/check"]
    API --> UPSERT["Upsert ip_threats<br>Cache in memory"]
    UPSERT --> TOUCH["touch_threat_last_seen(ip)<br>coalesced writes 60s"]
    TOUCH --> DONE
    QUEUE --> DONE

    SKIP --> DONE2["Return parsed dict<br>no enrichment"]

    style START fill:#8e44ad,color:#fff
    style DONE fill:#27ae60,color:#fff
    style DONE2 fill:#95a5a6,color:#fff
    style ABUSE fill:#e74c3c,color:#fff
    style QUEUE fill:#f39c12,color:#fff
```

## 5. Background Tasks & Scheduling

```mermaid
flowchart TD
    subgraph SCHEDULER["Scheduler Thread (run_scheduler)"]
        direction TB
        S1["Every 15 min:<br>log_stats()<br>db.get_stats() + enricher.get_stats()"]
        S2["Every 15 min:<br>refresh_wan_ip()<br>db.detect_wan_ip()<br>db.detect_gateway_ips()"]
        S3["Daily 03:00:<br>retention_cleanup()<br>Delete logs > 60d<br>Delete DNS > 10d"]
        S4["Daily 03:30:<br>auth_cleanup()<br>Clean audit_log"]
        S5["Daily 04:00:<br>pull_blacklist()<br>AbuseIPDB top 10k IPs"]
    end

    subgraph BACKFILL["Backfill Daemon (BackfillTask)"]
        direction TB
        B0["Sleep 60s on startup"]
        B0 --> B1["Every 5 min: _run_once()"]
        B1 --> B2["One-time repairs:<br>backfill_direction<br>fix_wan_ip_enrichment<br>fix_abuse_hostname_mixing"]
        B2 --> B3["One-shot migrations:<br>service_name_migration<br>backfill_rule_action<br>orphan_queue_seed"]
        B3 --> B4["Queue worker:<br>Pull 50 due IPs<br>abuseipdb.lookup() each<br>patch logs with results"]
        B4 --> B5["Every 12th cycle (~hourly):<br>re-enrich stale threats > 4d"]
    end

    subgraph UNIFI["UniFi Polling Thread"]
        direction TB
        U1["Every 5 min:<br>Fetch clients (MAC/IP/name)<br>Fetch devices (APs, gateways)<br>Cache in _ip_to_name"]
    end

    subgraph CRON["Cron Process"]
        direction TB
        C1["Wed + Sat 07:00 UTC:<br>geoipupdate<br>Download GeoLite2-City<br>Download GeoLite2-ASN"]
        C1 --> C2["kill -USR1 receiver<br>Trigger reload_geoip()"]
    end

    subgraph BLACKLIST_INIT["Initial Blacklist"]
        direction TB
        BL1["30s after startup:<br>BlacklistFetcher.fetch_and_store()<br>10k known-bad IPs to ip_threats"]
    end

    style SCHEDULER fill:#2980b9,color:#fff
    style BACKFILL fill:#8e44ad,color:#fff
    style UNIFI fill:#27ae60,color:#fff
    style CRON fill:#7f8c8d,color:#fff
    style BLACKLIST_INIT fill:#e67e22,color:#fff
```

## 6. API Request Flow

```mermaid
flowchart TD
    REQ["HTTP Request<br>:8090 to :8000"] --> CORS["DualCORSMiddleware<br>Cookie-auth: same-origin<br>Token-auth: permissive"]
    CORS --> AUTH["AuthMiddleware"]

    AUTH --> A1{"Public path?<br>/auth/login, /auth/setup<br>/health"}
    A1 -- Yes --> ROUTER
    A1 -- No --> A2{"Session cookie<br>or Bearer token?"}
    A2 -- Cookie --> A3["Validate session<br>Check role (admin/viewer)"]
    A2 -- Token --> A4["Validate token hash<br>Check effective_scopes<br>vs _SCOPE_MAP"]
    A2 -- Neither --> A5["401 Unauthorized"]

    A3 --> A6{"Viewer role +<br>write method?"}
    A6 -- Yes --> A7["403 Forbidden<br>read-only"]
    A6 -- No --> ROUTER

    A4 --> A8{"Scope covers<br>this path?"}
    A8 -- No --> A9["403 Insufficient scope"]
    A8 -- Yes --> ROUTER

    ROUTER["FastAPI Router<br>13 registered routers"]

    ROUTER --> R1["logs_router<br>/api/logs, /api/export"]
    ROUTER --> R2["stats_router<br>/api/stats/*"]
    ROUTER --> R3["flows_router<br>/api/flows/*"]
    ROUTER --> R4["threats_router<br>/api/threats/*"]
    ROUTER --> R5["unifi_router<br>/api/firewall/*, /api/unifi/*"]
    ROUTER --> R6["setup_router<br>/api/config/*, /api/setup/*"]
    ROUTER --> R7["Other routers<br>health, auth, tokens,<br>views, migration, mcp"]

    R1 & R2 & R3 & R4 & R5 & R6 & R7 --> DB["PostgreSQL Query<br>ThreadedConnectionPool<br>2-10 connections"]
    DB --> RESP["JSON Response<br>or SSE Stream"]

    style REQ fill:#4a90d9,color:#fff
    style AUTH fill:#f39c12,color:#fff
    style ROUTER fill:#8e44ad,color:#fff
    style DB fill:#27ae60,color:#fff
    style A5 fill:#e74c3c,color:#fff
    style A7 fill:#e74c3c,color:#fff
    style A9 fill:#e74c3c,color:#fff
```

## 7. Frontend Query Patterns

```mermaid
flowchart LR
    subgraph UI["React Dashboard"]
        direction TB
        DASH["Dashboard Page"]
        LOGS["Logs Page"]
        FLOWS["Flows Page"]
        THREATS["Threat Map"]
        FW["Firewall Policies"]
        SETTINGS["Settings"]
    end

    subgraph ENDPOINTS["API Endpoints"]
        direction TB

        subgraph DASH_API["Dashboard Queries"]
            D1["/api/stats/overview<br>allow/block/threat counts<br>direction and type breakdown"]
            D2["/api/stats/tables<br>top countries, services<br>blocked IPs, DNS, active IPs"]
            D3["/api/stats/charts<br>time-series: logs_over_time<br>traffic_by_action"]
            D4["/api/health<br>total logs, retention<br>storage, uptime"]
        end

        subgraph LOGS_API["Log Queries"]
            L1["/api/logs<br>Filtered search with pagination<br>IP, direction, action, country<br>service, protocol, threat_min"]
            L2["/api/logs/aggregate<br>GROUP BY src_ip/dst_ip/country<br>CIDR collapsing, MODE()"]
            L3["/api/logs/{id}<br>Detail view with ip_threats JOIN<br>direction-aware threat fields"]
            L4["/api/export<br>CSV streaming<br>device names + badges"]
            L5["/api/services<br>/api/protocols<br>Distinct values (cached 30s)"]
        end

        subgraph FLOWS_API["Flow Queries"]
            F1["/api/flows/graph<br>3-dimension Sankey<br>top-N remapping"]
            F2["/api/flows/zone-matrix<br>GROUP BY interface_in/out<br>allow/block counts"]
            F3["/api/flows/host-detail<br>Peer summary, port breakdown<br>device info, top connections"]
        end

        subgraph THREAT_API["Threat Queries"]
            T1["/api/threats<br>Paginated threat list<br>score >= threshold"]
            T2["/api/threats/geo<br>GeoJSON FeatureCollection<br>lat/lon clusters, top log_ids"]
            T3["/api/threats/batch<br>Bulk IP to threat lookup<br>ip_threats + recent logs"]
            T4["/api/enrich/{ip}<br>On-demand AbuseIPDB lookup<br>patch logs with results"]
        end

        subgraph FW_API["Firewall Queries"]
            FW1["/api/firewall/policies<br>Network v2 policies + zones<br>Integration-shaped response"]
            FW2["/api/firewall/policies/bulk-logging<br>Batch toggle loggingEnabled"]
            FW3["/api/firewall/policies/match-log<br>Match log to policy"]
        end

        subgraph SETTINGS_API["Settings and Config"]
            S1["/api/config<br>Merged settings JSON"]
            S2["/api/settings/unifi<br>UniFi controller config"]
            S3["/api/settings/ui<br>Theme, layout prefs"]
            S4["/api/config/retention<br>Get/set retention days"]
            S5["/api/setup/*<br>Wizard: WAN candidates<br>network segments, status"]
        end
    end

    DASH --> D1 & D2 & D3 & D4
    LOGS --> L1 & L2 & L3 & L4 & L5
    FLOWS --> F1 & F2 & F3
    THREATS --> T1 & T2 & T3 & T4
    FW --> FW1 & FW2 & FW3
    SETTINGS --> S1 & S2 & S3 & S4 & S5

    subgraph PATTERNS["Common Query Patterns"]
        direction TB
        P1["Time Range:<br>validate_time_params()<br>1h/6h/24h/7d/30d/90d"]
        P2["Device Names:<br>LATERAL JOIN unifi_clients<br>+ unifi_devices COALESCE"]
        P3["WAN IP Exclusion:<br>NOT ip = ANY(wan+gw IPs)"]
        P4["Pagination:<br>LIMIT/OFFSET<br>or pg_class estimate"]
        P5["Threat Fallback:<br>Direction-aware COALESCE<br>src threat vs dst threat"]
    end

    style UI fill:#4a90d9,color:#fff
    style PATTERNS fill:#95a5a6,color:#fff
```

## 8. UniFi Firewall API Boundary

Most UniFi data access uses the documented local Network Integration API under
`/proxy/network/integration/v1`. Firewall policy logging is intentionally
different on UniFi OS controllers running Network 10.x:

- Integration firewall policy reads can omit `id` for policies created in the
  UniFi Network UI, which makes later PATCH calls impossible.
- Integration firewall zone reads return UUID zone ids, while Network v2
  firewall policies reference Mongo-style zone ids.
- The Firewall Syslog Manager therefore reads both policies and zones from
  Network v2 endpoints and reshapes them to the existing frontend contract.

The invariant is that one `/api/firewall/policies` response must use one
identifier namespace: every `policy.source.zoneId` and
`policy.destination.zoneId` must appear in `zones[].id`. Policy writes use the
same v2 `_id` exposed as `policy.id`, fetch the full policy body, flip only the
`logging` flag, and `PUT` the full body back to Network v2.

Log-to-policy matching still needs interface membership. When v2 zone records do
not include contained `networkIds`, the matcher uses `firewall_zone_id` from the
classic `/rest/networkconf` network records to join bridge interfaces to the same
v2 zone ids.
