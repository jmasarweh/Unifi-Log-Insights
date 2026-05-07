"""
UniFi Log Insight - Queue-driven Threat Backfill (issue #67)

Replaces the sweep-style backfill that caused 30-minute SSD IO spikes.

Background daemon thread that:
1. Runs one-time gated repairs (direction, WAN IP, abuse hostname)
2. Processes the threat_backfill_queue (deferred AbuseIPDB lookups)
3. Runs targeted log patching only for IPs whose threat data changed
4. Performs low-priority stale threat re-enrichment
5. Runs one-shot service-name migration with ID cursor
"""

import time
import logging
import threading

from psycopg2 import extras

from services import get_service_mappings

logger = logging.getLogger('backfill')

QUEUE_WORKER_INTERVAL = 300       # 5 minutes
QUEUE_BATCH_SIZE = 50             # IPs per queue pass
STALE_REENRICH_BATCH = 10         # Stale IPs per pass
SERVICE_NAME_BATCH_SIZE = 1000    # Rows per service-name cursor batch
RULE_ACTION_BATCH_SIZE = 500      # Rows per rule-action cursor batch


class BackfillTask:
    """Queue-driven backfill of missing threat scores and abuse detail."""

    def __init__(self, db, enricher):
        self.db = db
        self.enricher = enricher
        self.abuseipdb = enricher.abuseipdb
        self.geoip = enricher.geoip
        self.rdns = enricher.rdns
        self._thread = None

    def start(self):
        """Start the backfill daemon thread."""
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name='backfill')
        self._thread.start()
        logger.info("Backfill task started — queue worker runs every %ds", QUEUE_WORKER_INTERVAL)

    def _run_loop(self):
        """Main loop — sleep then process queue."""
        # Initial delay: let the system settle after startup
        time.sleep(60)

        cycle = 0
        while True:
            try:
                self._run_once(cycle)
            except Exception as e:
                logger.error("Backfill cycle failed: %s", e, exc_info=True)

            cycle += 1
            time.sleep(QUEUE_WORKER_INTERVAL)

    def _run_once(self, cycle: int = 0):
        """Execute one backfill cycle."""
        # One-time gated repairs (kept from original, run every cycle until done)
        self._backfill_direction()
        self._fix_wan_ip_enrichment()
        self._fix_abuse_hostname_mixing()

        # One-shot migrations (ID cursor, persisted progress)
        self._service_name_migration()
        self._backfill_rule_action()
        self._orphan_queue_seed()

        # Queue worker: process deferred threat lookups
        self._process_queue()

        # Low-priority stale re-enrichment (every 12th cycle ≈ hourly)
        if cycle % 12 == 0:
            self._reenrich_stale_threats()

    # ── Queue worker ──────────────────────────────────────────────────────────

    def _process_queue(self):
        """Pull due IPs from the backfill queue, look them up, patch logs."""
        from db import get_wan_ips_from_config

        budget = self.abuseipdb.remaining_budget
        # Bootstrap rule: when rate-limit state is unknown (startup),
        # remaining_budget returns 0 but _check_rate_limit allows one call.
        # Allow one lookup to bootstrap rate-limit state.
        allow_bootstrap = (
            budget == 0
            and self.abuseipdb.enabled
            and not self.abuseipdb.is_rate_limit_known()
        )

        if budget == 0 and not allow_bootstrap:
            logger.debug("Queue: no API budget")
            return

        due_ips = self.db.pull_due_queue_batch(limit=QUEUE_BATCH_SIZE)
        if not due_ips:
            return

        wan_ips = get_wan_ips_from_config(self.db)
        successful_ips = []
        detail_ips = []  # IPs that gained abuse detail
        failed_ips = []

        for i, ip in enumerate(due_ips):
            # After bootstrap call, recheck budget
            if i == 1 and allow_bootstrap:
                budget = self.abuseipdb.remaining_budget
                allow_bootstrap = False
            if i > 0 and budget <= 0 and not allow_bootstrap:
                # Remaining IPs stay in queue for next cycle
                break

            result = self.abuseipdb.lookup(ip)
            if result and 'threat_score' in result:
                successful_ips.append(ip)
                if any(result.get(k) for k in (
                    'abuse_usage_type', 'abuse_hostnames',
                    'abuse_total_reports', 'abuse_last_reported',
                    'abuse_is_whitelisted', 'abuse_is_tor',
                )):
                    detail_ips.append(ip)
                budget = self.abuseipdb.remaining_budget
            else:
                failed_ips.append(ip)

            time.sleep(1)  # Avoid rapid-fire API calls

        # Targeted patching for successful lookups
        patched_cache = 0
        patched_abuse = 0
        if successful_ips:
            patched_cache = self.db.patch_from_cache_for_ips(successful_ips, wan_ips)
        if detail_ips:
            patched_abuse = self.db.patch_abuse_fields_for_ips(detail_ips, wan_ips)

        # Remove successful, backoff failed
        self.db.delete_queue_rows(successful_ips)
        self.db.fail_queue_rows(failed_ips, error='lookup_failed')

        if successful_ips or failed_ips:
            stats = self.db.get_queue_stats()
            logger.info(
                "Queue: %d looked up, %d failed, %d cache-patched, %d abuse-patched, "
                "queue: %d total (%d due, %d retried)",
                len(successful_ips), len(failed_ips),
                patched_cache, patched_abuse,
                stats['total'], stats['due'], stats['retried']
            )

    # ── Stale threat re-enrichment ────────────────────────────────────────────

    def _reenrich_stale_threats(self):
        """Re-enrich ip_threats entries missing abuse detail.

        Uses last_seen_at from ip_threats directly — no logs join.
        """
        from db import get_wan_ips_from_config

        budget = self.abuseipdb.remaining_budget
        if budget == 0:
            return 0

        batch_size = min(STALE_REENRICH_BATCH, budget)
        stale_ips = self.db.get_stale_threat_candidates(limit=batch_size)
        if not stale_ips:
            return 0

        # Expire these entries so lookup() bypasses cache and hits API
        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ip_threats SET looked_up_at = NOW() - INTERVAL '30 days' "
                    "WHERE ip = ANY(%s::inet[])",
                    [stale_ips]
                )

        # Clear from memory cache too
        for ip in stale_ips:
            self.abuseipdb.cache.delete(ip)

        reenriched = []
        detail_ips = []
        for ip in stale_ips:
            result = self.abuseipdb.lookup(ip)
            if result and 'threat_score' in result:
                reenriched.append(ip)
                if any(result.get(k) for k in (
                    'abuse_usage_type', 'abuse_hostnames',
                    'abuse_total_reports', 'abuse_last_reported',
                    'abuse_is_whitelisted', 'abuse_is_tor',
                )):
                    detail_ips.append(ip)
            time.sleep(1)

        # Targeted patching for re-enriched IPs
        if reenriched:
            wan_ips = get_wan_ips_from_config(self.db)
            self.db.patch_from_cache_for_ips(reenriched, wan_ips)
            if detail_ips:
                self.db.patch_abuse_fields_for_ips(detail_ips, wan_ips)

        if reenriched:
            logger.info("Stale re-enrichment: %d/%d refreshed (%d with abuse detail)",
                        len(reenriched), len(stale_ips), len(detail_ips))
        return len(reenriched)

    # ── One-shot service-name migration ───────────────────────────────────────

    def _service_name_migration(self):
        """One-shot ID-cursor migration for historical service_name gaps.

        Persists cursor position in system_config. Stops when complete.
        """
        from db import get_config, set_config

        if get_config(self.db, 'service_name_backfill_done', False):
            return

        last_id = get_config(self.db, 'service_name_backfill_last_id', 0) or 0
        service_map = get_service_mappings()
        total_patched = 0

        # Process one batch per cycle to avoid blocking
        rows = self.db.service_name_backfill_batch(last_id, SERVICE_NAME_BATCH_SIZE)
        if not rows:
            # No more rows — mark as done
            set_config(self.db, 'service_name_backfill_done', True)
            logger.info("Service-name backfill complete (cursor at id=%d)", last_id)
            return

        updates = []
        for row_id, dst_port, protocol in rows:
            last_id = row_id
            proto = (protocol or '').lower()
            name = service_map.get((dst_port, proto))
            if name:
                updates.append((row_id, name))

        if updates:
            total_patched = self.db.patch_service_names(updates)

        # Persist cursor
        set_config(self.db, 'service_name_backfill_last_id', last_id)

        if total_patched > 0 or len(rows) > 0:
            logger.debug("Service-name migration: %d patched in batch (cursor at id=%d)",
                         total_patched, last_id)

    # ── One-shot rule_action backfill for zone_index format rules ────────────

    def _backfill_rule_action(self):
        """One-shot ID-cursor repair for zone_index format rules stored with wrong rule_action.

        New-format rule names (ZONE_ZONE-INDEX) lack an embedded action code,
        so derive_action() previously defaulted them to 'allow'. This backfill
        resolves the correct action via policy metadata or description fallback.

        Performance note: the regex filter in the query is applied by Postgres
        during the index scan — non-matching rows are not sent to Python but
        ARE examined by the database. Runtime depends on match sparsity and
        distribution across the id range, not just match count. On large tables
        (20M+ rows) with sparse matches, individual batches may scan large id
        ranges. This is a one-time migration cost; consider running off-peak.
        """
        from db import get_config, set_config
        from firewall_policy_matcher import parse_firewall_rule, resolve_rule_action

        if get_config(self.db, 'rule_action_backfill_done', False):
            return

        last_id = get_config(self.db, 'rule_action_backfill_last_id', 0) or 0

        # UniFi API is optional — desc_hint fallback works without it
        has_unifi = self.enricher.unifi and self.enricher.unifi.enabled
        vpn_networks = {}
        if has_unifi:
            from db import parse_vpn_config
            vpn_networks = parse_vpn_config(get_config(self.db, 'vpn_networks'))

        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, rule_name, rule_desc, rule_action, interface_in, interface_out "
                    "FROM logs "
                    "WHERE id > %s "
                    "  AND log_type = 'firewall' "
                    "  AND rule_name ~ '^[A-Z][A-Z0-9]*_[A-Z][A-Z0-9]*-[0-9]+$' "
                    "ORDER BY id LIMIT %s",
                    [last_id, RULE_ACTION_BATCH_SIZE]
                )
                rows = cur.fetchall()

        if not rows:
            set_config(self.db, 'rule_action_backfill_done', True)
            logger.info("Rule-action backfill complete (cursor at id=%d)", last_id)
            return

        updates = []
        for row_id, rule_name, rule_desc, stored_action, iface_in, iface_out in rows:
            last_id = row_id
            parsed_rule = parse_firewall_rule(rule_name, rule_desc=rule_desc)
            if not parsed_rule or parsed_rule['format'] != 'zone_index':
                continue
            # resolve_rule_action handles both policy lookup (preferred) and desc_hint fallback
            action = resolve_rule_action(
                parsed_rule, self.enricher.unifi if has_unifi else None,
                interface_in=iface_in or '',
                interface_out=iface_out or '',
                vpn_networks=vpn_networks,
            )
            if action and action != stored_action:
                updates.append((row_id, action))

        if updates:
            with self.db.get_conn() as conn:
                with conn.cursor() as cur:
                    extras.execute_batch(
                        cur,
                        "UPDATE logs SET rule_action = %s WHERE id = %s",
                        [(action, row_id) for row_id, action in updates]
                    )
                    conn.commit()
            logger.debug("Rule-action backfill: %d rows patched in batch (cursor at id=%d)",
                         len(updates), last_id)

        set_config(self.db, 'rule_action_backfill_last_id', last_id)

    def _orphan_queue_seed(self):
        """One-time seed: scan historical logs for orphan IPs missing from ip_threats.

        Uses ID-cursor batching to avoid full-table scans. Seeds the
        threat_backfill_queue so the queue worker can process them gradually.
        Persists cursor position in system_config. Stops when complete.
        Gated on AbuseIPDB being enabled — no point seeding a queue that can't drain.
        """
        from db import get_config, set_config

        if not self.abuseipdb.enabled:
            return

        if get_config(self.db, 'orphan_queue_seed_done', False):
            return

        last_id = get_config(self.db, 'orphan_queue_seed_last_id', 0) or 0
        batch_size = 2000  # Larger batch OK — just reading IDs + lightweight inserts

        # Read a batch of firewall/block log IDs where threat_score IS NULL
        with self.db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, host(src_ip) as src, host(dst_ip) as dst "
                    "FROM logs "
                    "WHERE id > %s "
                    "  AND log_type = 'firewall' "
                    "  AND rule_action = 'block' "
                    "  AND threat_score IS NULL "
                    "ORDER BY id LIMIT %s",
                    [last_id, batch_size]
                )
                rows = cur.fetchall()

        if not rows:
            set_config(self.db, 'orphan_queue_seed_done', True)
            logger.info("Orphan queue seed complete (cursor at id=%d)", last_id)
            return

        # Collect distinct remote IPs from this batch
        candidate_ips = set()
        for row_id, src, dst in rows:
            last_id = row_id
            if src and self.enricher._is_remote_ip(src):
                candidate_ips.add(src)
            if dst and self.enricher._is_remote_ip(dst):
                candidate_ips.add(dst)

        # Filter out IPs already in ip_threats
        if candidate_ips:
            ip_list = list(candidate_ips)
            with self.db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT host(ip) FROM ip_threats WHERE ip = ANY(%s::inet[])",
                        [ip_list]
                    )
                    already_known = {row[0] for row in cur.fetchall()}

            orphans = candidate_ips - already_known
            for ip in orphans:
                try:
                    self.db.enqueue_threat_backfill(ip, source='seed')
                except Exception:
                    logger.debug("Failed to seed-enqueue %s", ip, exc_info=True)

            if orphans:
                logger.debug("Orphan seed: enqueued %d IPs from batch (cursor at id=%d)",
                             len(orphans), last_id)

        set_config(self.db, 'orphan_queue_seed_last_id', last_id)

    # ── One-time gated repairs (kept from original) ───────────────────────────

    def _backfill_direction(self) -> int:
        """Re-derive direction for firewall logs when WAN interfaces change.

        Only processes firewall logs (direction is derived from iptables interfaces).
        Uses ID-cursor batching for optimal performance (avoids OFFSET scan overhead).
        Returns number of rows updated.
        """
        import parsers
        from db import get_config, set_config

        # Check if backfill is needed
        if not get_config(self.db, 'direction_backfill_pending', False):
            return 0

        logger.debug("Starting direction backfill...")

        total_updated = 0
        batch_size = 500
        last_id = 0

        while True:
            # Fetch batch using ID cursor (faster than OFFSET on large tables)
            with self.db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id, interface_in, interface_out, rule_name,
                               src_ip::text, dst_ip::text
                        FROM logs
                        WHERE log_type = 'firewall' AND id > %s
                        ORDER BY id
                        LIMIT %s
                    """, [last_id, batch_size])
                    rows = cur.fetchall()

            if not rows:
                break

            # Re-derive directions using current WAN_INTERFACES
            updates = []
            for row in rows:
                id_val, iface_in, iface_out, rule_name, src_ip, dst_ip = row
                new_direction = parsers.derive_direction(
                    iface_in, iface_out, rule_name, src_ip, dst_ip
                )
                updates.append((new_direction, id_val))
                last_id = id_val

            # Batch update
            with self.db.get_conn() as conn:
                with conn.cursor() as cur:
                    extras.execute_batch(cur,
                        "UPDATE logs SET direction = %s WHERE id = %s",
                        updates, page_size=500
                    )

            total_updated += len(updates)
            logger.debug("Direction backfill progress: %d logs updated", total_updated)

        # Clear the pending flag
        set_config(self.db, 'direction_backfill_pending', False)
        logger.info("Direction backfill complete: %d total logs updated", total_updated)
        return total_updated

    def _fix_wan_ip_enrichment(self) -> int:
        """One-time fix: re-enrich logs that were enriched on our WAN IP.

        Finds firewall logs where src_ip is a known WAN IP and enrichment
        data exists (geo_country not null) — these have our own ISP's data
        instead of the remote endpoint's. Re-enriches with dst_ip using
        local GeoIP/ASN/rDNS lookups (zero API cost). NULLs threat/abuse
        fields so targeted patching re-fills from the correct IP.

        Gated by 'enrichment_wan_fix_pending' config flag — runs once.
        """
        from db import get_config, set_config, get_wan_ips_from_config

        if not get_config(self.db, 'enrichment_wan_fix_pending', False):
            return 0

        wan_ips = get_wan_ips_from_config(self.db)
        if not wan_ips:
            return 0

        logger.info("Starting WAN IP enrichment fix (WAN IPs: %s)...", wan_ips)

        total_fixed = 0
        affected_remote_ips = set()  # Collect for targeted cache refill
        batch_size = 500
        last_id = 0

        while True:
            with self.db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id, host(dst_ip) as dst_ip
                        FROM logs
                        WHERE log_type = 'firewall'
                          AND src_ip = ANY(%s::inet[])
                          AND geo_country IS NOT NULL
                          AND dst_ip IS NOT NULL
                          AND id > %s
                        ORDER BY id
                        LIMIT %s
                    """, [wan_ips, last_id, batch_size])
                    rows = cur.fetchall()

            if not rows:
                break

            updates = []
            for row in rows:
                id_val, dst_ip = row
                last_id = id_val

                if not self.enricher._is_remote_ip(dst_ip):
                    updates.append((
                        None, None, None, None, None, None, None,
                        None, None, None, None, None, None, None, None,
                        id_val
                    ))
                    continue

                affected_remote_ips.add(dst_ip)
                geo = self.geoip.lookup(dst_ip)
                if self.enricher._rdns_enabled:
                    rdns = self.rdns.lookup(dst_ip)
                else:
                    rdns = {'rdns': None}

                updates.append((
                    geo.get('geo_country'), geo.get('geo_city'),
                    geo.get('geo_lat'), geo.get('geo_lon'),
                    geo.get('asn_number'), geo.get('asn_name'),
                    rdns.get('rdns'),
                    None, None, None, None, None, None, None, None,
                    id_val
                ))

            if updates:
                with self.db.get_conn() as conn:
                    with conn.cursor() as cur:
                        extras.execute_batch(cur, """
                            UPDATE logs SET
                                geo_country = %s, geo_city = %s,
                                geo_lat = %s, geo_lon = %s,
                                asn_number = %s, asn_name = %s,
                                rdns = %s,
                                threat_score = %s, threat_categories = %s,
                                abuse_usage_type = %s, abuse_hostnames = %s,
                                abuse_total_reports = %s, abuse_last_reported = %s,
                                abuse_is_whitelisted = %s, abuse_is_tor = %s
                            WHERE id = %s
                        """, updates, page_size=500)

            total_fixed += len(updates)
            logger.debug("WAN enrichment fix progress: %d logs fixed", total_fixed)

        # Refill NULLed threat/abuse fields from ip_threats for affected IPs
        if affected_remote_ips:
            refilled = self.db.patch_from_cache_for_ips(
                list(affected_remote_ips), wan_ips
            )
            if refilled:
                logger.info("WAN fix: refilled %d log rows from ip_threats cache", refilled)

        set_config(self.db, 'enrichment_wan_fix_pending', False)
        logger.info("Enrichment WAN fix complete: %d logs re-enriched", total_fixed)
        return total_fixed

    def _fix_abuse_hostname_mixing(self) -> int:
        """One-time fix: repair logs contaminated by WAN IP abuse data (issue #30).

        The direction-blind UPDATE in manual enrichment wrote WAN IP's abuse
        data (hostname, usage_type, threat_score) onto attacker logs where the
        WAN IP was dst. This migration:
        1. Deletes WAN/gateway entries from ip_threats
        2. Re-patches corrupted log rows from the correct src_ip's ip_threats
        3. NULLs abuse fields for rows with no ip_threats entry

        Gated by 'abuse_hostname_fix_done' config flag — runs once.
        """
        from psycopg2.extras import RealDictCursor
        from db import get_config, set_config, get_wan_ips_from_config

        if get_config(self.db, 'abuse_hostname_fix_done', False):
            return 0

        wan_ips = get_wan_ips_from_config(self.db)
        if not wan_ips:
            return 0

        gateway_ips = get_config(self.db, 'gateway_ips') or []
        all_excluded = wan_ips + gateway_ips

        logger.info("Starting abuse hostname fix (WAN IPs: %s, gateway IPs: %s)...",
                     wan_ips, gateway_ips)

        # Step A: Delete WAN/gateway entries from ip_threats
        with self.db.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT host(ip) as ip_text, abuse_hostnames, abuse_usage_type "
                    "FROM ip_threats WHERE ip = ANY(%s::inet[])",
                    [all_excluded],
                )
                wan_entries = cur.fetchall()
                if wan_entries:
                    logger.info(
                        "Removing %d WAN/gateway entries from ip_threats: %s",
                        len(wan_entries),
                        [e['ip_text'] for e in wan_entries],
                    )
                    cur.execute(
                        "DELETE FROM ip_threats WHERE ip = ANY(%s::inet[])",
                        [all_excluded],
                    )

        # Step B: Repair corrupted log rows using ID-cursor batching
        total_fixed = 0
        batch_size = 500
        last_id = 0

        while True:
            with self.db.get_conn() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT id, host(src_ip) as src_ip
                        FROM logs
                        WHERE dst_ip = ANY(%s::inet[])
                          AND direction IN ('inbound', 'in')
                          AND src_ip != ALL(%s::inet[])
                          AND (abuse_hostnames IS NOT NULL
                               OR abuse_usage_type IS NOT NULL)
                          AND id > %s
                        ORDER BY id
                        LIMIT %s
                    """, [wan_ips, all_excluded, last_id, batch_size])
                    rows = cur.fetchall()

            if not rows:
                break

            src_ips = list({row['src_ip'] for row in rows})
            with self.db.get_conn() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT host(ip) as ip_text, threat_score, threat_categories,
                               abuse_usage_type, abuse_hostnames, abuse_total_reports,
                               abuse_last_reported, abuse_is_whitelisted, abuse_is_tor
                        FROM ip_threats WHERE ip = ANY(%s::inet[])
                    """, [src_ips])
                    threats_by_ip = {r['ip_text']: r for r in cur.fetchall()}

            updates = []
            for row in rows:
                last_id = row['id']
                threat = threats_by_ip.get(row['src_ip'])
                if threat:
                    updates.append((
                        threat['threat_score'], threat['threat_categories'],
                        threat['abuse_usage_type'], threat['abuse_hostnames'],
                        threat['abuse_total_reports'], threat['abuse_last_reported'],
                        threat['abuse_is_whitelisted'], threat['abuse_is_tor'],
                        row['id'],
                    ))
                else:
                    updates.append((
                        None, None, None, None, None, None, None, None,
                        row['id'],
                    ))

            if updates:
                with self.db.get_conn() as conn:
                    with conn.cursor() as cur:
                        extras.execute_batch(cur, """
                            UPDATE logs SET
                                threat_score = %s, threat_categories = %s,
                                abuse_usage_type = %s, abuse_hostnames = %s,
                                abuse_total_reports = %s, abuse_last_reported = %s,
                                abuse_is_whitelisted = %s, abuse_is_tor = %s
                            WHERE id = %s
                        """, updates, page_size=500)

            total_fixed += len(rows)
            logger.debug("Abuse hostname fix progress: %d logs processed", total_fixed)

        set_config(self.db, 'abuse_hostname_fix_done', True)
        logger.info("Abuse hostname fix complete: %d logs repaired", total_fixed)
        return total_fixed
