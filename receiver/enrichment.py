"""
UniFi Log Insight - IP Enrichment

Enriches public IPs with:
- GeoIP (country, city, lat/lon) via MaxMind GeoLite2-City
- ASN (number, name) via MaxMind GeoLite2-ASN
- Threat score via AbuseIPDB (blocked firewall events only, cached 24h)
- Reverse DNS via PTR lookup (cached 24h)
"""

import os
import json
import socket
import ipaddress
import logging
import time
import threading
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Private/reserved IP detection ─────────────────────────────────────────────

def is_public_ip(ip_str: str) -> bool:
    """Check if an IP is public (not RFC1918, ULA, loopback, link-local, multicast).

    Works for both IPv4 and IPv6 addresses using Python's built-in is_global.
    """
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return False


# ── AbuseIPDB stats retrieval ────────────────────────────────────────────────

def get_abuseipdb_stats(db):
    """Load AbuseIPDB rate-limit state from tmp file with DB fallback.

    Read order:
      1. /tmp/abuseipdb_stats.json  (written by receiver process each API call)
      2. system_config.abuseipdb_rate_limit  (persisted by enricher on shutdown)

    Returns dict with keys: limit, remaining, reset_at, paused_until, quota_reset_pending
    or None if no stats are available.
    """
    from db import get_config

    stats = None
    try:
        with open('/tmp/abuseipdb_stats.json', 'r') as f:
            stats = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    if not stats or stats.get('limit') is None:
        try:
            db_stats = get_config(db, 'abuseipdb_rate_limit')
            if db_stats:
                paused = db_stats.get('paused_until')
                pause_active = False
                if paused:
                    try:
                        pause_active = time.time() < float(paused)
                    except (ValueError, TypeError):
                        pass
                if db_stats.get('limit') is not None or pause_active:
                    stats = db_stats
        except Exception as e:
            logger.debug("Failed to read AbuseIPDB stats from DB: %s", e)
    return stats


# ── Thread-safe cache ─────────────────────────────────────────────────────────

class TTLCache:
    """Simple thread-safe cache with TTL expiry."""

    def __init__(self, ttl_seconds: int = 86400):
        self.ttl = ttl_seconds
        self._cache = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and time.time() - entry['time'] < self.ttl:
                return entry['value']
            elif entry:
                del self._cache[key]
            return None

    def set(self, key: str, value: dict):
        with self._lock:
            self._cache[key] = {'value': value, 'time': time.time()}

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def delete(self, key: str):
        with self._lock:
            self._cache.pop(key, None)


# ── GeoIP Enrichment ─────────────────────────────────────────────────────────

class GeoIPEnricher:
    """MaxMind GeoLite2 lookups for City and ASN."""

    def __init__(self, db_dir: str = '/app/maxmind'):
        self.city_reader = None
        self.asn_reader = None
        self.db_dir = db_dir
        self._load_databases(db_dir)

    def _load_databases(self, db_dir: str):
        try:
            import geoip2.database
            city_path = os.path.join(db_dir, 'GeoLite2-City.mmdb')
            asn_path = os.path.join(db_dir, 'GeoLite2-ASN.mmdb')

            if os.path.exists(city_path):
                self.city_reader = geoip2.database.Reader(city_path)
                logger.info("Loaded GeoLite2-City database")
            else:
                logger.warning("GeoLite2-City.mmdb not found at %s", city_path)

            if os.path.exists(asn_path):
                self.asn_reader = geoip2.database.Reader(asn_path)
                logger.info("Loaded GeoLite2-ASN database")
            else:
                logger.warning("GeoLite2-ASN.mmdb not found at %s", asn_path)

        except ImportError:
            logger.error("geoip2 package not installed")
        except Exception as e:
            logger.error("Failed to load MaxMind databases: %s", e)

    def reload(self):
        """Reload databases from disk (called after geoipupdate)."""
        logger.info("Reloading MaxMind databases...")
        old_city = self.city_reader
        old_asn = self.asn_reader
        self._load_databases(self.db_dir)
        # Close old readers after loading new ones
        if old_city:
            try: old_city.close()
            except: pass
        if old_asn:
            try: old_asn.close()
            except: pass
        logger.info("MaxMind databases reloaded")

    def lookup(self, ip_str: str) -> dict:
        """Look up GeoIP and ASN data for an IP. Returns dict of fields."""
        result = {}

        if self.city_reader:
            try:
                resp = self.city_reader.city(ip_str)
                result['geo_country'] = resp.country.iso_code
                result['geo_city'] = resp.city.name
                if resp.location:
                    result['geo_lat'] = float(resp.location.latitude) if resp.location.latitude else None
                    result['geo_lon'] = float(resp.location.longitude) if resp.location.longitude else None
            except Exception:
                pass

        if self.asn_reader:
            try:
                resp = self.asn_reader.asn(ip_str)
                result['asn_number'] = resp.autonomous_system_number
                result['asn_name'] = resp.autonomous_system_organization
            except Exception:
                pass

        return result

    def close(self):
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()


# ── AbuseIPDB Enrichment ─────────────────────────────────────────────────────

class AbuseIPDBEnricher:
    """AbuseIPDB threat score lookups. Only for blocked firewall events."""

    API_URL = 'https://api.abuseipdb.com/api/v2/check'
    STATS_FILE = '/tmp/abuseipdb_stats.json'

    def __init__(self, api_key: str = None, db=None):
        self.api_key = api_key if api_key is not None else os.environ.get('ABUSEIPDB_API_KEY', '')
        self.cache = TTLCache(ttl_seconds=86400)  # 24h in-memory hot cache
        self.db = db  # Database instance for persistent threat cache
        self.enabled = bool(self.api_key)
        self._lock = threading.Lock()
        self.STALE_DAYS = 4  # Refresh from API after this many days
        self.SAFETY_BUFFER = 0  # No reserve — first come first serve

        # Rate limit state — None means unknown (not yet bootstrapped)
        # After first API call, these are set from response headers
        self._rate_limit_limit = None      # e.g. 1000
        self._rate_limit_remaining = None  # e.g. 743
        self._rate_limit_reset = None      # Unix timestamp (seconds)

        # Pause until this UTC timestamp on 429
        self._paused_until = 0.0

        # IPs to exclude from lookups (e.g. our own WAN IP)
        self._excluded_ips = set()

        if self.enabled:
            logger.info("AbuseIPDB enrichment enabled (safety buffer: %d)", self.SAFETY_BUFFER)
            self._load_persisted_stats()
            self._write_stats()
        else:
            logger.warning("AbuseIPDB API key not set — threat enrichment disabled")

    def _load_persisted_stats(self):
        """Restore rate limit state from database on startup.

        If reset_at has passed, treat quota as renewed.
        If paused_until has expired, clear it.
        Missing fields stay None to preserve bootstrap semantics.
        """
        if not self.db:
            return
        try:
            stats = self.db.get_config('abuseipdb_rate_limit')
            if not stats:
                return

            # Restore pause even if limit is None (429 before first success)
            paused = stats.get('paused_until')
            if paused and float(paused) > time.time():
                self._paused_until = float(paused)
            else:
                self._paused_until = 0.0

            # Only restore rate limit fields if we have real data
            if stats.get('limit') is None:
                if self._paused_until > 0:
                    logger.info(
                        "AbuseIPDB: restored pause (until %s), no rate limit data yet",
                        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._paused_until))
                    )
                return

            self._rate_limit_limit = stats.get('limit')
            self._rate_limit_remaining = stats.get('remaining')
            self._rate_limit_reset = stats.get('reset_at')

            # If reset_at has passed, quota is renewed
            if self._rate_limit_reset is not None:
                try:
                    if time.time() > float(self._rate_limit_reset):
                        logger.info(
                            "AbuseIPDB: persisted reset_at %s has passed, "
                            "restoring quota to %s",
                            self._rate_limit_reset, self._rate_limit_limit
                        )
                        self._rate_limit_remaining = self._rate_limit_limit
                        self._rate_limit_reset = None
                        self._paused_until = 0.0
                except (ValueError, TypeError):
                    pass

            logger.info(
                "AbuseIPDB: restored persisted stats "
                "(limit=%s, remaining=%s, reset_at=%s)",
                self._rate_limit_limit,
                self._rate_limit_remaining,
                self._rate_limit_reset,
            )
        except Exception as e:
            logger.warning("Failed to load persisted AbuseIPDB stats: %s", e)

    def exclude_ip(self, ip_str: str):
        """Add an IP to the exclusion list (e.g. our own WAN IP)."""
        if ip_str:
            self._excluded_ips.add(ip_str)
            logger.info("AbuseIPDB: excluding IP %s from lookups", ip_str)

    def _check_rate_limit(self) -> bool:
        """Check if we can make an API call.
        
        Uses AbuseIPDB's own headers as the single source of truth.
        On first call after startup, remaining is None → allow it to bootstrap.
        """
        with self._lock:
            # Hard pause from 429
            if time.time() < self._paused_until:
                return False

            # Check if quota has reset (reset_at has passed)
            if self._rate_limit_reset is not None:
                try:
                    reset_ts = float(self._rate_limit_reset)
                    if time.time() > reset_ts:
                        # Quota has renewed — restore to known limit
                        logger.info("AbuseIPDB quota reset (reset_at %s has passed)", self._rate_limit_reset)
                        self._rate_limit_remaining = self._rate_limit_limit  # e.g. 1000; None if unknown
                        self._rate_limit_reset = None
                        self._paused_until = 0.0
                        self._write_stats()  # Persist so API process sees the reset
                except (ValueError, TypeError):
                    pass

            # Unknown state (startup or after reset) → allow one call to bootstrap
            if self._rate_limit_remaining is None:
                return True

            # Gate on real remaining with safety buffer
            return self._rate_limit_remaining > self.SAFETY_BUFFER

    @property
    def remaining_budget(self) -> int:
        """How many API calls we can still make this period.

        Used by backfill to limit orphan lookups.
        Returns 0 if unknown or exhausted.
        """
        self._check_rate_limit()  # Detect daily reset before reading state
        with self._lock:
            if self._rate_limit_remaining is None:
                return 0  # Unknown — don't let backfill guess
            return max(0, self._rate_limit_remaining - self.SAFETY_BUFFER)

    def _update_rate_limits(self, resp_headers):
        """Update rate limit state from AbuseIPDB response headers."""
        with self._lock:
            limit = resp_headers.get('X-RateLimit-Limit')
            remaining = resp_headers.get('X-RateLimit-Remaining')
            reset_ts = resp_headers.get('X-RateLimit-Reset')
            if limit is not None:
                self._rate_limit_limit = int(limit)
            if remaining is not None:
                self._rate_limit_remaining = int(remaining)
            if reset_ts is not None:
                self._rate_limit_reset = reset_ts

    def _write_stats(self):
        """Write rate limit stats to shared file for API/UI to read,
        and persist to database for survival across restarts."""
        stats = {
            'limit': self._rate_limit_limit,
            'remaining': self._rate_limit_remaining,
            'reset_at': self._rate_limit_reset,
            'paused_until': self._paused_until if self._paused_until > time.time() else None,
            'updated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }
        # IPC: tmp file for API process
        try:
            with open(self.STATS_FILE, 'w') as f:
                json.dump(stats, f)
        except Exception:
            pass  # Non-critical, don't break enrichment
        # Persistence: DB for restart survival
        # Persist when we have real rate limit data OR an active pause (429
        # before first successful call still needs to survive restarts)
        should_persist = (self._rate_limit_limit is not None
                          or self._paused_until > time.time())
        if self.db and should_persist:
            try:
                self.db.set_config('abuseipdb_rate_limit', stats)
            except Exception:
                pass

    def lookup(self, ip_str: str) -> dict:
        """Check an IP against AbuseIPDB. Returns threat_score and categories.
        
        Lookup order:
        1. In-memory cache (hot path, no I/O)
        2. DB ip_threats table (< 4 days old)
        3. AbuseIPDB API (writes back to DB + memory cache)
        """
        if not self.enabled:
            return {}

        # Skip excluded IPs (our WAN IP)
        if ip_str in self._excluded_ips:
            return {}

        # 1. Check in-memory cache
        cached = self.cache.get(ip_str)
        if cached is not None:
            return cached

        # 2. Check persistent DB cache
        if self.db:
            try:
                db_result = self.db.get_threat_cache(ip_str, max_age_days=self.STALE_DAYS)
                if db_result:
                    self.cache.set(ip_str, db_result)  # Promote to memory cache
                    return db_result
            except Exception as e:
                logger.debug("DB threat cache lookup failed for %s: %s", ip_str, e)

        # 3. Check rate limit before API call
        if not self._check_rate_limit():
            return {}

        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json',
            }
            params = {
                'ipAddress': ip_str,
                'maxAgeInDays': 90,
                'verbose': 'true',
            }
            resp = requests.get(self.API_URL, headers=headers, params=params, timeout=5)

            # Handle 429 — pause until reset
            if resp.status_code == 429:
                with self._lock:
                    retry_after = resp.headers.get('Retry-After')
                    reset_ts = resp.headers.get('X-RateLimit-Reset')
                    if retry_after:
                        self._paused_until = time.time() + int(retry_after)
                    elif reset_ts:
                        try:
                            self._paused_until = float(reset_ts)
                        except (ValueError, TypeError):
                            self._paused_until = time.time() + 3600
                    else:
                        self._paused_until = time.time() + 3600  # fallback: 1h
                    self._rate_limit_remaining = 0
                logger.warning("AbuseIPDB 429 — paused until %s",
                             time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._paused_until)))
                self._write_stats()
                return {}

            resp.raise_for_status()
            data = resp.json().get('data', {})

            # Aggregate categories from all reports (verbose mode)
            all_cats = set()
            for report in data.get('reports', []):
                for cat in report.get('categories', []):
                    all_cats.add(str(cat))

            result = {
                'threat_score': data.get('abuseConfidenceScore', 0),
                'threat_categories': sorted(all_cats),
            }

            # Extra AbuseIPDB detail fields
            usage_type = data.get('usageType')
            if usage_type:
                result['abuse_usage_type'] = usage_type

            hostnames = data.get('hostnames', [])
            if hostnames:
                result['abuse_hostnames'] = ', '.join(hostnames)

            total_reports = data.get('totalReports')
            if total_reports is not None:
                result['abuse_total_reports'] = total_reports

            last_reported = data.get('lastReportedAt')
            if last_reported:
                result['abuse_last_reported'] = last_reported

            is_whitelisted = data.get('isWhitelisted')
            if is_whitelisted:
                result['abuse_is_whitelisted'] = True

            is_tor = data.get('isTor')
            if is_tor:
                result['abuse_is_tor'] = True

            # Update rate limits from response headers (source of truth)
            self._update_rate_limits(resp.headers)

            # Persist to DB and memory cache
            if self.db:
                try:
                    self.db.upsert_threat(ip_str, result)
                except Exception as e:
                    logger.debug("DB threat cache write failed for %s: %s", ip_str, e)

            self._write_stats()
            self.cache.set(ip_str, result)
            return result

        except requests.Timeout:
            logger.warning("AbuseIPDB timeout for %s", ip_str)
        except requests.RequestException as e:
            logger.warning("AbuseIPDB error for %s: %s", ip_str, e)
        except Exception as e:
            logger.error("AbuseIPDB unexpected error: %s", e)

        return {}

    @property
    def daily_usage(self) -> int:
        """Derived from API headers: limit - remaining."""
        with self._lock:
            if self._rate_limit_limit is None or self._rate_limit_remaining is None:
                return 0
            return self._rate_limit_limit - self._rate_limit_remaining


# ── Reverse DNS ───────────────────────────────────────────────────────────────

class RDNSEnricher:
    """Reverse DNS (PTR) lookups with caching."""

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.cache = TTLCache(ttl_seconds=86400)  # 24h cache

    def lookup(self, ip_str: str) -> dict:
        """Perform rDNS lookup. Returns {'rdns': hostname} or {}."""
        cached = self.cache.get(ip_str)
        if cached is not None:
            return cached

        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            result = {'rdns': hostname}
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            result = {'rdns': None}

        self.cache.set(ip_str, result)
        return result


# ── Main Enrichment Pipeline ──────────────────────────────────────────────────

class Enricher:
    """Orchestrates all enrichment for a parsed log entry."""

    # Coalescing TTL for touch/enqueue DB writes (seconds)
    _COALESCE_TTL = 60.0
    # Max entries before lazy-pruning the coalescing map
    _COALESCE_MAP_MAX_SIZE = 256

    def __init__(self, db=None, unifi=None):
        self.geoip = GeoIPEnricher()
        self.abuseipdb = AbuseIPDBEnricher(db=db)
        self.rdns = RDNSEnricher()
        self.unifi = unifi
        self._db = db
        self._known_wan_ip = None
        self._excluded_ips = set()  # WAN IPs, gateway IPs — not enrichable
        # @coderabbit Accessed only from the single-threaded UDP receive/enrich
        # loop today, so this coalescing map intentionally does not use a lock.
        # If enrich() is ever called concurrently, revisit Enricher shared-state
        # locking.
        self._recently_touched = {}  # {ip: monotonic_time} — coalescing set for DB writes

        # Pre-load WAN/gateway exclusions from DB so background threads
        # (backfill) have exclusions before the first enrich() call
        if db:
            try:
                from db import get_config, get_wan_ips_from_config
                for ip in get_wan_ips_from_config(db):
                    self._excluded_ips.add(ip)
                    self.abuseipdb.exclude_ip(ip)
                for ip in get_config(db, 'gateway_ips') or []:
                    self._excluded_ips.add(ip)
            except Exception:
                logger.debug("Failed to pre-load exclusions from DB", exc_info=True)

    def _is_remote_ip(self, ip_str: str) -> bool:
        """Check if IP is remote (enrichable): public, not our WAN, not gateway."""
        if not ip_str:
            return False
        if not is_public_ip(ip_str):
            return False
        if ip_str in self._excluded_ips:
            return False
        return True

    def _is_recently_touched(self, ip: str) -> bool:
        """Check if an IP was touched/enqueued within the coalescing TTL.

        Also prunes expired entries to prevent unbounded growth.
        """
        now = time.monotonic()
        ts = self._recently_touched.get(ip)
        if ts is not None and (now - ts) < self._COALESCE_TTL:
            return True
        # Lazy prune: when map exceeds threshold, remove expired entries
        if len(self._recently_touched) > self._COALESCE_MAP_MAX_SIZE:
            cutoff = now - self._COALESCE_TTL
            self._recently_touched = {
                k: v for k, v in self._recently_touched.items() if v > cutoff
            }
        return False

    def enrich(self, parsed: dict) -> dict:
        """Enrich a parsed log entry with GeoIP, ASN, threat, and rDNS data.

        Strategy:
        - GeoIP + ASN: all remote public IPs (local lookups, fast)
        - AbuseIPDB: only blocked firewall events with remote public IPs
        - rDNS: all remote public IPs

        WAN and gateway IPs are excluded — they belong to us, not the remote party.
        """
        # Auto-exclude WAN IPs (v4 + v6) from enrichment as they're learned
        from parsers import get_wan_ip
        wan_ip = get_wan_ip()
        if wan_ip and wan_ip != self._known_wan_ip:
            self._known_wan_ip = wan_ip
            self._excluded_ips.add(wan_ip)
            self.abuseipdb.exclude_ip(wan_ip)
            # Refresh full wan_ips + gateway_ips from DB
            if self._db:
                from db import get_config, get_wan_ips_from_config
                for ip in get_wan_ips_from_config(self._db):
                    self._excluded_ips.add(ip)
                    if ip not in self.abuseipdb._excluded_ips:
                        self.abuseipdb.exclude_ip(ip)
                for ip in get_config(self._db, 'gateway_ips') or []:
                    self._excluded_ips.add(ip)

        # Determine which IP to enrich — the remote party, not our infrastructure
        ip_to_enrich = None
        src_ip = parsed.get('src_ip')
        dst_ip = parsed.get('dst_ip')
        src_remote = self._is_remote_ip(src_ip)
        dst_remote = self._is_remote_ip(dst_ip)

        # Device name resolution (private IPs) — runs BEFORE public IP guard
        # so inter-VLAN and local-only traffic still gets device names
        if self.unifi and self.unifi.enabled:
            try:
                if src_ip and not src_remote:
                    parsed['src_device_name'] = self.unifi.resolve_name(
                        ip=src_ip, mac=parsed.get('mac_address'))
                if dst_ip and not dst_remote:
                    parsed['dst_device_name'] = self.unifi.resolve_name(ip=dst_ip)
            except Exception:
                logger.debug("Device name resolution failed for src=%s dst=%s", src_ip, dst_ip, exc_info=True)

        if src_remote and not dst_remote:
            ip_to_enrich = src_ip
        elif dst_remote and not src_remote:
            ip_to_enrich = dst_ip
        elif src_remote and dst_remote:
            ip_to_enrich = src_ip

        parsed['remote_ip'] = ip_to_enrich
        if not ip_to_enrich:
            return parsed

        # GeoIP + ASN (always, local lookup)
        geo_data = self.geoip.lookup(ip_to_enrich)
        parsed.update(geo_data)

        # rDNS (always for public IPs)
        rdns_data = self.rdns.lookup(ip_to_enrich)
        if rdns_data.get('rdns'):
            parsed['rdns'] = rdns_data['rdns']

        # AbuseIPDB (only for blocked firewall events)
        if (parsed.get('log_type') == 'firewall'
                and parsed.get('rule_action') == 'block'):
            threat_data = self.abuseipdb.lookup(ip_to_enrich)
            if threat_data:
                parsed.update(threat_data)
                # Touch last_seen_at — coalesced to avoid per-packet DB writes
                if self._db and not self._is_recently_touched(ip_to_enrich):
                    try:
                        self._db.touch_threat_last_seen(ip_to_enrich)
                    except Exception:
                        logger.debug("touch_threat_last_seen failed for %s", ip_to_enrich, exc_info=True)
                    self._recently_touched[ip_to_enrich] = time.monotonic()
            elif self.abuseipdb.enabled and self._db:
                # Enqueue for deferred lookup — coalesced, only when AbuseIPDB is configured
                if not self._is_recently_touched(ip_to_enrich):
                    try:
                        self._db.enqueue_threat_backfill(ip_to_enrich, source='live_miss')
                    except Exception:
                        logger.debug("enqueue_threat_backfill failed for %s", ip_to_enrich, exc_info=True)
                    self._recently_touched[ip_to_enrich] = time.monotonic()

        return parsed

    def get_stats(self) -> dict:
        """Return enrichment cache stats."""
        return {
            'geoip_loaded': self.geoip.city_reader is not None,
            'asn_loaded': self.geoip.asn_reader is not None,
            'abuseipdb_enabled': self.abuseipdb.enabled,
            'abuseipdb_daily_usage': self.abuseipdb.daily_usage,
            'abuseipdb_cache_size': self.abuseipdb.cache.size(),
            'rdns_cache_size': self.rdns.cache.size(),
        }

    def close(self):
        self.geoip.close()

    def reload_geoip(self):
        """Reload GeoIP databases (called via SIGUSR1)."""
        self.geoip.reload()
