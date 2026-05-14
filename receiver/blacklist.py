"""
UniFi Log Insight - AbuseIPDB Blacklist Fetcher

Pulls the AbuseIPDB blacklist (top 10,000 known-bad IPs) once daily.
Uses the separate blacklist quota (5/day), NOT the check quota.
Pre-seeds ip_threats cache so blocked IPs get instant scores without API calls.
"""

import ipaddress
import os
import time
import logging
import requests

from db import get_config, set_config, get_wan_ips_from_config

logger = logging.getLogger('blacklist')


def _normalize_ip(ip_str: str) -> str:
    """Normalize an IP address string for reliable comparison."""
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        return ip_str

BLACKLIST_URL = 'https://api.abuseipdb.com/api/v2/blacklist'


class BlacklistFetcher:
    """Fetches AbuseIPDB blacklist and bulk-inserts into ip_threats."""

    def __init__(self, db, api_key: str = None):
        self.db = db
        self.api_key = api_key or os.environ.get('ABUSEIPDB_API_KEY', '')
        self.enabled = bool(self.api_key)

    def fetch_and_store(self):
        """Pull blacklist and upsert into ip_threats. Returns count of IPs stored."""
        if not self.enabled:
            logger.warning("Blacklist fetch skipped — no API key")
            return 0

        try:
            resp = requests.get(
                BLACKLIST_URL,
                headers={
                    'Key': self.api_key,
                    'Accept': 'application/json',
                },
                params={
                    'confidenceMinimum': 75,
                    'limit': 10000,
                },
                timeout=30,
            )

            if resp.status_code == 429:
                logger.warning("Blacklist fetch rate limited (429)")
                return 0

            resp.raise_for_status()
            data = resp.json().get('data', [])

            if not data:
                logger.warning("Blacklist returned empty data")
                return 0

            # Build list of (ip, score, categories) tuples
            entries = []
            for item in data:
                ip = item.get('ipAddress')
                score = item.get('abuseConfidenceScore', 100)
                if ip:
                    entries.append((ip, score, ['blacklist']))

            # Filter out WAN/gateway IPs to prevent self-contamination
            wan_ips_cfg = get_wan_ips_from_config(self.db)
            gateway_ips_cfg = get_config(self.db, 'gateway_ips') or []
            excluded = set()
            for ip_str in wan_ips_cfg + gateway_ips_cfg:
                try:
                    excluded.add(str(ipaddress.ip_address(ip_str)))
                except ValueError:
                    pass
            if excluded:
                before = len(entries)
                entries = [(ip, score, cats) for ip, score, cats in entries
                           if _normalize_ip(ip) not in excluded]
                filtered = before - len(entries)
                if filtered:
                    logger.info("Blacklist: filtered %d WAN/gateway IPs from import", filtered)

            # Bulk upsert into ip_threats
            count = self.db.bulk_upsert_threats(entries)
            logger.info("Blacklist: fetched %d IPs, upserted %d into ip_threats", len(entries), count)
            if count:
                # Record the successful pull so startup gating in main.py can
                # skip redundant /blacklist calls within ABUSEIPDB_BLACKLIST_MIN_INTERVAL_HOURS.
                # Free-tier quota is 5/day — restarts must not burn it.
                try:
                    set_config(self.db, 'last_blacklist_pull_at', int(time.time()))
                except Exception:
                    logger.exception("Failed to persist last_blacklist_pull_at")
            return count

        except requests.Timeout:
            logger.warning("Blacklist fetch timed out")
        except requests.RequestException as e:
            logger.warning("Blacklist fetch error: %s", e)
        except Exception as e:
            logger.error("Blacklist fetch unexpected error: %s", e)

        return 0
