# UniFi-Insights-Plus — Firewall policy toggle: switch to v2 internal API

**Repo:** https://github.com/jmasarweh/UniFi-Insights-Plus
**Observed against:** image revision `b4617fdc4e5164042c35f5132fa4e46b25e6ebd7` (3.7.0), controller UniFi Network 10.3.58, UDM Pro Gen1
**Scope:** Fix the silent-400-on-toggle bug for UI-created firewall policies. Read- and write-path change in `unifi_api.py`; no frontend or DB changes required.

---

## 1. Problem statement

UIP currently uses the UniFi **integration API** (`/proxy/network/integration/v1/sites/{site}/firewall/policies`) for both reads and writes of firewall policies. That API has a structural limitation in controller 10.x: it only exposes the `id` field on policies that were *created via the integration API itself*. Policies created via the UniFi Network web UI appear in the same response list but **carry no `id`**, so any subsequent PATCH-by-id silently constructs the URL `/firewall/policies/undefined` and the controller correctly returns HTTP 400.

The user-visible symptom is: clicking the "enable logging" toggle on certain firewall policies in UIP does nothing, with no UI feedback. The backend logs the exception:

```
api.unifi  ERROR  Failed to patch firewall policy undefined
  ...
  requests.exceptions.HTTPError: 400 Client Error:  for url:
    https://<udm>/proxy/network/integration/v1/sites/<uuid>/firewall/policies/undefined
```

On the affected deployment, **20 of 89** policies are affected — all of them USER_DEFINED rules created via the Network web UI.

---

## 2. Empirical findings (please re-verify on the target deployment before coding)

Run the following against the live UDM (replace `${UDM_HOST}`, `${API_KEY}`, `${SITE_UUID}` with deployment values). Authentication is via the same `X-API-KEY` header UIP already uses.

| Endpoint | Behavior |
|---|---|
| `GET /proxy/network/integration/v1/sites/{uuid}/firewall/policies?limit=200` | Returns 89 entries; `id` populated for 69, missing on 20 (all USER_DEFINED) |
| `GET /proxy/network/v2/api/site/default/firewall-policies` | Returns 89 entries; `_id` populated on **all 89** (Mongo ObjectId, 24-char hex) |
| `PATCH /proxy/network/integration/v1/sites/{uuid}/firewall/policies/{id}` with `{loggingEnabled: bool}` | Works for the 69 policies that have integration `id`; impossible for the other 20 |
| `PUT /proxy/network/v2/api/site/default/firewall-policies/{_id}` with **full policy body** (just flip `logging`) | Works for **all 89**, returns 200 with the updated record |
| `PUT /proxy/network/v2/api/site/default/firewall-policies/batch` with `[{_id, logging}]` | Returns 200 but **does not write anything**. **Do not use.** |
| `PUT /proxy/network/v2/api/site/default/firewall-policies/{_id}` with partial body (just `{logging: bool}`) | Returns 400 ("Validation failed for argument [2]"). Full body is required. |

The v2 `_id` and integration `id` are different identifier systems (Mongo ObjectId vs UUID); the same physical policy has both for API-created policies, only `_id` for UI-created ones. We searched all v2 records for the integration UUID of a known API-created policy and found it nowhere in the v2 schema — the mapping is held in an internal table we have no documented write path to.

---

## 3. Recommended fix

Switch UIP from the integration API to the v2 internal API for **firewall policy reads and writes**. Keep using the integration API for everything else (sites discovery, devices, clients, etc.) — it works fine for those.

The fix lives entirely in `unifi_api.py` in the running image (`/app/unifi_api.py`). Three functions to change, one new helper. The backend should re-shape the v2 response so that the existing frontend continues to work without changes.

### 3.1 New v2 GET (replace `get_firewall_policies`)

The current implementation paginates `/proxy/network/integration/v1/.../firewall/policies?offset=&limit=`. The v2 endpoint does **not** require pagination params on a typical deployment (returns all rows in one response), but you may add `?offset=&limit=` if you want to keep symmetry.

Pseudocode:

```python
def get_firewall_policies(self) -> list:
    """Return firewall policies from the v2 internal endpoint.

    The integration API at /v1 only exposes `id` for policies that were
    created via that API; UI-created policies arrive without an addressable
    handle, which breaks PATCH. The v2 internal API at /v2/api/site/.../
    firewall-policies returns `_id` for every policy. We re-shape the v2
    schema to look like the integration schema so existing callers and the
    frontend keep working without changes.
    """
    url = f"{self.host}/proxy/network/v2/api/site/default/firewall-policies"
    resp = self._get_session().get(url, timeout=self.TIMEOUT)
    self._check_integration_permissions(resp)
    resp.raise_for_status()
    v2_items = resp.json()
    return [self._v2_policy_to_integration_shape(p) for p in v2_items]
```

Note: the URL uses the literal string `default` for the site (not the integration site UUID). All probes against this deployment used `default`. Verify on your test deployment.

### 3.2 New v2 PATCH (replace `patch_firewall_policy`)

```python
def patch_firewall_policy(self, policy_id: str, logging_enabled: bool) -> dict:
    """Update a single policy's logging via v2 endpoint.

    `policy_id` here is the v2 `_id` (Mongo ObjectId, 24-char hex). We
    fetch the full v2 record, flip `logging`, and PUT the full body —
    v2 rejects partial updates ('Validation failed for argument [2]') and
    the v2 'batch' endpoint silently no-ops, so neither is viable.
    """
    base = f"{self.host}/proxy/network/v2/api/site/default/firewall-policies"
    # Fetch full body (v2 requires it for the write)
    listing = self._get_session().get(base, timeout=self.TIMEOUT)
    self._check_integration_permissions(listing)
    listing.raise_for_status()
    items = listing.json()
    record = next((p for p in items if p["_id"] == policy_id), None)
    if record is None:
        raise ValueError(f"policy not found: {policy_id}")
    if record.get("logging") == logging_enabled:
        return self._v2_policy_to_integration_shape(record)  # no-op
    record["logging"] = logging_enabled
    resp = self._get_session().put(f"{base}/{policy_id}", json=record, timeout=self.TIMEOUT)
    self._check_integration_permissions(resp)
    resp.raise_for_status()
    return self._v2_policy_to_integration_shape(resp.json())
```

Performance note: the GET-then-PUT is one extra HTTP round-trip per toggle. If that matters in the bulk path, cache the listing for the duration of one `bulk_patch_logging` invocation and pass each record into `_patch_one_policy` from that cache.

### 3.3 New helper `_v2_policy_to_integration_shape`

Translate v2 schema → integration schema so existing callers (and the frontend) don't see the change. Below is the mapping derived from real records on the test deployment:

| Integration field | Source from v2 |
|---|---|
| `id` | `_id` |
| `enabled` | `enabled` |
| `name` | `name` |
| `description` | `description` (or `""` if absent) |
| `index` | `index` |
| `loggingEnabled` | `logging` |
| `action.type` | `action` (string → wrap as `{"type": <action>}`) |
| `action.allowReturnTraffic` | `create_allow_respond` *only when action == "ALLOW"* |
| `ipProtocolScope.ipVersion` | `ip_version` mapped: `"BOTH"`→`"IPV4_AND_IPV6"`, `"IPV4"`→`"IPV4"`, `"IPV6"`→`"IPV6"` |
| `source.zoneId` | `source.zone_id` |
| `destination.zoneId` | `destination.zone_id` |
| `metadata.origin` | `"SYSTEM_DEFINED"` if `predefined` is true, else `"USER_DEFINED"` |
| `source.trafficFilter` / `destination.trafficFilter` | see below — depends on `matching_target` |

`trafficFilter` translation (apply to both `source` and `destination`):

```
v2 matching_target          →  integration trafficFilter
─────────────────────────────────────────────────────────
"ANY"                       →  (omit trafficFilter entirely)
"APP"                       →  {type: "APPLICATION", applicationFilter: {applicationIds: <app_ids>}}
"IP"                        →  {type: "IP_ADDRESS",
                                  ipAddressFilter: {
                                    type: "IP_ADDRESSES",
                                    matchOpposite: <match_opposite_ips>,
                                    items: [{type: "IP_ADDRESS", value: x} for x in ips]
                                  }}
"NETWORK"                   →  {type: "NETWORK",
                                  networkFilter: {
                                    networkIds: <network_ids>,
                                    matchOpposite: <match_opposite_networks>
                                  }}
```

If you see additional `matching_target` values on the target deployment, surface them honestly to the caller (raise or return an unknown-shape marker) rather than silently dropping fields — better to fail loudly than corrupt downstream comparisons.

**Heads-up on inner IDs.** The id-system divergence applies not only to policies (integration UUID vs v2 `_id`) but also to **networks**, and possibly to other referenced objects (zones, applications). The same network appears as a UUID in `networkFilter.networkIds` from the integration API and as a Mongo `_id` in `network_ids` from v2. The translator above passes these through verbatim, which means:

- **For the toggle-logging path, this does not matter** — UIP only writes back to the policy by its top-level id, and only changes the `logging` flag.
- **For any feature that reads inner ids to display a name** (e.g. resolving `networkIds[0]` to "IoT VLAN"), the frontend would now receive v2-style ids. If UIP currently joins those against the integration-API networks endpoint, it would fail to find a match. Worth grepping for `networkIds` / `applicationIds` / `ipAddressFilter` consumers in the frontend before merging; if any exist, they need a corresponding v2 lookup or a backend join.

Zones (`zoneId` → `zone_id`) appear to use Mongo `_id`s in both schemas on this deployment, but verify on yours.

The reverse mapping (integration → v2) is not needed for this fix because we only call v2 with bodies we already obtained from v2.

### 3.4 Update `bulk_patch_logging`

Currently iterates `_patch_one_policy(item['id'], item['loggingEnabled'])` in 4 worker threads. After the change above, `_patch_one_policy` will call `patch_firewall_policy` which already does the GET-then-PUT. Optimization: pull the listing once at the top of `bulk_patch_logging` and pass each pre-fetched record down through the worker so per-policy traffic is one PUT instead of GET+PUT. Optional; correctness doesn't depend on it.

### 3.5 Frontend

**No changes required.** The frontend continues to do `PATCH /api/firewall/policies/${policy.id}` with `{loggingEnabled: bool}`. Because the backend now presents the v2 `_id` as `id` in its response, every policy carries a usable id from the frontend's perspective.

If you want to be defensive against future API drift (recommended): in the row render where the toggle is wired, add `if (!policy.id) return;` so any future regression fails closed instead of producing silent 400s.

---

## 4. Out of scope (intentional)

- **The "undefined" path produced by the bug today.** It vanishes the moment every policy carries an id.
- **The 20 already-id-less policies on existing deployments.** They become addressable as soon as the backend reads them from v2; no migration, no data change, no operator action needed.
- **Removing the integration API entirely.** It's still the right interface for the rest of UIP's surface (clients, devices, gateway info). Only firewall policy GET/PATCH switches.
- **A general v2 client.** Don't refactor — this is two functions and a translator. A larger v2 abstraction can come later if you switch more endpoints.

---

## 5. Acceptance criteria

The fix is complete when:

1. `get_firewall_policies()` returns objects shaped exactly like the current integration-API output (same field names, same nesting), with `id` populated on **every** returned policy.
2. `patch_firewall_policy(policy_id, logging_enabled)` succeeds against any policy in the controller, including those that were id-less before, and the change is observable in subsequent GET calls.
3. The frontend "enable/disable logging" toggle works for **all** policies, including the ones that previously produced `api.unifi ERROR: Failed to patch firewall policy undefined`.
4. `bulk_patch_logging` succeeds for a mixed list of API-created and UI-created policies. Verification pass still passes.
5. No new dependency added, no schema change in Postgres, no env var change.

---

## 6. Tests

Add to whatever test layer the repo already uses (`pytest.ini` is present in `/app/` so there is one).

### 6.1 Pure-function test of the schema translator

For each v2 → integration mapping case, feed a representative v2 record into `_v2_policy_to_integration_shape` and assert the output structure matches a hand-written expected integration shape. Cover:

- `matching_target: "ANY"` → no `trafficFilter`
- `matching_target: "APP"` with `app_ids` → `APPLICATION` filter
- `matching_target: "IP"` with `ips` → `IP_ADDRESS` filter
- `matching_target: "NETWORK"` with `network_ids` → `NETWORK` filter
- `predefined: true` → `metadata.origin == "SYSTEM_DEFINED"`
- `action: "ALLOW"` with `create_allow_respond: true` → `action.allowReturnTraffic: true`
- `ip_version: "BOTH"` → `ipProtocolScope.ipVersion: "IPV4_AND_IPV6"`

Real v2 records to base test fixtures on are reproducible via the GET probe above.

### 6.2 Integration test against a live controller

Marked optional / skipped by default. Pulls policies via the new path, asserts every returned record has a non-empty `id` field, picks one record with the lowest impact (e.g. by `predefined` flag and rule `index`), toggles `loggingEnabled`, asserts the toggle takes, restores the original value. Skip when `UNIFI_API_KEY` is not in env.

### 6.3 Manual smoke test (the operator runs this)

1. Open UIP firewall policies view.
2. Toggle logging on one previously-broken policy (e.g. a NETWORK-filter policy created via the Network web UI).
3. Verify the toggle persists (refresh page, check state).
4. Verify in the UniFi Network UI that the policy's logging flag changed correspondingly.
5. Toggle it back. Verify likewise.

---

## 7. Notes / hand-off context

- The v2 endpoint accepts the same `X-API-KEY` header UIP already uses; no separate session/cookie auth needed on this controller version.
- The v2 endpoint's URL uses the literal site name `default` (not the integration site UUID). Verify on any non-default-site deployments.
- v2 `_id` is a 24-char lowercase hex string (Mongo ObjectId). The integration `id` is a UUID. Don't try to alias them; they are different identifier systems and the controller doesn't cross-reference them in any field we can read.
- The integration API still works correctly for the policies that have integration `id`s — this fix doesn't break anything that was working; it adds working coverage for the missing 20-of-89.
- We deliberately do **not** propose attempting to retroactively mint integration `id`s for UI-created policies (would require SSH into UDM and writing to an internal mapping table — unsupported, brittle across controller upgrades).
- The integration API's POST-to-create-new-policy flow still works fine and could be useful for other features; nothing in this fix touches it.

---

## 8. Suggested PR shape

Single PR:

- `unifi_api.py` — replace `get_firewall_policies` and `patch_firewall_policy`, add `_v2_policy_to_integration_shape`. Optionally optimize `bulk_patch_logging`.
- `tests/test_v2_policy_translation.py` (new) — pure-function tests per §6.1.
- `README.md` / changelog entry — note: "Firewall policy toggle now works for policies created via the UniFi Network web UI, not just those created via the integration API." Brief mention that the underlying cause is a UniFi controller integration-API limitation.
- No frontend changes.

---

## Addendum (2026-05-15): zones must also come from v2

After deploying the initial fix we found that the **zone matrix in the Firewall Policies view is empty**, and toggling logging on some rows produces 404s on URLs like `/firewall-policies/<src_zone_id><dst_zone_id>3<counter>`. Root cause: the inner-id divergence applies to **zones**, contrary to my speculation in §3.3.

Empirical comparison on the test deployment:

| Zone name | v2 `_id` (from `firewall/zone-matrix`) | Integration `id` (from `firewall/zones`) |
|---|---|---|
| Internal | `6a02f3f867050d3ccb3cb0d3` | `fedb7e64-ff34-4dcb-ae6d-9645807b3329` |
| Vpn | `6a02f3f867050d3ccb3cb0d6` | `31cd7a3a-45d0-40ae-9a7e-a073dd068305` |
| Hotspot | `6a02f3f867050d3ccb3cb0d7` | `f3509485-b5d2-42d6-a9ce-838f21302082` |

After the first patch, `get_firewall_policies()` returns policies whose `source.zoneId` / `destination.zoneId` are Mongo `_id`s (`6a02f3…`), while `get_firewall_zones()` is still hitting the integration API and returning zones with UUID `id`s (`fedb7e…`). The frontend can't cross-reference them, the zone-matrix renders empty, and on duplicate-name rows the frontend falls back to building synthetic keys from `source.zone_id + destination.zone_id + counter` — those synthetic keys are then sent back as policy IDs on PATCH, producing the observed 404s.

### Fix

In `unifi_api.py`:

1. Add a helper for the v2 zone endpoint, parallel to `_firewall_policies_v2_url`:

```python
def _firewall_zones_v2_url(self) -> str:
    """Return the v2 firewall zone-matrix URL for this controller."""
    if self._controller_type == 'self_hosted':
        raise NotImplementedError("Firewall zone v2 API not available on self-hosted controllers")
    site = self.site or 'default'
    return f"{self.host}/proxy/network/v2/api/site/{site}/firewall/zone-matrix"
```

2. Replace `get_firewall_zones()` to read from v2 and reshape into the integration zone schema the frontend already consumes:

```python
def get_firewall_zones(self) -> list:
    """Fetch firewall zones from the v2 zone-matrix endpoint.

    Reading zones from v2 keeps the zone identifier system consistent with
    the policy identifier system. If zones came from the integration API
    (UUIDs) while policies came from v2 (Mongo _ids), the frontend can't
    cross-reference them — the zone matrix renders empty and duplicate-name
    policy rows pick up synthesized keys that then fail PATCH with 404.
    """
    resp = self._get_session().get(self._firewall_zones_v2_url(), timeout=self.TIMEOUT)
    self._check_integration_permissions(resp)
    resp.raise_for_status()
    return [self._v2_zone_to_integration_shape(z) for z in self._unwrap_v2_list(resp.json())]

@staticmethod
def _v2_zone_to_integration_shape(zone: dict) -> dict:
    """Translate a v2 zone-matrix record to the integration zone shape.

    The v2 record carries cross-zone aggregation info under `data` that the
    integration shape doesn't carry; we drop it. The integration shape's
    `networkIds` (zone → contained networks) isn't surfaced by v2 either;
    we return [] which the existing frontend tolerates. `zone_key` ('internal',
    'external', etc.) is exposed as `metadata.origin` proxy: zones with a
    `zone_key` are predefined system zones, user-defined zones don't carry one.
    """
    return {
        'id': zone.get('_id'),
        'name': zone.get('name'),
        'networkIds': [],
        'metadata': {
            'origin': 'SYSTEM_DEFINED' if zone.get('zone_key') else 'USER_DEFINED',
            'configurable': True,
        },
    }
```

### Verification

Run from inside the container after the fix:

```python
from deps import unifi_api
data = unifi_api.get_firewall_data()
zone_ids = {z['id'] for z in data['zones']}
for p in data['policies']:
    src = p['source']['zoneId']
    dst = p['destination']['zoneId']
    assert src in zone_ids, f"policy {p['name']!r} src zone {src} not in zones list"
    assert dst in zone_ids, f"policy {p['name']!r} dst zone {dst} not in zones list"
print("all policy zones resolve to a known zone — frontend can cross-reference")
```

### Acceptance criteria addendum

5. Every `policy.source.zoneId` and `policy.destination.zoneId` returned by `get_firewall_data()` must appear as an `id` in the `zones` list of the same response.
6. The zone matrix on the Firewall Policies page renders populated, with per-cell policy counts visible.
7. Toggling logging on a previously-broken policy (e.g. `DropInvalid`, `EstablishedRelated`, `Allow smartmeter`) succeeds with the new v2 PATCH path, no longer producing 404s on synthesized URLs.

---

## Addendum (2026-05-22): final API boundary and implementation approach

### Documentation research summary

Ubiquiti's official API guidance separates two supported surfaces:

- **Site Manager API** at `api.ui.com`, for cloud-level aggregated site/device status.
- **Local Application APIs**, where each UniFi application exposes local,
  application-specific endpoints. For Network, Ubiquiti directs operators to
  the controller's own **UniFi Network > Integrations** page for version-specific
  API docs.

Sources:

- Ubiquiti Help Center: [Getting Started with the Official UniFi API](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)
- Local Network API docs observed for Network 10.0.162, e.g. [Get Firewall Zones](https://developer.ui.com/network/v10.0.162/getfirewallzones)
- Ubiquiti Help Center: [Zone-Based Firewalls in UniFi](https://help.ui.com/hc/en-us/articles/115003173168-Zone-Based-Firewalls-in-UniFi), which notes that extra policies can be created by features such as port forwarding and VPN servers.

The documented Network Integration API is the right default for stable, public
resources. It is not sufficient for UIP's firewall logging toggle in Network
10.x because real deployments show that:

- `GET /proxy/network/integration/v1/sites/{site_uuid}/firewall/policies`
  can omit `id` on policies created in the UniFi Network UI.
- `GET /proxy/network/integration/v1/sites/{site_uuid}/firewall/zones`
  returns zone UUIDs that do not match the zone ids embedded in v2 policy
  records.
- `GET /proxy/network/v2/api/site/{site}/firewall-policies` and
  `GET /proxy/network/v2/api/site/{site}/firewall/zone-matrix` use the same
  Mongo-style zone id namespace.

So the refactor is intentionally narrow: keep the Integration API for normal
site discovery and non-firewall resources, but keep the Firewall Syslog Manager's
policy and zone view entirely inside the Network v2 identifier namespace.

### Implemented approach

1. `get_firewall_policies()` reads v2 firewall policy records and reshapes them
   to the existing frontend policy schema. Top-level `id` is the v2 `_id`.
2. `patch_firewall_policy()` writes through v2 by fetching the full policy body,
   flipping only `logging`, and `PUT`ing the full body to
   `/firewall-policies/{_id}`. Partial writes and the v2 batch endpoint remain
   intentionally avoided because they were observed to fail or no-op.
3. `get_firewall_zones()` now reads
   `/proxy/network/v2/api/site/{site}/firewall/zone-matrix` and reshapes zones
   to the frontend's existing zone schema. Zone `id` is the v2 `_id`, so every
   `policy.source.zoneId` and `policy.destination.zoneId` can resolve in the
   same response.
4. `get_network_config()` carries `firewall_zone_id` from classic
   `/rest/networkconf` into each network record. This preserves log-to-policy
   matching when v2 zone records omit `networkIds`; the matcher can still join
   `network.firewall_zone_id` to the v2 zone id.
5. `isControllablePolicy()` rejects rows without `policy.id` before the frontend
   can send a PATCH. This is a guardrail, not the primary fix.

### Design rule

Do not mix Integration API UUIDs and v2 Mongo ids inside one firewall policy
response. If future firewall-policy features need additional policy-adjacent
objects (applications, networks, port-forward-generated policies, etc.), either:

- fetch those objects from the same v2 surface, or
- translate them explicitly before exposing them to the frontend.

Implicit joins by display name or synthetic ids are not acceptable for write
paths. They caused the observed `/firewall-policies/<src><dst><counter>` 404s.

### Verification after implementation

- Unit tests cover v2 policy translation, v2 zone translation, same-response
  policy/zone id consistency, matcher fallback through `firewall_zone_id`, and
  frontend refusal to toggle policies without ids.
- Full receiver suite: `689 passed, 1 skipped`.
- Targeted UI helper test: `3 passed`.
- Full UI suite has an unrelated pre-existing failure in
  `App.vpn-toast-dismissal.test.jsx`: the test mock replaces `localStorage`
  without `getItem`, causing `App.jsx` theme initialization to fail before this
  firewall code is exercised.
