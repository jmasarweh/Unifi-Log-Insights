"""MCP server endpoints (HTTP + JSON-RPC)."""

import asyncio
import json
import logging
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from psycopg2.extras import RealDictCursor

from db import get_config, set_config
from deps import APP_VERSION, get_conn, put_conn, enricher_db, unifi_api
from routes import logs as logs_routes
from routes import stats as stats_routes
from routes import setup as setup_routes
from routes import unifi as unifi_routes
from routes import health as health_routes
from routes import threats as threats_routes
from routes.auth import get_forwarded_proto, validate_token_with_effective_scopes

logger = logging.getLogger('api.mcp')

router = APIRouter()

_PROTOCOL_VERSION = "2025-11-25"
_SUPPORTED_PROTOCOLS = {_PROTOCOL_VERSION, "2025-06-18", "2025-03-26", "2024-11-05"}

_SCOPES = {
    'logs.read',
    'firewall.read',
    'firewall.syslog',
    'unifi.read',
    'system.read',
    'mcp.admin',
}

_SCOPE_DESCRIPTIONS = {
    'logs.read': 'Search and analyze logs.',
    'firewall.read': 'View firewall rules and policies.',
    'firewall.syslog': 'Turn logging on/off for firewall rules.',
    'unifi.read': 'View UniFi clients, devices, and status.',
    'system.read': 'View system health and network interfaces.',
    'mcp.admin': 'Manage MCP access and settings.',
}


def _as_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ('true', '1', 'yes', 'y')
    return bool(val)


def _as_int(val: Any, default: int | None = None) -> int | None:
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _default_allowed_origins(request: Request) -> list[str]:
    host = request.headers.get('host', '')
    scheme = get_forwarded_proto(request)
    if not host:
        return []
    return [f"{scheme}://{host}"]


def _validate_origin(request: Request) -> None:
    origin = request.headers.get('origin')
    if not origin:
        return
    allowed = get_config(enricher_db, 'mcp_allowed_origins', [])
    if not allowed:
        allowed = _default_allowed_origins(request)
    if origin not in allowed:
        raise HTTPException(status_code=403, detail="Origin not allowed")


def _validate_protocol_version(request: Request) -> None:
    version = request.headers.get('mcp-protocol-version')
    if version and version not in _SUPPORTED_PROTOCOLS:
        raise HTTPException(status_code=400, detail="Unsupported MCP protocol version")


def _get_bearer_token(request: Request) -> str | None:
    auth = request.headers.get('authorization') or ''
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return None


def _lookup_token(token: str) -> dict | None:
    """Validate MCP token using the shared auth token validator.

    Delegates to validate_token_with_effective_scopes from auth module which
    checks owner_user_id, is_active, disabled status, JOINs user/role info,
    and computes effective_scopes (token scopes ∩ owner role permissions).
    Returns the full auth context as-is for scope checks and audit attribution.
    """
    if not token:
        return None
    return validate_token_with_effective_scopes(token)


def _require_scope(token_info: dict, required: list[str]) -> None:
    """Check that the token's effective scopes include all required scopes."""
    # Explicit None check: empty effective_scopes (set()) means *no* permissions
    # and must NOT fall through to raw scopes — that would be privilege escalation.
    # effective_scopes is always a set (assigned by validate_token_with_effective_scopes
    # via set intersection at auth.py:277-280). No string/invalid type possible.
    es = token_info.get('effective_scopes')
    granted = set(es) if es is not None else set(token_info.get('scopes') or [])
    if not set(required).issubset(granted):
        raise PermissionError("Missing required scope")


def _audit_enabled() -> bool:
    return bool(get_config(enricher_db, 'mcp_audit_enabled', False))


def _audit_retention_days() -> int:
    val = get_config(enricher_db, 'mcp_audit_retention_days', 10)
    try:
        return max(1, int(val))
    except (ValueError, TypeError):
        return 10


_SENSITIVE_PARAM_KEYS = frozenset({
    'password', 'secret', 'token', 'api_key', 'credentials', 'ssn', 'credit_card',
})


def _sanitize_params(params: dict | None) -> dict:
    """Redact sensitive keys from params before audit logging.

    Uses substring matching: a key like 'user_password' or 'api_secret_key'
    is redacted if any token in _SENSITIVE_PARAM_KEYS appears within it.
    """
    if not params:
        return {}
    def _is_sensitive(key: str) -> bool:
        kl = key.lower()
        return any(tok in kl for tok in _SENSITIVE_PARAM_KEYS)
    return {k: ('***' if _is_sensitive(k) else v) for k, v in params.items()}


def _write_audit(token_info: dict, tool_name: str, scope: str, params: dict | None,
                 success: bool, error: str | None = None) -> None:
    # Won't Fix: raw error logged intentionally — audit entries are admin-only
    # and error messages from tool execution are needed for debugging. Params
    # are already sanitized via _sanitize_params; error strings don't contain secrets.
    if not _audit_enabled():
        return
    token_id = token_info.get('token_id')
    user_id = token_info.get('owner_user_id')
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_log (user_id, token_id, action, detail, created_at)
                   VALUES (%s, %s, 'api_call', %s, NOW())""",
                [user_id, token_id, json.dumps({'tool_name': tool_name, 'scope': scope,
                                        'success': success, 'error': error,
                                        'params': _sanitize_params(params)}, default=str)]
            )
        conn.commit()
    except Exception:
        # Intentionally swallowed: audit is non-critical and must not break MCP tool calls.
        # The exception is still logged for observability.
        conn.rollback()
        logger.exception("Failed to write audit entry")
    finally:
        put_conn(conn)


def _tool_result(data: Any) -> dict:
    payload = json.dumps(data, ensure_ascii=True, indent=2, default=str)
    return {
        "content": [
            {"type": "text", "text": payload}
        ]
    }


def _tool_error(message: str) -> dict:
    return {
        "content": [
            {"type": "text", "text": message}
        ],
        "isError": True,
    }


def _tools_catalog() -> list[dict]:
    return [
        {
            "name": "search_logs",
            "description": "Search logs with filters (log type, time range, IPs, ports, protocol, actions, services, ASN, etc.). Most text filters support ! prefix for negation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "log_type": {"type": "string", "description": "Comma-separated: firewall,dns,dhcp,wifi,system"},
                    "time_range": {"type": "string", "description": "1h,6h,24h,7d,30d,60d"},
                    "time_from": {"type": "string", "description": "ISO datetime"},
                    "time_to": {"type": "string", "description": "ISO datetime"},
                    "src_ip": {"type": "string", "description": "Source IP (prefix with ! to negate)"},
                    "dst_ip": {"type": "string", "description": "Dest IP (prefix with ! to negate)"},
                    "ip": {"type": "string", "description": "Search both src and dst (prefix with ! to negate)"},
                    "direction": {"type": "string", "description": "Comma-separated: inbound,outbound,inter_vlan,nat"},
                    "rule_action": {"type": "string", "description": "Comma-separated: allow,block,redirect (prefix with ! to negate)"},
                    "rule_name": {"type": "string", "description": "Rule name search (prefix with ! to negate)"},
                    "country": {"type": "string", "description": "Comma-separated country codes (prefix with ! to negate)"},
                    "threat_min": {"type": "integer"},
                    "search": {"type": "string", "description": "Full-text search in raw_log (prefix with ! to negate)"},
                    "service": {"type": "string", "description": "Comma-separated service names (prefix with ! to negate)"},
                    "interface": {"type": "string", "description": "Comma-separated interface names"},
                    "vpn_only": {"type": "boolean"},
                    "asn": {"type": "string", "description": "ASN name search (prefix with ! to negate)"},
                    "dst_port": {"type": "string", "description": "Destination port (prefix with ! to negate)"},
                    "src_port": {"type": "string", "description": "Source port (prefix with ! to negate)"},
                    "protocol": {"type": "string", "description": "Comma-separated: TCP,UDP,ICMP (prefix with ! to negate)"},
                    "sort": {"type": "string"},
                    "order": {"type": "string", "description": "asc or desc"},
                    "page": {"type": "integer"},
                    "per_page": {"type": "integer", "description": "1-200"},
                },
            },
        },
        {
            "name": "get_log",
            "description": "Fetch a single log by id (includes enrichment fields).",
            "inputSchema": {
                "type": "object",
                "properties": {"log_id": {"type": "integer"}},
                "required": ["log_id"],
            },
        },
        {
            "name": "get_log_stats",
            "description": "Get dashboard stats for a time range (includes top threat IPs in that range).",
            "inputSchema": {
                "type": "object",
                "properties": {"time_range": {"type": "string", "description": "1h,6h,24h,7d,30d,60d"}},
            },
        },
        {
            "name": "get_top_threat_ips",
            "description": "Return top threat IPs from logs for a time range.",
            "inputSchema": {
                "type": "object",
                "properties": {"time_range": {"type": "string", "description": "1h,6h,24h,7d,30d,60d"}},
            },
        },
        {
            "name": "list_threat_ips",
            "description": "Query the ip_threats cache (score, categories, AbuseIPDB fields).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "min_score": {"type": "integer"},
                    "max_score": {"type": "integer"},
                    "since": {"type": "string", "description": "ISO datetime for looked_up_at lower bound"},
                    "limit": {"type": "integer"},
                    "sort": {"type": "string", "description": "threat_score, looked_up_at, abuse_total_reports"},
                    "order": {"type": "string", "description": "asc or desc"},
                },
            },
        },
        {
            "name": "list_services",
            "description": "List distinct service names seen in logs.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "list_protocols",
            "description": "List distinct protocols seen in logs (e.g. TCP, UDP, ICMP).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "aggregate_logs",
            "description": "Aggregate logs by a dimension (src_ip, dst_ip, country, asn, rule_name, service) with counts. Supports CIDR grouping for IPs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group_by": {"type": "string", "description": "Group by: src_ip, dst_ip, country, asn, rule_name, service"},
                    "prefix_length": {"type": "integer", "description": "CIDR prefix for IP grouping: 8, 16, 22, 24"},
                    "having_min_total": {"type": "integer", "description": "Min row count per group"},
                    "having_min_unique_ips": {"type": "integer", "description": "Min distinct src_ip per group"},
                    "limit": {"type": "integer", "description": "Max groups to return (1-500)"},
                    "log_type": {"type": "string"},
                    "time_range": {"type": "string"},
                    "time_from": {"type": "string"},
                    "time_to": {"type": "string"},
                    "src_ip": {"type": "string"},
                    "dst_ip": {"type": "string"},
                    "ip": {"type": "string"},
                    "direction": {"type": "string"},
                    "rule_action": {"type": "string"},
                    "rule_name": {"type": "string"},
                    "country": {"type": "string"},
                    "threat_min": {"type": "integer"},
                    "search": {"type": "string"},
                    "service": {"type": "string"},
                    "interface": {"type": "string"},
                    "vpn_only": {"type": "boolean"},
                    "asn": {"type": "string"},
                    "dst_port": {"type": "string"},
                    "src_port": {"type": "string"},
                    "protocol": {"type": "string"},
                },
                "required": ["group_by"],
            },
        },
        {
            "name": "export_logs_csv_url",
            "description": "Return a CSV export URL for logs matching filters (downloadable file).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "log_type": {"type": "string"},
                    "time_range": {"type": "string"},
                    "time_from": {"type": "string"},
                    "time_to": {"type": "string"},
                    "src_ip": {"type": "string"},
                    "dst_ip": {"type": "string"},
                    "ip": {"type": "string"},
                    "direction": {"type": "string"},
                    "rule_action": {"type": "string"},
                    "rule_name": {"type": "string"},
                    "country": {"type": "string"},
                    "threat_min": {"type": "integer"},
                    "search": {"type": "string"},
                    "service": {"type": "string"},
                    "interface": {"type": "string"},
                    "vpn_only": {"type": "boolean"},
                    "asn": {"type": "string"},
                    "dst_port": {"type": "string"},
                    "src_port": {"type": "string"},
                    "protocol": {"type": "string"},
                    "limit": {"type": "integer", "description": "1-100000"},
                },
            },
        },
        {
            "name": "list_firewall_policies",
            "description": "Fetch firewall policies and zones from UniFi.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "set_firewall_syslog",
            "description": "Enable/disable syslog logging for one or more firewall policies.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "policies": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "loggingEnabled": {"type": "boolean"},
                            },
                            "required": ["id", "loggingEnabled"],
                        },
                    },
                },
                "required": ["policies"],
            },
        },
        {
            "name": "list_unifi_clients",
            "description": "List cached UniFi clients (supports search and limit).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "search": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
        },
        {
            "name": "list_unifi_devices",
            "description": "List cached UniFi infrastructure devices.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "get_unifi_status",
            "description": "Get UniFi polling and feature status.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "get_health",
            "description": "Return API health and version info.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "list_interfaces",
            "description": "List discovered interfaces with labels and types.",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


_TOOL_SCOPES = {
    'search_logs': ['logs.read'],
    'get_log': ['logs.read'],
    'get_log_stats': ['logs.read'],
    'get_top_threat_ips': ['logs.read'],
    'list_threat_ips': ['logs.read'],
    'list_services': ['logs.read'],
    'list_protocols': ['logs.read'],
    'aggregate_logs': ['logs.read'],
    'export_logs_csv_url': ['logs.read'],
    'list_firewall_policies': ['firewall.read'],
    'set_firewall_syslog': ['firewall.syslog'],
    'list_unifi_clients': ['unifi.read'],
    'list_unifi_devices': ['unifi.read'],
    'get_unifi_status': ['unifi.read'],
    'get_health': ['system.read'],
    'list_interfaces': ['system.read'],
}


def _tool_search_logs(args: dict) -> dict:
    page = _as_int(args.get('page'), 1)
    per_page = _as_int(args.get('per_page'), 50)
    if per_page is not None and (per_page < 1 or per_page > 200):
        raise ValueError("per_page must be between 1 and 200")
    return logs_routes.get_logs(
        log_type=args.get('log_type'),
        time_range=args.get('time_range'),
        time_from=args.get('time_from'),
        time_to=args.get('time_to'),
        src_ip=args.get('src_ip'),
        dst_ip=args.get('dst_ip'),
        ip=args.get('ip'),
        direction=args.get('direction'),
        rule_action=args.get('rule_action'),
        rule_name=args.get('rule_name'),
        country=args.get('country'),
        threat_min=args.get('threat_min'),
        search=args.get('search'),
        service=args.get('service'),
        interface=args.get('interface'),
        vpn_only=_as_bool(args.get('vpn_only', False)),
        asn=args.get('asn'),
        dst_port=args.get('dst_port'),
        src_port=args.get('src_port'),
        protocol=args.get('protocol'),
        sort=args.get('sort', 'timestamp'),
        order=args.get('order', 'desc'),
        page=page,
        per_page=per_page,
    )


def _tool_get_log(args: dict) -> dict:
    log_id = args.get('log_id')
    if log_id is None:
        raise ValueError("log_id is required")
    if isinstance(log_id, str) and log_id.isdigit():
        log_id = int(log_id)
    return logs_routes.get_log(log_id)


def _tool_get_top_threat_ips(args: dict) -> dict:
    stats = stats_routes.get_stats(time_range=args.get('time_range', '24h'))
    return {'top_threat_ips': stats.get('top_threat_ips', [])}


def _tool_list_threat_ips(args: dict) -> dict:
    limit = _as_int(args.get('limit'), 100)
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    return threats_routes.list_threats(
        ip=args.get('ip'),
        min_score=_as_int(args.get('min_score'), 0),
        max_score=_as_int(args.get('max_score')),
        since=args.get('since'),
        limit=limit,
        sort=args.get('sort', 'threat_score'),
        order=args.get('order', 'desc'),
    )


def _tool_aggregate_logs(args: dict) -> dict:
    return logs_routes.get_logs_aggregate(
        group_by=args.get('group_by', ''),
        prefix_length=_as_int(args.get('prefix_length')),
        having_min_total=_as_int(args.get('having_min_total')),
        having_min_unique_ips=_as_int(args.get('having_min_unique_ips')),
        limit=_as_int(args.get('limit'), 100),
        log_type=args.get('log_type'),
        time_range=args.get('time_range'),
        time_from=args.get('time_from'),
        time_to=args.get('time_to'),
        src_ip=args.get('src_ip'),
        dst_ip=args.get('dst_ip'),
        ip=args.get('ip'),
        direction=args.get('direction'),
        rule_action=args.get('rule_action'),
        rule_name=args.get('rule_name'),
        country=args.get('country'),
        threat_min=_as_int(args.get('threat_min')),
        search=args.get('search'),
        service=args.get('service'),
        interface=args.get('interface'),
        vpn_only=_as_bool(args.get('vpn_only', False)),
        asn=args.get('asn'),
        dst_port=args.get('dst_port'),
        src_port=args.get('src_port'),
        protocol=args.get('protocol'),
    )


def _tool_export_logs_csv_url(args: dict) -> dict:
    limit = _as_int(args.get('limit'))
    if limit is not None and (limit < 1 or limit > 100000):
        raise ValueError("limit must be between 1 and 100000")
    params = {k: v for k, v in args.items() if v is not None}
    qs = urlencode(params)
    return {'download_url': f"/api/export?{qs}" if qs else "/api/export"}


def _tool_set_firewall_syslog(args: dict) -> dict:
    policies = args.get('policies') or []
    if not policies:
        raise ValueError("policies list is required")
    policy_data = unifi_routes.get_firewall_policies()
    by_id = {p.get('id'): p for p in policy_data.get('policies', [])}
    cleaned = []
    errors = []
    for item in policies:
        policy_id = item.get('id')
        logging_enabled = item.get('loggingEnabled')
        if policy_id is None or logging_enabled is None:
            errors.append({'id': policy_id, 'error': 'id and loggingEnabled required'})
            continue
        policy = by_id.get(policy_id)
        if not policy:
            errors.append({'id': policy_id, 'error': 'Unknown policy id'})
            continue
        if policy and policy.get('origin') == 'DERIVED':
            errors.append({'id': policy_id, 'error': 'Derived policy cannot be modified'})
            continue
        cleaned.append({'id': policy_id, 'loggingEnabled': logging_enabled})
    if not cleaned:
        return {'success': False, 'errors': errors}
    result = unifi_api.bulk_patch_logging(cleaned)
    if errors:
        result['skipped'] = result.get('skipped', 0) + len(errors)
        result['errors'] = (result.get('errors') or []) + errors
    return result


def _tool_list_unifi_clients(args: dict) -> dict:
    limit = _as_int(args.get('limit'), 200)
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    return unifi_routes.list_unifi_clients(
        search=args.get('search'),
        limit=limit,
    )


_TOOL_HANDLERS = {
    'search_logs':            _tool_search_logs,
    'get_log':                _tool_get_log,
    'get_log_stats':          lambda args: stats_routes.get_stats(time_range=args.get('time_range', '24h')),
    'get_top_threat_ips':     _tool_get_top_threat_ips,
    'list_threat_ips':        _tool_list_threat_ips,
    'list_services':          lambda _: logs_routes.get_services(),
    'list_protocols':         lambda _: logs_routes.get_protocols(),
    'aggregate_logs':         _tool_aggregate_logs,
    'export_logs_csv_url':    _tool_export_logs_csv_url,
    'list_firewall_policies': lambda _: unifi_routes.get_firewall_policies(),
    'set_firewall_syslog':    _tool_set_firewall_syslog,
    'list_unifi_clients':     _tool_list_unifi_clients,
    'list_unifi_devices':     lambda _: unifi_routes.list_unifi_devices(),
    'get_unifi_status':       lambda _: unifi_routes.unifi_poll_status(),
    'get_health':             lambda _: health_routes.health(),
    'list_interfaces':        lambda _: setup_routes.list_interfaces(),
}

# Runtime guard: ensure _TOOL_HANDLERS and _TOOL_SCOPES stay in sync.
_handler_keys = set(_TOOL_HANDLERS.keys())
_scope_keys = set(_TOOL_SCOPES.keys())
if _handler_keys != _scope_keys:
    _missing_scopes = _handler_keys - _scope_keys
    _missing_handlers = _scope_keys - _handler_keys
    raise RuntimeError(
        f"_TOOL_HANDLERS / _TOOL_SCOPES key mismatch! "
        f"In handlers but not scopes: {_missing_scopes or 'none'}. "
        f"In scopes but not handlers: {_missing_handlers or 'none'}."
    )


def _handle_tool_call(name: str, args: dict) -> dict:
    handler = _TOOL_HANDLERS.get(name)
    if not handler:
        raise KeyError(f"Unknown tool: {name}")
    return handler(args)


def _jsonrpc_error(code: int, message: str, rpc_id: Any = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def _jsonrpc_result(result: Any, rpc_id: Any) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": result,
    }


def _handle_request(payload: dict, token_info: dict | None) -> dict | None:
    if payload.get('jsonrpc') != '2.0':
        return _jsonrpc_error(-32600, "Invalid JSON-RPC version", payload.get('id'))

    method = payload.get('method')
    params = payload.get('params') or {}
    is_notification = 'id' not in payload
    rpc_id = payload.get('id')

    # Notifications (no 'id' key): no response
    if is_notification:
        return None

    if method == 'initialize':
        requested_version = params.get('protocolVersion')
        negotiated_version = requested_version if requested_version in _SUPPORTED_PROTOCOLS else _PROTOCOL_VERSION
        capabilities = {
            "tools": {"listChanged": False},
            "resources": {"listChanged": False},
            "prompts": {"listChanged": False},
        }
        return _jsonrpc_result({
            "protocolVersion": negotiated_version,
            "capabilities": capabilities,
            "serverInfo": {
                "name": "unifi-log-insight",
                "version": APP_VERSION,
            },
        }, rpc_id)

    if method == 'tools/list':
        return _jsonrpc_result({"tools": _tools_catalog()}, rpc_id)

    if method == 'tools/call':
        tool_name = params.get('name')
        args = params.get('arguments') or {}
        if tool_name not in _TOOL_SCOPES:
            return _jsonrpc_result(_tool_error("Unknown tool"), rpc_id)
        try:
            _require_scope(token_info or {}, _TOOL_SCOPES[tool_name])
        except PermissionError:
            return _jsonrpc_result(_tool_error("Permission denied"), rpc_id)
        safe_token = token_info or {}
        try:
            result = _handle_tool_call(tool_name, args)
            response = _tool_result(result)
            _write_audit(safe_token, tool_name, _TOOL_SCOPES[tool_name][0], args, True)
            return _jsonrpc_result(response, rpc_id)
        except (ValueError, KeyError) as e:
            _write_audit(safe_token, tool_name, _TOOL_SCOPES[tool_name][0], args, False, str(e))
            return _jsonrpc_result(_tool_error(str(e)), rpc_id)
        except HTTPException as e:
            _write_audit(safe_token, tool_name, _TOOL_SCOPES[tool_name][0], args, False, str(e.detail))
            return _jsonrpc_result(_tool_error(e.detail), rpc_id)
        except Exception as e:
            logger.exception("Tool call failed: %s", tool_name)
            _write_audit(safe_token, tool_name, _TOOL_SCOPES[tool_name][0], args, False, str(e))
            return _jsonrpc_result(_tool_error(f"Internal error executing {tool_name}"), rpc_id)

    if method == 'resources/list':
        return _jsonrpc_result({"resources": []}, rpc_id)

    if method == 'prompts/list':
        return _jsonrpc_result({"prompts": []}, rpc_id)

    if method == 'ping':
        return _jsonrpc_result({}, rpc_id)

    return _jsonrpc_error(-32601, f"Method not found: {method}", rpc_id)


async def _handle_jsonrpc(body: Any, token_info: dict | None) -> Response:
    if isinstance(body, list):
        return JSONResponse(_jsonrpc_error(-32600, "Batch requests not supported"), status_code=400)

    if not isinstance(body, dict):
        return JSONResponse(_jsonrpc_error(-32600, "Invalid request", None))
    resp = _handle_request(body, token_info)
    if resp is None:
        return Response(status_code=202)
    return JSONResponse(resp)


def _require_mcp_enabled():
    if not get_config(enricher_db, 'mcp_enabled', False):
        raise HTTPException(status_code=404, detail="MCP not enabled")


@router.get("/api/mcp")
async def mcp_get(request: Request):
    _require_mcp_enabled()
    _validate_origin(request)
    _validate_protocol_version(request)

    token = _get_bearer_token(request)
    token_info = _lookup_token(token)
    if not token_info:
        raise HTTPException(status_code=401, detail="Unauthorized")

    async def _event_stream():
        yield ": connected\n\n"
        while True:
            await asyncio.sleep(15)
            yield ": ping\n\n"

    return StreamingResponse(_event_stream(), media_type="text/event-stream")


@router.post("/api/mcp")
async def mcp_post(request: Request):
    _require_mcp_enabled()
    _validate_origin(request)
    _validate_protocol_version(request)

    token = _get_bearer_token(request)
    token_info = _lookup_token(token)
    if not token_info:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON") from None

    return await _handle_jsonrpc(body, token_info)


# ── Settings + Token Management ─────────────────────────────────────────────

@router.get("/api/settings/mcp")
def get_mcp_settings():
    return {
        "enabled": get_config(enricher_db, "mcp_enabled", False),
        "audit_enabled": get_config(enricher_db, "mcp_audit_enabled", False),
        "audit_retention_days": get_config(enricher_db, "mcp_audit_retention_days", 10),
        "allowed_origins": get_config(enricher_db, "mcp_allowed_origins", []),
    }


@router.put("/api/settings/mcp")
def update_mcp_settings(body: dict):
    if 'enabled' in body:
        set_config(enricher_db, "mcp_enabled", bool(body['enabled']))
    if 'audit_enabled' in body:
        set_config(enricher_db, "mcp_audit_enabled", bool(body['audit_enabled']))
    if 'audit_retention_days' in body:
        try:
            days = int(body['audit_retention_days'])
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="audit_retention_days must be an integer") from None
        if days < 1 or days > 365:
            raise HTTPException(status_code=400, detail="audit_retention_days must be between 1 and 365")
        set_config(enricher_db, "mcp_audit_retention_days", days)
    if 'allowed_origins' in body:
        origins = body['allowed_origins'] or []
        if not isinstance(origins, list):
            raise HTTPException(status_code=400, detail="allowed_origins must be a list")
        set_config(enricher_db, "mcp_allowed_origins", origins)
    return {"success": True}



@router.get("/api/settings/mcp/scopes")
def list_mcp_scopes():
    return {
        "scopes": [
            {"id": scope, "description": _SCOPE_DESCRIPTIONS.get(scope, "")}
            for scope in sorted(_SCOPES)
        ]
    }


@router.get("/api/settings/mcp/audit")
def list_mcp_audit(limit: int = 200, offset: int = 0):
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'api_call'")
            total = cur.fetchone()['count']
            cur.execute("""
                SELECT a.id, a.token_id, t.name as token_name, t.token_prefix,
                       a.detail, a.created_at
                FROM audit_log a
                LEFT JOIN api_tokens t ON t.id = a.token_id
                WHERE a.action = 'api_call'
                ORDER BY a.created_at DESC
                LIMIT %s OFFSET %s
            """, [limit, offset])
            rows = cur.fetchall()
        conn.commit()

        entries = []
        for row in rows:
            item = dict(row)
            if item.get('created_at'):
                item['created_at'] = item['created_at'].isoformat()
            # Extract fields from detail JSONB for backward compatibility
            detail = item.pop('detail', None) or {}
            if isinstance(detail, str):
                try:
                    detail = json.loads(detail)
                except (json.JSONDecodeError, TypeError):
                    detail = {}
            item['tool_name'] = detail.get('tool_name')
            item['scope'] = detail.get('scope')
            item['success'] = detail.get('success')
            item['error'] = detail.get('error')
            item['params'] = detail.get('params')
            entries.append(item)

        return {"entries": entries, "total": total, "limit": limit, "offset": offset}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to list MCP audit log")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)
