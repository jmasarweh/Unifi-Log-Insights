"""Tests for proxy-auth shared-secret trust model.

# @coderabbit: Helper functions intentionally duplicate production logic rather than
# importing from routes.auth. The production functions depend on module-level state
# (PROXY_AUTH_TOKEN from env vars) and take Starlette Request objects, making them
# unsuitable for pure unit tests. These helpers test the algorithm in isolation
# with caller-supplied secrets and values.
"""

import hashlib
import hmac

import pytest


def _derive_proxy_token(secret: str) -> str:
    """Replicate the derivation logic from routes/auth.py."""
    return hmac.new(secret.encode(), b'proxy-auth', hashlib.sha256).hexdigest()


def _should_trust_proxy(expected_token: str, header_value: str | None) -> bool:
    """Replicate the trust check from routes/auth.py."""
    if not header_value:
        return False
    return hmac.compare_digest(expected_token, header_value)


class TestProxyTokenDerivation:
    """Verify HMAC derivation produces stable, non-empty tokens."""

    def test_deterministic(self):
        assert _derive_proxy_token('mysecret') == _derive_proxy_token('mysecret')

    def test_different_secrets_different_tokens(self):
        assert _derive_proxy_token('secret-a') != _derive_proxy_token('secret-b')

    def test_non_empty(self):
        token = _derive_proxy_token('any-secret')
        assert len(token) == 64  # SHA-256 hex digest

    def test_empty_secret_still_produces_token(self):
        """Even with empty secret, derivation must not crash."""
        token = _derive_proxy_token('')
        assert len(token) == 64


class TestProxyHeaderTrust:
    """Verify header-matching logic (unit-level, no HTTP)."""

    def test_matching_header_trusts_forwarded_proto(self):
        token = _derive_proxy_token('test-secret')
        # Simulate: request has matching X-ULI-Proxy-Auth
        assert _should_trust_proxy(token, token) is True

    def test_wrong_header_rejects(self):
        token = _derive_proxy_token('test-secret')
        assert _should_trust_proxy(token, 'wrong-value') is False

    def test_missing_header_rejects(self):
        token = _derive_proxy_token('test-secret')
        assert _should_trust_proxy(token, None) is False

    def test_empty_header_rejects(self):
        token = _derive_proxy_token('test-secret')
        assert _should_trust_proxy(token, '') is False


# ── Fake Request for get_real_client_ip / get_forwarded_proto unit tests ──

class _FakeURL:
    def __init__(self, scheme):
        self.scheme = scheme

class _FakeClient:
    def __init__(self, host):
        self.host = host

class _FakeRequest:
    """Minimal Request stand-in with .client.host and .headers and .url.scheme."""
    def __init__(self, headers: dict, client_host: str = '127.0.0.1', scheme: str = 'http'):
        self.client = _FakeClient(client_host)
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.url = _FakeURL(scheme)


def _get_real_client_ip(request, expected_token: str) -> str:
    """Replicate get_real_client_ip from routes/auth.py."""
    client_ip = request.client.host if request.client else '127.0.0.1'
    if not _should_trust_proxy(expected_token, request.headers.get('x-uli-proxy-auth')):
        return client_ip
    xff = request.headers.get('x-forwarded-for', '')
    if not xff:
        return client_ip
    parts = [p.strip() for p in xff.split(',')]
    for ip in reversed(parts):
        if ip:
            return ip
    return client_ip


def _get_forwarded_proto(request, expected_token: str) -> str:
    """Replicate get_forwarded_proto from routes/auth.py."""
    if _should_trust_proxy(expected_token, request.headers.get('x-uli-proxy-auth')):
        proto = request.headers.get('x-forwarded-proto', '').lower()
        if proto in ('http', 'https'):
            return proto
    return str(request.url.scheme)


class TestGetRealClientIp:
    """Verify X-Forwarded-For is honored only with valid proxy auth."""

    def setup_method(self):
        self.token = _derive_proxy_token('test-secret')

    def test_xff_honored_with_valid_auth(self):
        # Single XFF entry — matches our single-proxy model where nginx/Caddy/Traefik
        # set $remote_addr (not $proxy_add_x_forwarded_for).
        req = _FakeRequest({
            'x-uli-proxy-auth': self.token,
            'x-forwarded-for': '203.0.113.42',
        }, client_host='172.17.0.1')
        assert _get_real_client_ip(req, self.token) == '203.0.113.42'

    def test_xff_ignored_without_auth(self):
        req = _FakeRequest({
            'x-forwarded-for': '203.0.113.42',
        }, client_host='172.17.0.1')
        assert _get_real_client_ip(req, self.token) == '172.17.0.1'

    def test_xff_ignored_with_wrong_auth(self):
        req = _FakeRequest({
            'x-uli-proxy-auth': 'wrong',
            'x-forwarded-for': '203.0.113.42',
        }, client_host='172.17.0.1')
        assert _get_real_client_ip(req, self.token) == '172.17.0.1'

    def test_no_xff_returns_client_ip(self):
        req = _FakeRequest({
            'x-uli-proxy-auth': self.token,
        }, client_host='10.0.0.5')
        assert _get_real_client_ip(req, self.token) == '10.0.0.5'

    def test_single_xff_entry(self):
        req = _FakeRequest({
            'x-uli-proxy-auth': self.token,
            'x-forwarded-for': '198.51.100.7',
        }, client_host='172.17.0.1')
        assert _get_real_client_ip(req, self.token) == '198.51.100.7'


class TestGetForwardedProto:
    """Verify X-Forwarded-Proto is honored only with valid proxy auth."""

    def setup_method(self):
        self.token = _derive_proxy_token('test-secret')

    def test_proto_honored_with_valid_auth(self):
        req = _FakeRequest({
            'x-uli-proxy-auth': self.token,
            'x-forwarded-proto': 'https',
        })
        assert _get_forwarded_proto(req, self.token) == 'https'

    def test_proto_ignored_without_auth(self):
        req = _FakeRequest({
            'x-forwarded-proto': 'https',
        })
        assert _get_forwarded_proto(req, self.token) == 'http'

    def test_proto_ignored_with_wrong_auth(self):
        req = _FakeRequest({
            'x-uli-proxy-auth': 'wrong',
            'x-forwarded-proto': 'https',
        })
        assert _get_forwarded_proto(req, self.token) == 'http'

    def test_invalid_proto_ignored(self):
        req = _FakeRequest({
            'x-uli-proxy-auth': self.token,
            'x-forwarded-proto': 'ftp',
        })
        assert _get_forwarded_proto(req, self.token) == 'http'

