/**
 * Tests for VPN toast per-interface dismissal (set-difference logic).
 *
 * Verifies that vpn_toast_dismissed now stores a per-interface array
 * (was a global boolean), and that Dismiss posts the current unlabeled
 * interface names while X is session-only.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'

// ── Mock setup (before App import) ──────────────────────────────────────────

const baseConfig = {
  wan_interfaces: ['ppp0'],
  interface_labels: {},
  setup_complete: true,
  config_version: 2,
  unifi_enabled: false,
  vpn_networks: {},
  vpn_toast_dismissed: [],
  wan_ip_by_iface: {},
  upgrade_v2_dismissed: true,
  mcp_enabled: false,
}

const mockInterfaces = [
  { name: 'tun0', count: 50 },
  { name: 'tun1', count: 30 },
  { name: 'ppp0', count: 200 },
  { name: 'br0', count: 100 },
]

// Per-test config override — set in each test before render
let configOverride = {}

vi.mock('../api', () => ({
  fetchConfig: vi.fn(() => Promise.resolve({ ...baseConfig, ...configOverride })),
  fetchHealth: vi.fn(() => Promise.resolve({ status: 'ok', version: '3.3.0' })),
  fetchLatestRelease: vi.fn(() => Promise.resolve(null)),
  dismissUpgradeModal: vi.fn(() => Promise.resolve()),
  dismissVpnToast: vi.fn(() => Promise.resolve({ success: true })),
  fetchInterfaces: vi.fn(() => Promise.resolve({ interfaces: [...mockInterfaces] })),
  fetchUiSettings: vi.fn(() => Promise.resolve({})),
  updateUiSettings: vi.fn(() => Promise.resolve()),
  fetchUniFiSettings: vi.fn(() => Promise.resolve({})),
  fetchAuthStatus: vi.fn(() => Promise.resolve({ auth_enabled: false })),
  fetchAuthMe: vi.fn(() => Promise.resolve(null)),
  authLogout: vi.fn(() => Promise.resolve()),
  setAuthExpiredHandler: vi.fn(),
}))

vi.mock('../utils', () => ({
  loadInterfaceLabels: vi.fn(() => ({})),
}))

vi.mock('../vpnUtils', () => ({
  isVpnInterface: vi.fn((name) => name.startsWith('tun') || name.startsWith('wg')),
}))

// Mock heavy child components to keep tests fast
vi.mock('../components/LogStream', () => ({ default: () => <div data-testid="logstream" /> }))
vi.mock('../components/SetupWizard', () => ({ default: () => <div /> }))
vi.mock('../components/SettingsOverlay', () => ({ default: () => <div /> }))
vi.mock('../components/Dashboard', () => ({
  default: () => <div />,
  DashboardSkeleton: () => <div />,
}))
vi.mock('../components/ThreatMap', () => ({
  default: () => <div />,
  ThreatMapSkeleton: () => <div />,
}))
vi.mock('../components/FlowView', () => ({ default: () => <div /> }))
vi.mock('../components/FlowViewSkeleton', () => ({ default: () => <div /> }))
vi.mock('../components/Login', () => ({ default: () => <div /> }))

// Import after mocks are declared
import App from '../App'
import { dismissVpnToast, fetchConfig, fetchInterfaces } from '../api'

beforeEach(() => {
  vi.clearAllMocks()
  configOverride = {}
})


describe('VPN toast per-interface dismissal', () => {
  it('shows toast when new interface is not dismissed', async () => {
    configOverride = { vpn_toast_dismissed: ['tun0'] }

    render(<App />)

    await waitFor(() => {
      expect(screen.getByText(/Unlabeled VPN networks found/)).toBeInTheDocument()
    })
  })

  it('hides toast when all unlabeled are dismissed', async () => {
    configOverride = { vpn_toast_dismissed: ['tun0', 'tun1'] }

    render(<App />)

    // Wait for the interfaces fetch to complete
    await waitFor(() => {
      expect(fetchInterfaces).toHaveBeenCalled()
    })

    // Allow effects to settle
    await new Promise(r => setTimeout(r, 100))
    expect(screen.queryByText(/Unlabeled VPN networks found/)).not.toBeInTheDocument()
  })

  it('Dismiss posts current unlabeled interface names', async () => {
    configOverride = { vpn_toast_dismissed: [] }

    render(<App />)

    await waitFor(() => {
      expect(screen.getByText(/Unlabeled VPN networks found/)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Dismiss'))

    await waitFor(() => {
      expect(dismissVpnToast).toHaveBeenCalledTimes(1)
    })
    const args = dismissVpnToast.mock.calls[0][0]
    expect(args).toEqual(expect.arrayContaining(['tun0', 'tun1']))
    expect(args).toHaveLength(2)
  })

  it('Dismiss reloads config so toast stays hidden on next poll', async () => {
    configOverride = { vpn_toast_dismissed: [] }

    render(<App />)

    await waitFor(() => {
      expect(screen.getByText(/Unlabeled VPN networks found/)).toBeInTheDocument()
    })

    // After dismiss, the backend accepts ['tun0', 'tun1'] — simulate config
    // reload returning the updated dismissed list so the next poll sees it.
    const initialCallCount = fetchConfig.mock.calls.length
    dismissVpnToast.mockImplementationOnce(() => {
      // On next fetchConfig call (reloadConfig), return dismissed interfaces
      configOverride = { vpn_toast_dismissed: ['tun0', 'tun1'] }
      return Promise.resolve({ success: true })
    })

    fireEvent.click(screen.getByText('Dismiss'))

    // Verify reloadConfig was triggered (fetchConfig called again)
    await waitFor(() => {
      expect(fetchConfig.mock.calls.length).toBeGreaterThan(initialCallCount)
    })

    // Allow effects to settle after config reload
    await new Promise(r => setTimeout(r, 100))
    expect(screen.queryByText(/Unlabeled VPN networks found/)).not.toBeInTheDocument()
  })

  it('X button is session-only and does not call dismiss API', async () => {
    configOverride = { vpn_toast_dismissed: [] }

    render(<App />)

    await waitFor(() => {
      expect(screen.getByText(/Unlabeled VPN networks found/)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTestId('vpn-toast-close'))

    await waitFor(() => {
      expect(screen.queryByText(/Unlabeled VPN networks found/)).not.toBeInTheDocument()
    })

    expect(dismissVpnToast).not.toHaveBeenCalled()
  })
})
