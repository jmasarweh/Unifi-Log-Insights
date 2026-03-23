/**
 * Tests for api.js — verify fetch call patterns and error handling.
 * buildQS is not exported, so we test it indirectly via fetchLogs.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  fetchLogs,
  fetchHealth,
  fetchStats,
  fetchStatsOverview,
  fetchStatsCharts,
  fetchStatsTables,
  enrichIP,
  getExportUrl,
  createSavedView,
} from '../api'


beforeEach(() => {
  vi.restoreAllMocks()
})


describe('fetchLogs (indirectly tests buildQS)', () => {
  it('calls /api/logs with query params', async () => {
    const mockData = { logs: [], total: 0 }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockData),
    }))

    const result = await fetchLogs({ log_type: 'firewall', time_range: '24h' })
    expect(result).toEqual(mockData)

    const url = fetch.mock.calls[0][0]
    expect(url).toContain('/api/logs?')
    expect(url).toContain('log_type=firewall')
    expect(url).toContain('time_range=24h')
  })

  it('omits null/undefined/empty params from query string', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    }))

    await fetchLogs({ log_type: 'dns', src_ip: null, dst_ip: undefined, query: '' })

    const url = fetch.mock.calls[0][0]
    expect(url).toContain('log_type=dns')
    expect(url).not.toContain('src_ip')
    expect(url).not.toContain('dst_ip')
    expect(url).not.toContain('query')
  })

  it('throws on non-ok response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.resolve({}),
    }))

    await expect(fetchLogs()).rejects.toThrow('API error: 500')
  })
})


describe('fetchHealth', () => {
  it('calls /api/health', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ status: 'ok' }),
    }))

    const result = await fetchHealth()
    expect(result.status).toBe('ok')
    expect(fetch.mock.calls[0][0]).toBe('/api/health')
  })
})


describe('fetchStats', () => {
  it('passes time_range as query param', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    }))

    await fetchStats('7d')
    expect(fetch.mock.calls[0][0]).toBe('/api/stats?time_range=7d')
  })

  it('defaults to 24h', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    }))

    await fetchStats()
    expect(fetch.mock.calls[0][0]).toBe('/api/stats?time_range=24h')
  })
})


/** Mock a non-ok response that works with apiFetch (which calls resp.json()). */
function mockErrorResponse(status) {
  return { ok: false, status, json: () => Promise.resolve({}) }
}

describe('fetchStatsOverview', () => {
  it('calls /api/stats/overview with time_range', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ total: 100 }),
    }))

    const result = await fetchStatsOverview('7d')
    expect(fetch.mock.calls[0][0]).toBe('/api/stats/overview?time_range=7d')
    expect(result.total).toBe(100)
  })

  it('defaults to 24h', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    }))

    await fetchStatsOverview()
    expect(fetch.mock.calls[0][0]).toBe('/api/stats/overview?time_range=24h')
  })

  it('throws on non-ok response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockErrorResponse(500)))

    await expect(fetchStatsOverview()).rejects.toThrow('API error: 500')
  })
})


describe('fetchStatsCharts', () => {
  it('calls /api/stats/charts with time_range', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ logs_over_time: [] }),
    }))

    const result = await fetchStatsCharts('30d')
    expect(fetch.mock.calls[0][0]).toBe('/api/stats/charts?time_range=30d')
    expect(result.logs_over_time).toEqual([])
  })

  it('defaults to 24h', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    }))

    await fetchStatsCharts()
    expect(fetch.mock.calls[0][0]).toBe('/api/stats/charts?time_range=24h')
  })

  it('throws on non-ok response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockErrorResponse(500)))

    await expect(fetchStatsCharts()).rejects.toThrow('API error: 500')
  })
})


describe('fetchStatsTables', () => {
  it('calls /api/stats/tables with time_range', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ top_dns: [] }),
    }))

    const result = await fetchStatsTables('60d')
    expect(fetch.mock.calls[0][0]).toBe('/api/stats/tables?time_range=60d')
    expect(result.top_dns).toEqual([])
  })

  it('defaults to 24h', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    }))

    await fetchStatsTables()
    expect(fetch.mock.calls[0][0]).toBe('/api/stats/tables?time_range=24h')
  })

  it('throws on non-ok response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockErrorResponse(500)))

    await expect(fetchStatsTables()).rejects.toThrow('API error: 500')
  })
})


describe('enrichIP', () => {
  it('uses POST and encodes IP', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ ip: '1.1.1.1' }),
    }))

    await enrichIP('1.1.1.1')
    const [url, opts] = fetch.mock.calls[0]
    expect(url).toBe('/api/enrich/1.1.1.1')
    expect(opts.method).toBe('POST')
  })

  it('throws with detail message on error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      json: () => Promise.resolve({ detail: 'Rate limited' }),
    }))

    await expect(enrichIP('1.1.1.1')).rejects.toThrow('Rate limited')
  })
})


describe('getExportUrl', () => {
  it('builds export URL with params', () => {
    const url = getExportUrl({ log_type: 'firewall', time_range: '7d' })
    expect(url).toContain('/api/export?')
    expect(url).toContain('log_type=firewall')
    expect(url).toContain('time_range=7d')
  })

  it('returns base URL with no params', () => {
    const url = getExportUrl()
    expect(url).toBe('/api/export?')
  })
})


describe('createSavedView', () => {
  it('sends POST with JSON body', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ id: 1 }),
    }))

    await createSavedView('My View', { log_type: 'dns' })
    const [url, opts] = fetch.mock.calls[0]
    expect(url).toBe('/api/views')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ name: 'My View', filters: { log_type: 'dns' } })
  })
})
