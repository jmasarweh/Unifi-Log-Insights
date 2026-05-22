/**
 * Shared firewall policy logging helpers.
 *
 * Used by both FirewallRules.jsx (matrix toggle) and LogDetail.jsx (row toggle)
 * to avoid duplicating controllability checks and confirmation copy.
 */

/** Whether a policy can have its logging toggled. */
export function isControllablePolicy(policy) {
  if (!policy) return false
  if (!policy.id) return false
  if (policy.metadata?.origin === 'DERIVED') return false
  if (policy.enabled === false) return false
  return true
}

/** Warning text shared by both FirewallRules bulk confirm and LogDetail single confirm. */
export const SYSLOG_DELAY_WARNING =
  'Changes are applied immediately on the UniFi Gateway but may take up to 5 minutes to reflect in the Log Stream.'

const _LEGACY_RE = /^(.+?)-(A|B|D|R)-(\d+)(?:-[A-Z])?$/
const _ZONE_INDEX_RE = /^([A-Z][A-Z0-9]*_[A-Z][A-Z0-9]*)-(\d+)$/
const _ACTION_LABELS = { 'A': 'Allow', 'B': 'Block', 'D': 'Drop', 'R': 'Reject' }

/** Parse a syslog rule_name into {chain, actionCode, action, priority} or null.
 *  Supports legacy (CHAIN-A-123) and zone-index (ZONE_ZONE-123) formats.
 *  For zone-index, action is null — use log.rule_action from backend instead. */
export function parseRuleName(ruleName) {
  if (!ruleName) return null
  const m = ruleName.match(_LEGACY_RE)
  if (m) {
    return {
      chain: m[1],
      actionCode: m[2],
      action: _ACTION_LABELS[m[2]],
      priority: parseInt(m[3], 10),
    }
  }
  const m2 = ruleName.match(_ZONE_INDEX_RE)
  if (m2) {
    return {
      chain: m2[1],
      actionCode: null,
      action: null,
      priority: parseInt(m2[2], 10),
    }
  }
  return null
}
