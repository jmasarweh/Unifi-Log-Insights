import FirewallRules from './FirewallRules'

export default function SettingsFirewall({ unifiEnabled, supportsFirewall, onRestartWizard }) {
  return (
    <div>
      <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
        Firewall Rules
      </h2>
      {!unifiEnabled ? (
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center">
          <p className="text-xs text-gray-500 mb-3">
            Connect your UniFi controller to manage firewall rules.
          </p>
          <button
            onClick={onRestartWizard}
            className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
          >
            Run Setup Wizard
          </button>
        </div>
      ) : !supportsFirewall ? (
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center">
          <p className="text-xs text-gray-500">
            Firewall management requires a UniFi OS gateway (UDM, UDR, UCG Ultra).
            Self-hosted controllers do not support the Integration API needed for firewall rule management.
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-gray-700 bg-gray-950 p-4">
          <FirewallRules />
        </div>
      )}
    </div>
  )
}
