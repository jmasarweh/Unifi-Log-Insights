# Changelog

## Unreleased

- Fix Firewall Syslog Manager policy toggles on UniFi Network 10.x by keeping
  firewall policies and firewall zones in the same Network v2 identifier
  namespace. This restores the zone matrix and prevents PATCH requests from
  using synthesized policy ids when UniFi's Integration API omits policy ids or
  returns zone UUIDs that cannot be joined to v2 policy zone ids.
