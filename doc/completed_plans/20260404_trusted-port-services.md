Review 1 completed: 2026-04-04

# Plan: Trust well-known port/service pairs at any Nmap confidence level

## Summary

Add a `TRUSTED_PORT_SERVICES` allowlist so that well-known port/service combinations (e.g. 443/https, 445/microsoft-ds, 636/ldapssl) are classified as normal confidence even when Nmap reports `conf=3, method=table`. Currently every service below `conf=10` lands in `low_confidence/`, which is correct for obscure table guesses (d-star:9011 on a Canon printer) but wrong for IANA-standard assignments where the port number *is* the definition.

## Problem

Nmap assigns `conf=3, method=table` to any service it identifies solely from its `nmap-services` port table. The tool treats all `conf < 10` equally, so well-known services on their standard ports get mixed in with genuinely uncertain identifications:

- **False low-confidence**: https:443, microsoft-ds:445, ldapssl:636, globalcatLDAPssl:3269, kpasswd5:464, wsmans:5986, jetdirect:9100, https-alt:8443 -- these are the IANA-registered services for those ports.
- **Correctly low-confidence**: d-star:9011, ogs-client:9007, panagolin-ident:9021, paragent:9022 on Canon printers; pando-pub:7680 (actually Windows Delivery Optimization, not Pando); snpp:444, realserver:7070, unknown:*.

The main pattern is SSL/TLS counterparts of already-confirmed services on the same host (LDAP:389 confirmed at conf=10, but LDAPS:636 is conf=3 because Nmap can't probe through TLS the same way). Also affected: universally standard ports like 445/SMB and 9100/JetDirect.

## Goal

After implementation:
1. Services on ports listed in `TRUSTED_PORT_SERVICES` whose Nmap service name matches the expected name are written to the normal output directory, not `low_confidence/`.
2. All other `conf < 10` services remain in `low_confidence/` -- no change in behavior for them.
3. The allowlist is easy to audit and extend.

## Design

Add a single `dict[int, str]` constant, `TRUSTED_PORT_SERVICES`, mapping port numbers to their expected lowercase service names. Modify the `is_low_conf` check on line 166 to exclude matches against this dict.

```python
TRUSTED_PORT_SERVICES = {
    443: "https",
    445: "microsoft-ds",
    464: "kpasswd5",
    636: "ldapssl",
    993: "imaps",
    995: "pop3s",
    3269: "globalcatldapssl",
    5986: "wsmans",
    8443: "https-alt",
    9100: "jetdirect",
}
```

The confidence check becomes:

```python
is_low_conf = service_info["conf"] < 10 and TRUSTED_PORT_SERVICES.get(port_num) != service_name
```

This is a single-line logic change plus one new constant. No new functions, no structural changes, no new dependencies.

### Why an allowlist instead of alternatives

| Alternative | Rejected because |
|---|---|
| Lower the conf threshold (e.g. `< 3`) | conf=3 is the lowest table value; would let everything through |
| Sibling-aware boosting (check if plaintext service confirmed on same host) | More complex, requires a pre-pass to build per-host confirmed service sets; doesn't cover non-SSL cases like microsoft-ds:445 |
| Parse `nmap-services` at runtime | Adds file dependency and is overkill when ~10 entries cover the real-world cases |

The allowlist is explicit, auditable, zero-dependency, and trivially extensible.

## Affected Components

- `organize.py`: Add `TRUSTED_PORT_SERVICES` constant near existing module-level constants; modify the `is_low_conf` expression on line 161.

## Execution Notes

- **Executed**: 2026-04-04
- **Deviations**: Plan referenced line 166 for `is_low_conf`; actual location was line 149 (now line 161 after adding the constant). No logic deviations.
- **Changes**: Added `TRUSTED_PORT_SERVICES` dict (lines 19-30) and modified `is_low_conf` (line 161) in `organize.py`.
