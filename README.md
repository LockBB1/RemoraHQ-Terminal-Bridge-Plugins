# RemoraHQ - Terminal Bridge

MeshCentral plugin providing the server-side validator + correlation issuer
for RemoraHQ terminal sessions. Fifth member of the `RemoraHQ - *` plugin
family.

## Identity

| Field | Value |
|-------|-------|
| Display name | `RemoraHQ - Terminal Bridge` |
| Short name (Mesh shortName) | `remoraTerminalBridge` |
| Entry file | `remoraTerminalBridge.js` |
| Source repo folder | `RemoraHQ-Terminal-Bridge-Plugins` |
| Deploy folder under Mesh | `meshcentral/plugins/remoraTerminalBridge` |

## Terminal contract (Bridge 0.12.0)

The `open` action accepts `nodeId`, `shell` (`cmd`, `powershell`, `bash`,
`zsh`) and the optional `context: "user"`. It returns a session identifier,
relay URL, native User protocol (8 or 9), and agent tunnel details. The plugin
does not open the relay socket itself. The matching SPA retains its route MFA
check and sends only User options.

Operator and SYSTEM modes are disabled, including requests using old grants or
TOTP. `openAdmin` returns `terminal_admin_unavailable` without verifying a
password or issuing a relay cookie. Admin remains unavailable until Windows
identity and elevation can be established. Unsupported legacy inputs are
rejected instead of falling back to User.

This applies only to this plugin and matching SPA. Native MeshCentral relay and
agent behavior are separate and unchanged; this does not close that route.
Deployments need matching plugin and SPA versions. The `.setup` snapshot is not
updated by edits to this checkout.

## Remote Install

Native plugin version `0.10.0` accepts `remoteInstall.run` with `host`,
`groupId` and optional `installFlags`, without a TOTP field or grant. The
authenticated caller still needs `canRemoteInstall` and install rights on the
target Machine Group. Host/group validation, the per-actor push limit,
fail-closed duplicate detection, sealed local push credentials and audit remain.
Push Account administration remains separately authorized.

Deploy this plugin and the matching SPA together. An earlier plugin can reject
the new SPA with `2fa-failed`; an earlier SPA still asks for TOTP even though
this run handler no longer validates it. Mixed versions do not provide the new
policy consistently. The setup package snapshot and actual loaded server plugin
must be checked separately; editing this checkout does not update either.

`npm test` exercises the real dispatcher with in-memory filesystem, database,
installer and process fixtures. It never runs PowerShell or WinRM and does not
prove DPAPI decryption, a live agent install or deployment readiness. The npm
package metadata version is independent of the native `config.json` version.

## Install (development)

```powershell
# from MeshCentral root
New-Item -ItemType SymbolicLink `
  -Path .\plugins\remoraTerminalBridge `
  -Target "D:\…\RemoraHQ-Terminal-Bridge-Plugins"
```

Then register via `Admin → Plugins → Add` with the `configUrl` from `config.json`.

## License

Apache-2.0 (matches MeshCentral). See `LICENSE`.
