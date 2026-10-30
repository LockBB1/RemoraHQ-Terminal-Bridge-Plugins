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

## Responsibilities

1. Validate shell + context against allow-lists.
2. For SYSTEM context — verify supplied TOTP token via `otplib` against the
   calling user's `otpsecret` (same scheme Mesh uses for login 2FA).
3. Issue a correlation `sessionId` + a `relayUrl` pointing at Mesh's native
   `meshrelay.ashx` with the nodeid + shell parameters.
4. Dispatch an audit event for every open (success + denial).

The plugin does **not** open the relay socket itself — the Terminal UI in
RC-12.1+ uses the `relayUrl` to do that, binary WS proxying xterm.js I/O.

## Wire protocol

Client → Server:

```jsonc
{
  "action": "plugin",
  "plugin": "remoraTerminalBridge",
  "pluginaction": "open",
  "nodeId": "node//...",
  "shell": "cmd" | "powershell" | "bash" | "zsh",
  "context": "user" | "system",
  "totpToken": "<6 digits, required if context=system>",
  "tag": "<correlation-id>",
  "responseid": "<correlation-id>"
}
```

Server → Client (success):

```jsonc
{
  "action": "plugin",
  "plugin": "remoraTerminalBridge",
  "pluginaction": "open",
  "tag": "...",
  "responseid": "...",
  "result": "ok",
  "sessionId": "<32-char hex>",
  "relayUrl": "/meshrelay.ashx?id=...&nodeid=...&p=2&shell=...&context=..."
}
```

Server → Client (error):

```jsonc
{
  "result": "error",
  "error": "invalid_nodeId" | "invalid_shell" | "invalid_context" | "2fa-failed" | "unknown_pluginaction"
}
```

## Audit events

Every open attempt dispatches:

```jsonc
{
  "etype": "terminal-open",
  "action": "plugin.terminal.open",
  "msg": "Terminal session opened" | "Terminal open denied: invalid TOTP for SYSTEM context",
  "nodeid": "node//...",
  "shell": "...",
  "context": "user" | "system",
  "actor": "user//...",
  "sessionId": "...",       // only on success
  "status": "success" | "denied"
}
```

Visible in `Audit Log` page in RemoraHQ.

## Admin terminal password API

Native plugin version `0.11.0` adds `pluginaction: "openAdmin"` with `nodeId`,
`shell: "cmd" | "powershell"`, `context: "operator"` and `password`. This is the
password of the already authenticated MeshCentral/RemoraHQ account. Every open
checks it through MeshCentral `webserver.authenticate`, requires the returned
user id to match the caller, then rechecks the active caller, role and node rights
before issuing the terminal response. No password or TOTP grant is cached.
The per-account password budget is five attempts per minute per server process,
including successful opens; it is not a shared cluster limiter.

The Admin API allows super-admin, administrator and operator roles, denies the
auditor override, requires a visible target with remote control rights and
rejects view-only/terminal-prohibited rights. Full native node-admin rights retain
their native exception. Locked accounts and retired sessions fail closed.
Local login keys and LDAP's existing Core email-local-part convention are
supported; a different LDAP naming convention can reject a correct password.
SSPI and other external authentication modes are unsupported by this API.

The execution context remains `operator`, using the existing native protocols
`1/6`. The password is never sent to the agent or written to audit/replies.
This check protects this plugin API only: native MeshCentral relay access keeps
its existing policy and can bypass the RemoraHQ Admin flow. Native/overlay and
agent logon behavior are unchanged. Device Policy restrictions still apply.

The matching SPA applies the previous route MFA check before each non-Admin
connect when its entry proof is stale. Operator/SYSTEM keep their separate TOTP
checks. Admin password verification neither creates nor refreshes an MFA proof.
Deploy this plugin with the matching SPA: old plugins reject `openAdmin`; old
SPAs continue their previous flow. The setup snapshot is not updated here.

## Remote Install

Native plugin version `0.10.0` accepts `remoteInstall.run` with `host`,
`groupId` and optional `installFlags`, without a TOTP field or grant. The
authenticated caller still needs `canRemoteInstall` and install rights on the
target Machine Group. Host/group validation, the per-actor push limit,
fail-closed duplicate detection, sealed local push credentials and audit remain.
Push Account administration and terminal TOTP checks are separate and unchanged.

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
