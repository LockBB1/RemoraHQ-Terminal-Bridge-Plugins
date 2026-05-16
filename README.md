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
