# pico_mcp
MCP for Raspberry Pi Pico

## LED Control via JSON-RPC

The firmware exposes a `mcp.call` JSON-RPC method. When the
`location` field matches the value configured with `mcp.set_context`,
calling `mcp.call` with `switch_id` set to `led` and `state` set to
`"ON"` or `"OFF"` toggles the onboard LED.

Example request:

```json
{"jsonrpc": "2.0", "id": 1, "method": "mcp.call", "params": {"location": "office", "switch_id": "led", "state": "ON"}}
```

This will turn the LED on when `location` equals `office` in the stored
context.
