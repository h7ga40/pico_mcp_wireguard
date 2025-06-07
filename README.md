# MCP for Raspberry Pi Pico W

## LED Control via JSON-RPC

The firmware exposes a `mcp.call` JSON-RPC method. When the `location` field matches the value configured with `mcp.set_context`, calling `mcp.call` with `switch_id` set to `led` and `state` set to `"ON"` or `"OFF"` toggles the onboard LED.

Example request:

```json
{ "jsonrpc": "2.0", "method": "mcp.set_context", "params": { "context": { "switch_servers": { "servers": [ { "location": "kitchen", "url": "http://192.168.1.101:8080" } ] } } }, "id": 1 }
```

```json
{ "jsonrpc": "2.0", "method": "mcp.call", "params": { "function": "switch_control.set_state", "switch_id": "main_light", "state": "on", "location": "kitchen" }, "id": 2 }
```

This will turn the LED on when `location` equals `office` in the stored context.
