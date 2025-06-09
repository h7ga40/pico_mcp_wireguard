# MCP for Raspberry Pi Pico W

## LED Control via JSON-RPC

The firmware exposes a `set_switch` JSON-RPC method. When the `location` field matches the value configured with `set_context`, calling `set_switch` with `switch_id` set to `led` and `state` set to `"ON"` or `"OFF"` toggles the onboard LED.

Example request:

```json
{ "jsonrpc": "2.0", "method": "set_context", "params": { "context": { "switch_servers": { "servers": [ { "location": "kitchen", "url": "http://192.168.1.101:8080" } ] } } }, "id": 1 }
```

```json
{ "jsonrpc": "2.0", "method": "set_switch", "params": { "function": "switch_control.set_state", "switch_id": "main_light", "state": "on", "location": "kitchen" }, "id": 2 }
```

This will turn the LED on when `location` equals `office` in the stored context.
