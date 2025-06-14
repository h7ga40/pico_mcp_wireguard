# MCP for Raspberry Pi Pico W

## LED Control via JSON-RPC

The firmware exposes JSON-RPC tools that can be invoked using the `tools/call` method. Use `tools/list` to discover available tools:
`set_location`, `set_switch_id`, and `set_switch`.
These allow you to configure the target switch and toggle the onboard LED.

Example requests:

```json
{ "jsonrpc": "2.0", "method": "tools/call",
  "params": { "name": "set_location", "arguments": { "location": "office" } },
  "id": 1 }
```

```json
{ "jsonrpc": "2.0", "method": "tools/call",
  "params": { "name": "set_switch_id", "arguments": { "switch_id": "led" } },
  "id": 2 }
```

```json
{ "jsonrpc": "2.0", "method": "tools/call",
  "params": { "name": "set_switch", "arguments": { "state": "on" } },
  "id": 3 }
```

Call `set_switch` with `"state": "on"` or `"off"`. The LED changes only when the
request's `location` or `switch_id` matches the previously set values or when
both fields are omitted.

## Installing the pico-sdk

The following is an excerpt from a previous setup guide.

1. Create a working directory

   ```bash
   mkdir -p ~/.pico-sdk/sdk
   ```

2. Download the latest release (2.1.1) from the official Raspberry Pi repository

   ```bash
   cd ~/.pico-sdk/sdk
   git clone -b 2.1.1 https://github.com/raspberrypi/pico-sdk.git 2.1.1
   cd 2.1.1
   git submodule update --init
   ```

3. Set the `PICO_SDK_PATH` environment variable

   ```bash
   export PICO_SDK_PATH=$HOME/.pico-sdk/sdk/2.1.1
   ```

After verifying that the repository was cloned and its submodules were checked out,
the pico-sdk will be available under `~/.pico-sdk/sdk/2.1.1`.

## Build Instructions

The commands below automatically fetch the Pico SDK and build the project.

```bash
mkdir build
cd build
cmake -E env PICO_SDK_FETCH_FROM_GIT=1 cmake ..
make -j$(nproc)
```

When the build succeeds, artifacts such as `pico_mcp.uf2` are generated in the
`build` directory.
