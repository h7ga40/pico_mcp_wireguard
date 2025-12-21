# Remote keyboard for W55RP20-EVB-Pico with WireGuard and MCP Server

## About the “W55RP20-EVB-Pico”

This is an evaluation board enabling Ethernet connectivity by combining the Raspberry Pi Pico's RP2040 CPU with the W5500, which features hardware TCP/IP.

<https://docs.wiznet.io/Product/Chip/MCU/W55RP20/w55rp20-evb-pico>

## Overview

```less
[ Linux / Windows PC ]
   WireGuard Client
   Tunnel IP: 10.7.0.1
        |
        |  (WireGuard over UDP, LAN)
        |
[ Raspberry Pi Pico ]
   wireguard-lwip
   Tunnel IP: 10.7.0.2
   listen_port: 51820
```

To access web pages that require keyboard operation, please visit the URL “http://10.7.0.2”.

## WireGuard Configuration (Windows)

Install WireGuard for Windows from <https://www.wireguard.com/install/>.

### Generate the Pico keys

Run in PowerShell:

```PowerShell
wg.exe genkey | Tee-Object pico.key | wg.exe pubkey > pico.pub
```

### Configure Windows

1. Launch WireGuard.
2. Choose **Add Tunnel** → **Add empty tunnel**.
3. A key pair is generated automatically; use those values for the PC peer.

Treat the generated public key as `<pc.pub>` and the private key as `<pc.key>`,
then update the tunnel configuration:

```ini
[Interface]
PrivateKey = <pc.key>
Address    = 10.7.0.1/32
[Peer]
PublicKey  = <pico.pub>
AllowedIPs = 10.7.0.2/24
Endpoint   = 192.168.1.50:51820
```

### Update the Pico firmware configuration

Edit `argument_definitions.h` and set the macros as follows:

| Macro | Value | Notes |
| - | - | - |
| WG_PRIVATE_KEY | `<pico.key>` | Pico private key |
| WG_ADDRESS | `10.7.0.2` | Pico IP address |
| WG_SUBNET_MASK_IP | `255.255.255.255` | PC subnet |
| WG_GATEWAY_IP | `0.0.0.0` | PC IP address |
| WG_PUBLIC_KEY | `<pc.pub>` | PC public key |
| WG_ALLOWED_IP |  | Unused |
| WG_ALLOWED_IP_MASK_IP |  | Unused |
| WG_ENDPOINT_IP | `192.168.1.100` | PC IP address |
| WG_ENDPOINT_PORT | `51820` | PC WireGuard port |

## WireGuard Configuration (Linux)

The steps below use the `wg-quick` helper on Debian/Ubuntu-style systems. Adapt
package names and service managers as needed for other distributions.

1. Install WireGuard utilities.

   ```bash
   sudo apt update
   sudo apt install wireguard wireguard-tools
   ```

2. Generate key pairs.

   ```bash
   # Pico key pair (copy `pico.key` and `pico.pub` into your firmware settings)
   wg genkey | tee pico.key | wg pubkey > pico.pub

   # Linux client key pair
   wg genkey | tee pc.key | wg pubkey > pc.pub
   ```

3. Create `/etc/wireguard/wg0.conf` with the following template, replacing
   the placeholder values to match your network and the Pico firmware values
   in `argument_definitions.h`:

   ```ini
   [Interface]
   PrivateKey = <pc.key>
   Address    = 10.7.0.1/32

   [Peer]
   PublicKey  = <pico.pub>
   AllowedIPs = 10.7.0.2/24
   Endpoint   = 192.168.1.50:51820
   ```

4. Bring up the interface and enable it on boot:

   ```bash
   sudo wg-quick up wg0
   sudo systemctl enable wg-quick@wg0
   ```

Use `sudo wg` to verify that the tunnel is established and exchanging
handshakes.

## LED Control via JSON-RPC

The firmware exposes JSON-RPC tools that can be invoked using the `tools/call`
method. Use `tools/list` to discover available tools: `set_location`,
`set_switch_id`, and `set_switch`. These allow you to configure the target
switch and toggle the onboard LED.

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

Call `set_switch` with `"state": "on"` or `"off"`. The LED changes only when
the request's `location` or `switch_id` matches the previously set values or
when both fields are omitted.

## How it works

Use the agent mode of GitHub Copilot Chat in Visual Studio Code.

https://github.com/user-attachments/assets/7c040786-b527-4f8a-829e-545591232b0f

## Installing the pico-sdk

The following steps summarize the pico-sdk setup:

1. Create a working directory.

   ```bash
   mkdir -p ~/.pico-sdk/sdk
   ```

2. Download release 2.2.0 from the official Raspberry Pi repository.

   ```bash
   cd ~/.pico-sdk/sdk
   git clone -b 2.2.0 https://github.com/raspberrypi/pico-sdk.git 2.2.0
   cd 2.2.0
   git submodule update --init
   ```

3. Set the `PICO_SDK_PATH` environment variable.

   ```bash
   export PICO_SDK_PATH=$HOME/.pico-sdk/sdk/2.2.0
   ```

After verifying that the repository was cloned and its submodules were checked
out, the pico-sdk will be available under `~/.pico-sdk/sdk/2.2.0`.

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
