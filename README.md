# W55RP20-EVB-Pico WireGuard and MCP Server *Remote Keyboard*

![Overview](Overview.png)

W55RP20-EVB-Pico is an evaluation board based on Wiznet's SoC, the W55RP20. The W55RP20 integrates the RP2040 (used in the Raspberry Pi Pico), an Ethernet controller, and a hardware TCP/IP stack in a single SoC. It can be developed with the Pico SDK, and this project uses the SDK to implement a USB keyboard.

<https://docs.wiznet.io/Product/Chip/MCU/W55RP20/w55rp20-evb-pico>

WireGuard is a VPN protocol/software known for being simple, fast, and secure. It is used for the network side of the remote keyboard communication.

<https://github.com/Mr-Pine/pi-pico-wireguard-lwip>

An MCP server is a server that implements the Model Context Protocol, a standard that lets AI (large language models) integrate with external systems and data. This project uses it to receive key input from the remote keyboard. If you register the MCP server in GitHub Copilot (etc.), you should also be able to control it from chat.

<https://github.com/h7ga40/pico_mcp>

By accessing the remote keyboard URL from a web browser and using the web-based software keyboard, you can send key input through the USB keyboard interface. A power key is also implemented, so it should be possible to power on the PC (though it did not work on my test PC).

## Network configuration

For Pico-side networking, prepare a file named `net_config.yaml` and write it as shown below. At build time, `argument_definitions.h` is generated and the parameters are set. A PC configuration file `wg0.conf` is also generated; load it into WireGuard to create the tunnel.

```yaml
network:
  ethernets:
    e0:
      dhcp4: false
      addresses: [ 192.168.1.50/24 ]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [ 192.168.1.1 ]
  wifis:
    wf:
      dhcp4: true
      access-points:
        WIFI_SSID:
          password: WIFI_PASSWORD
  tunnels:
    wg:
      mode: wireguard
      addresses: [ 10.7.0.2/24 ]
      routes:
        - to: 0.0.0.0/0
          via: 10.7.0.1
      peers:
        - allowed-ips: [ 10.7.0.1/24 ]
          endpoint: 0.0.0.0:0
          keepalive: 1
      mtu: 1420
      listen-port: 51820
```

W55RP20-EVB-Pico only supports Ethernet, so use the `ethernets` settings. `wifis` is provided for Pico W.
Use `tunnels` for WireGuard settings.

At build time, files containing key material are generated: `pc.key`, `pc.pub`, `pico.key`, and `pico.pub`. They are not deleted even on a clean, so if you want new keys, delete those four files.

## Wake on LAN (WoL) allowlist

For security, WoL limits the destinations. Prepare a list in `content/wol_allowlist.json` as shown below.

```json
[
  { "name": "MyPC", "mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.11.10" },
  { "name": "NAS", "mac": "11:22:33:44:55:66", "ip": "192.168.11.20" }
]
```

## Build

Build using the Raspberry Pi Pico extension for Visual Studio Code.

Open a folder in a command prompt or shell and download the code.

```bash
git clone https://github.com/h7ga40/pico_mcp_wireguard.git .
```

Open this folder in Visual Studio Code. The Raspberry Pi Pico extension will install the toolchain and related components. The SDK download can take some time, so wait until it completes.

Python is used to process the network configuration, so please install it. You also need the `pyyaml` module to handle YAML files; install it with:

```bash
python -m pip install pyyaml
```

Building requires `net_config.yaml` and `content/wol_allowlist.json`. Create them for your network.

Run "Compile Project" in the Raspberry Pi Pico extension to build.

## WireGuard configuration for local networks

![Local network](LocalNetwork.drawio.svg)

After building, a `wg0.conf` file like the following is generated.

```ini
[Interface]
PrivateKey = <pc.key>
Address = 10.7.0.1/32
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = <pico.pub>
AllowedIPs = 10.7.0.2/32
Endpoint = 192.168.1.50:51820
PersistentKeepalive = 25
```

## Network configuration for use over the Internet

![Over the Internet](OverInternet.drawio.svg)

Set the `Endpoint` under `Peer` in `wg0.conf` to the public IP address of the network where the Pico is installed.

```ini
[Interface]
PrivateKey = <pc.key>
Address = 10.7.0.1/32
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = <pico.pub>
AllowedIPs = 10.7.0.2/32
Endpoint = <public IP address>:51820
PersistentKeepalive = 25
```

Configure the router on the Pico side to forward WireGuard's UDP port (51820) to the Pico's IP address.

Configure the PC firewall so the WireGuard client can receive UDP packets.

## WireGuard setup on Windows PC

Download and install WireGuard for Windows from:
<https://www.wireguard.com/install/>

After installation, start WireGuard, choose "Import tunnel(s) from file," and select the `wg0.conf` file generated at build time.

Click "Activate" to create the tunnel.

## WireGuard setup on Ubuntu PC

Install WireGuard.

```bash
sudo apt update
sudo apt install wireguard wireguard-tools
```

Copy the generated `wg0.conf` to `/etc/wireguard/wg0.conf`.

Enable it with:

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

## ATX power switch / power LED

`set_switch` outputs a one-shot pulse corresponding to the ATX PWR_SW signal.
The GPIO number, active level, and pulse width can be changed in `argument_definitions.h`:
`ATX_PWR_GPIO`, `ATX_PWR_ACTIVE_LEVEL`, `ATX_PWR_PULSE_MS`.

`get_switch_state()` reads the motherboard power LED pin and returns `on`/`off`.
Configure the input GPIO, active level, and pull setting with:
`PWR_LED_GPIO`, `PWR_LED_ACTIVE_LEVEL`, `PWR_LED_PULL`
(0 = none, 1 = pull-down, 2 = pull-up).

## Wake on LAN (WoL)

WoL magic packets and ARP probes are available over Ethernet. Use the UI over WireGuard (for example: `http://10.7.0.2:3001/wol`).

- Allowlist: `content/wol_allowlist.json` served by `GET /wol_allowlist.json`.
- UI: `GET /wol` and POST endpoints:
  - `POST /wol/send` `{ "mac": "...", "port": 7|9, "broadcast_ip": "..." }`
  - `POST /wol/probe` `{ "ip": "...", "timeout_ms": 1000 }`
  - `POST /wol/send_and_probe` `{ "mac": "...", "ip": "...", "port": 7|9 }`
- MCP tools: `wol_send`, `arp_probe`, `wol_send_and_probe`
- Rate limit: `WOL_RATE_LIMIT_MS` (default 30000 ms)
- ARP timeout: `WOL_ARP_DEFAULT_TIMEOUT_MS` (default 1000 ms)
