# MCP for Raspberry Pi Pico W

## 全体構成

```less
[ Linux / Windows PC ]
   WireGuard Client
   トンネルIP: 10.7.0.1
        |
        |  (WireGuard over UDP, LAN)
        |
[ Raspberry Pi Pico ]
   wireguard-lwip
   トンネルIP: 10.7.0.2
   listen_port: 51820
```

## WireGuardの設定(Windows)

Windowsの場合は下記のURLからWireGuardをインストールします。

<https://www.wireguard.com/install/>

### Pico側のキーの作成

```PowerShell
wg.exe genkey | Tee-Object pico.key | wg.exe pubkey > pico.pub
```

### Windows側の設定

1. WireGuard を起動

2. 「トンネルを追加」→「空のトンネルを追加」

3. 自動的に鍵が生成されます

公開鍵を<pc.pub>とし、PrivateKeyを<pc.key>とします。

設定を下記のように書き換えます。

```ini
[Interface]
PrivateKey = <pc.key>
Address    = 10.7.0.1/32
[Peer]
PublicKey  = <pico.pub>
AllowedIPs = 10.7.0.2/32
Endpoint   = 192.168.1.50:51820
```

### Picoのコードの変更

`argument_definitions.h`を編集して、マクロに値を入れます。

|マクロ|値|備考|
|-|-|-|
|WG_PRIVATE_KEY|<pico.key>|Pico側の秘密鍵|
|WG_ADDRESS|10.7.0.2||
|WG_SUBNET_MASK_IP|255.255.255.255||
|WG_GATEWAY_IP|0.0.0.0||
|WG_PUBLIC_KEY|<pc.pub>|PC側の公開鍵|
|WG_ALLOWED_IP||未使用|
|WG_ALLOWED_IP_MASK_IP||未使用|
|WG_ENDPOINT_IP|192.168.1.100|PC側のIPアドレス|
|WG_ENDPOINT_PORT|51820|PC側のポート|

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

## How it works

Use the agent mode of Github copilot Chat in Visual Studio Code.

https://github.com/user-attachments/assets/7c040786-b527-4f8a-829e-545591232b0f

## Installing the pico-sdk

The following is an excerpt from a previous setup guide.

1. Create a working directory

   ```bash
   mkdir -p ~/.pico-sdk/sdk
   ```

2. Download the latest release (2.2.0) from the official Raspberry Pi repository

   ```bash
   cd ~/.pico-sdk/sdk
   git clone -b 2.2.0 https://github.com/raspberrypi/pico-sdk.git 2.2.0
   cd 2.2.0
   git submodule update --init
   ```

3. Set the `PICO_SDK_PATH` environment variable

   ```bash
   export PICO_SDK_PATH=$HOME/.pico-sdk/sdk/2.2.0
   ```

After verifying that the repository was cloned and its submodules were checked out,
the pico-sdk will be available under `~/.pico-sdk/sdk/2.2.0`.

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
