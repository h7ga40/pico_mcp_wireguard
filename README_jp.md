# W55RP20-EVB-Pico で作る Wireguard と MCP サーバー を使った*リモートキーボード*

W55RP20-EVB-Pico は Wiznet 社の SoC、W55RP20 を搭載した評価ボードです。W55RP20 は、Raspberry Pi Pico に搭載されるチップ RP2040 と Ethernet コントローラ、ハードウェア TCP/IP スタックが一体になったSoCで、Pico SDK を使用した開発ができ、SDK を使用して USB キーボードを実装しています。

<https://docs.wiznet.io/Product/Chip/MCU/W55RP20/w55rp20-evb-pico>

Wireguard は VPN プロトコル・ソフトウェアで、シンプル・高速・安全を特徴とする最新のVPNです。リモートキーボードのネットワーク側の通信に使用しています。

<https://github.com/Mr-Pine/pi-pico-wireguard-lwip>

MCP サーバーとは、AI（大規模言語モデル）が外部のシステムやデータと連携するための標準プロトコル（Model Context Protocol）を実装したサーバーのことです。リモートキーボードからのキー入力を受け取るのに使用しています。
MCP サーバーを Github Copilot などに登録すれば、チェットからの操作もできるハズです。

<https://github.com/h7ga40/pico_mcp>

Web ブラウザからリモートキーボードの URL にアクセスして、Web ページのソフトウェアキーボードを操作することで、USB キーボードからキー入力することができます。電源キーを実装したので、PC の電源も入れられるハズです。（手元の PC では失敗…）

![概念図](Overview.drawio.svg)

## ネットワーク設定

Pico側のネットワーク設定として、`net_config.yaml`というファイルを用意しし、下記のように記述します。ビルド時に`argument_definitions.h`が生成され、パラメータが設定されます。また、PC 用の設定ファイル`wg0.conf`が生成されるので、このファイルを WireGuard に読み込ませてトンネルを作成します。

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
          keepalive: 0
      mtu: 1420
      listen-port: 51820
```

W55RP20-EVB-Pico は Ethernet のみなので、`ethernets`の設定を使います。`wifis`は Pico W 向けに用意しました。
Wireguard の設定は `tunnels` を使用します。

ビルド時に鍵のデータを収めたファイル`pc.key`と`pc.pub`、`pico.key`、`pico.pub`が生成されます。クリーンでも削除しないので新しい鍵が欲しい場合は、この４つを削除してください。

## ビルド

Visual Studio Code の Raspberry Pi Pico 拡張機能を使ってビルドします。

適当なフォルダをコマンドプロンプトやシェルで開き、コードをダウンロードします。

```bash
git clone https://github.com/h7ga40/pico_mcp_wireguard.git .
```

このフォルダを、Visual Studio Code で開けば、Raspberry Pi Pico 拡張機能が、ツールチェインのインストールなどを行ってくれるます。SDKのダウンロードに時間がかかるので、終わるまで待ちます。

ネットワーク設定を処理するために Python を利用しますのでインストールしてください。また、yaml ファイルを処理するため、`pyyaml`モジュールが必要なので、下記のコマンドでインストールしてください。

```bash
python -m pip install pyyaml
```

Raspberry Pi Pico 拡張機能の「Compile Project」を実行すれば、ビルドできます。

## Windows PC への WireGuard 設定

次のサイトから Windows 番 WireGuard をダウンロードして、インストールします。
<https://www.wireguard.com/install/>

インストールできたら WireGuard を起動して、「ファイルからトンネルをインポート」を選択し、ビルド時に生成された`wg0.conf`ファイルを指定します。

「有効化」ボタンでトンネルが作成されます。

## Ubuntu PC への WireGuard 設定

WireGuard をインストールします。

```bash
sudo apt update
sudo apt install wireguard wireguard-tools
```

ビルド時に生成された`wg0.conf`を、`/etc/wireguard/wg0.conf`にコピーします。

下記のコマンドで、有効化します。

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

## ATX 電源スイッチ / 電源 LED

`set_switch` は ATX の PWR_SW に相当するワンショットパルスを出力します。
GPIO 番号 / アクティブレベル / パルス幅は `argument_definitions.h` の
`ATX_PWR_GPIO`、`ATX_PWR_ACTIVE_LEVEL`、`ATX_PWR_PULSE_MS` で変更できます。

`get_switch_state()` はマザーボードの電源 LED ピン入力を読み取り、
`on`/`off` を返します。入力 GPIO とレベル・プル設定は
`PWR_LED_GPIO`、`PWR_LED_ACTIVE_LEVEL`、`PWR_LED_PULL`
(0 = なし, 1 = Pull-Down, 2 = Pull-Up) を使って設定してください。

## Wake on LAN (WoL)

WoL magic packet and ARP probe are available over Ethernet. Use the UI via
WireGuard (e.g. `http://10.7.0.2:3001/wol`).

- Allowlist: `content/wol_allowlist.json` served by `GET /wol_allowlist.json`.
- UI: `GET /wol` with POST endpoints:
  - `POST /wol/send` `{ "mac": "...", "port": 7|9, "broadcast_ip": "..." }`
  - `POST /wol/probe` `{ "ip": "...", "timeout_ms": 1000 }`
  - `POST /wol/send_and_probe` `{ "mac": "...", "ip": "...", "port": 7|9 }`
- MCP tools: `wol_send`, `arp_probe`, `wol_send_and_probe`
- Rate limit: `WOL_RATE_LIMIT_MS` (default 30000 ms)
- ARP timeout: `WOL_ARP_DEFAULT_TIMEOUT_MS` (default 1000 ms)
