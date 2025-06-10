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

## pico-sdkのインストール手順 (日本語)

以下は以前の手順の抜粋です。

1. 作業ディレクトリを作成
   ```bash
   mkdir -p ~/.pico-sdk/sdk
   ```
2. Raspberry Pi 公式リポジトリから最新リリース(2.1.1)を取得
   ```bash
   cd ~/.pico-sdk/sdk
   git clone -b 2.1.1 https://github.com/raspberrypi/pico-sdk.git 2.1.1
   cd 2.1.1
   git submodule update --init
   ```
3. `PICO_SDK_PATH` 環境変数を設定
   ```bash
   export PICO_SDK_PATH=$HOME/.pico-sdk/sdk/2.1.1
   ```

正常にクローンされ、サブモジュールも展開されたことを確認したら、
`~/.pico-sdk/sdk/2.1.1` に pico-sdk がインストールされたことになります。
