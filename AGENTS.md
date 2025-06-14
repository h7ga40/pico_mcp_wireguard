# Repository Instructions

## Environment Setup

1. Create a working directory for the Pico SDK:
   ```bash
   mkdir -p ~/.pico-sdk/sdk
   ```
2. Clone the Pico SDK (release 2.1.1) and initialize submodules:
   ```bash
   cd ~/.pico-sdk/sdk
   git clone -b 2.1.1 https://github.com/raspberrypi/pico-sdk.git 2.1.1
   cd 2.1.1
   git submodule update --init
   ```
3. Set the environment variable pointing to the SDK path:
   ```bash
   export PICO_SDK_PATH=$HOME/.pico-sdk/sdk/2.1.1
   ```

After completing these steps, the SDK will be available under `~/.pico-sdk/sdk/2.1.1`.

## Build Instructions

Run the following commands from the repository root to fetch the Pico SDK (if needed) and build the project:

```bash
mkdir build
cd build
cmake -E env PICO_SDK_FETCH_FROM_GIT=1 cmake ..
make -j$(nproc)
```

Successful builds generate artifacts such as `pico_mcp.uf2` inside the `build` directory.

## Formatting

The repository defines a `.editorconfig` file. When editing code, ensure your changes follow these rules. The `.editorconfig-checker.json` file excludes the `parson` and `llhttp` directories. Run the following command from the repository root before committing:

```bash
npx --yes editorconfig-checker
```

Only commit changes when this check succeeds.
