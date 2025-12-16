#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Dict, List


@dataclass
class KeyPair:
    private_key_b64: str
    public_key_b64: str


def run(cmd: List[str], *, input_text: Optional[str] = None) -> str:
    try:
        p = subprocess.run(
            cmd,
            input=input_text.encode("utf-8") if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stdout:\n{e.stdout.decode(errors='ignore')}\n"
            f"stderr:\n{e.stderr.decode(errors='ignore')}"
        )
    return p.stdout.decode("utf-8", errors="ignore")


def find_wg_tool(explicit_path: Optional[str]) -> List[str]:
    if explicit_path:
        p = Path(explicit_path)
        if not p.exists():
            raise FileNotFoundError(f"--wg-tool not found: {p}")
        return [str(p)]

    if os.name == "nt":
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WireGuard" / "wg.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "WireGuard" / "wg.exe",
        ]
        for c in candidates:
            if c.exists():
                return [str(c)]
        return ["wg.exe"]

    return ["wg"]


def read_text_one_line(path: Path) -> str:
    s = path.read_text(encoding="utf-8").strip()
    # remove all whitespace/newlines to prevent accidental line breaks
    return "".join(s.split())


def write_text_one_line(path: Path, value: str) -> None:
    path.write_text(value.strip() + "\n", encoding="utf-8")


def generate_keypair(wg_cmd: List[str]) -> KeyPair:
    priv = run(wg_cmd + ["genkey"]).strip()
    pub = run(wg_cmd + ["pubkey"], input_text=priv).strip()
    if not priv or not pub:
        raise RuntimeError("Failed to generate WireGuard keys (empty output).")
    return KeyPair(priv, pub)


def load_or_generate(prefix: str, wg_cmd: List[str], outdir: Path) -> Tuple[KeyPair, Path, Path]:
    key_path = outdir / f"{prefix}.key"
    pub_path = outdir / f"{prefix}.pub"

    if key_path.exists() and pub_path.exists():
        priv = read_text_one_line(key_path)
        pub = read_text_one_line(pub_path)
        return KeyPair(priv, pub), key_path, pub_path

    kp = generate_keypair(wg_cmd)
    write_text_one_line(key_path, kp.private_key_b64)
    write_text_one_line(pub_path, kp.public_key_b64)
    return kp, key_path, pub_path


def format_define(name: str, value: str, *, as_string: bool) -> str:
    if as_string:
        # keep it single-line, no embedded whitespace
        v = "".join(value.split())
        return f'#define {name} "{v}"\n'
    else:
        v = value.strip()
        return f"#define {name} {v}\n"


def patch_defines_with_continuations(
    header_path: Path,
    replacements: Dict[str, Tuple[str, bool]],
    *,
    require_all: bool = True,
) -> None:
    """
    Replace #define MACRO ... blocks including backslash-continued lines.
    Works even if macro is written as:
      #define WG_PRIVATE_KEY \
          "...."
    The entire block is replaced with a single-line define.

    replacements: { MACRO: (value, as_string) }
    """
    if not header_path.exists():
        raise FileNotFoundError(f"Header not found: {header_path}")

    lines = header_path.read_text(encoding="utf-8").splitlines(keepends=True)
    original = "".join(lines)

    found = set()
    out: List[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        # Identify "#define <NAME>" at line start (allow whitespace before #)
        if stripped.startswith("#define"):
            # tokenization: "#define" + name + rest
            parts = stripped.split(None, 2)  # ["#define","NAME","...optional..."]
            if len(parts) >= 2:
                name = parts[1]
                if name in replacements:
                    found.add(name)

                    # Consume continuation block: current line + subsequent lines while
                    # previous line ends with backslash (ignoring trailing whitespace/newline)
                    j = i
                    while True:
                        cur = lines[j]
                        if cur.rstrip().endswith("\\") and (j + 1) < len(lines):
                            j += 1
                            continue
                        break

                    value, as_string = replacements[name]
                    out.append(format_define(name, value, as_string=as_string))
                    i = j + 1
                    continue

        out.append(line)
        i += 1

    missing = [k for k in replacements.keys() if k not in found]
    if require_all and missing:
        raise RuntimeError(
            "Some required macros were not found in argument_definitions.h:\n"
            + "\n".join(f"  - {k}" for k in missing)
            + "\n\nTip: set --require-all 0 to allow partial replacement."
        )

    modified = "".join(out)
    if modified != original:
        bak = header_path.with_suffix(header_path.suffix + ".bak")
        if not bak.exists():
            bak.write_text(original, encoding="utf-8")
        header_path.write_text(modified, encoding="utf-8")


def write_wg0_conf(
    out_path: Path,
    pc: KeyPair,
    pico: KeyPair,
    *,
    pc_tunnel_ip: str,
    pico_lan_ip: str,
    pico_listen_port: int,
    allowed_ips: str,
) -> None:
    conf = (
        "[Interface]\n"
        f"PrivateKey = {pc.private_key_b64}\n"
        f"Address = {pc_tunnel_ip}/32\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {pico.public_key_b64}\n"
        f"AllowedIPs = {allowed_ips}\n"
        f"Endpoint = {pico_lan_ip}:{pico_listen_port}\n"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(conf, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=".", help="Directory for key files and wg0.conf")
    ap.add_argument(
        "--argument-definitions-h",
        required=True,
        help="Path to argument_definitions.h/.in to patch and emit to outdir",
    )
    ap.add_argument("--wg-tool", default=None, help="Explicit path to wg.exe / wg (optional)")
    ap.add_argument("--require-all", type=int, default=1, help="1: error if any macro missing, 0: replace what exists")

    # PC wg0.conf generation
    ap.add_argument("--pico-lan-ip", required=True, help="Pico LAN IP (Endpoint), e.g. 192.168.1.50")
    ap.add_argument("--pico-listen-port", type=int, default=51820, help="Pico WireGuard listen port")
    ap.add_argument("--pc-tunnel-ip", default="10.7.0.1", help="PC tunnel IP (wg0 Address)")
    ap.add_argument("--pico-tunnel-ip", default="10.7.0.2", help="Pico tunnel IP (for reference)")
    ap.add_argument("--allowed-ips", default="10.7.0.2/32", help="AllowedIPs on PC peer side")
    ap.add_argument("--wg0-conf", default="wg0.conf", help="Output wg0.conf filename (in outdir)")

    # Pico-side network parameters (for macros)
    ap.add_argument("--wg-address", default="10.7.0.2", help="Value for WG_ADDRESS")
    ap.add_argument("--wg-subnet-mask-ip", default="255.255.255.255", help="Value for WG_SUBNET_MASK_IP")
    ap.add_argument("--wg-gateway-ip", default="0.0.0.0", help="Value for WG_GATEWAY_IP")
    ap.add_argument("--wg-endpoint-ip", default="0.0.0.0", help="Value for WG_ENDPOINT_IP (if unused, keep 0.0.0.0)")
    ap.add_argument("--wg-endpoint-port", default="0", help="Value for WG_ENDPOINT_PORT (if unused, keep 0)")

    args = ap.parse_args()

    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    argument_definitions_src = Path(args.argument_definitions_h).resolve()
    if not argument_definitions_src.exists():
        raise FileNotFoundError(
            f"--argument-definitions-h not found: {argument_definitions_src}"
        )

    argument_definitions_out = outdir / "argument_definitions.h"
    shutil.copyfile(argument_definitions_src, argument_definitions_out)

    wg_cmd = find_wg_tool(args.wg_tool)

    pico_kp, _, _ = load_or_generate("pico", wg_cmd, outdir)
    pc_kp, _, _ = load_or_generate("pc", wg_cmd, outdir)

    # Replace the requested macros in argument_definitions.h
    # - WG_PRIVATE_KEY: Pico private key
    # - WG_PUBLIC_KEY : Pico public key
    # - WG_ADDRESS / WG_SUBNET_MASK_IP / WG_GATEWAY_IP: Pico tunnel addressing
    # - WG_ENDPOINT_IP / WG_ENDPOINT_PORT: settable (may be unused for "Pico server" mode)
    replacements: Dict[str, Tuple[str, bool]] = {
        "WG_PRIVATE_KEY": (pico_kp.private_key_b64, True),
        "WG_PUBLIC_KEY": (pico_kp.public_key_b64, True),
        "WG_ADDRESS": (args.wg_address, True),
        "WG_SUBNET_MASK_IP": (args.wg_subnet_mask_ip, True),
        "WG_GATEWAY_IP": (args.wg_gateway_ip, True),
        "WG_ENDPOINT_IP": (args.wg_endpoint_ip, True),
        "WG_ENDPOINT_PORT": (args.wg_endpoint_port, False),
    }

    patch_defines_with_continuations(
        argument_definitions_out,
        replacements,
        require_all=bool(args.require_all),
    )

    # Emit wg0.conf for Windows/Linux PC (client)
    wg0_path = outdir / args.wg0_conf
    write_wg0_conf(
        wg0_path,
        pc_kp,
        pico_kp,
        pc_tunnel_ip=args.pc_tunnel_ip,
        pico_lan_ip=args.pico_lan_ip,
        pico_listen_port=args.pico_listen_port,
        allowed_ips=args.allowed_ips,
    )

    print("OK")
    print(f"  Patched: {argument_definitions_out}")
    print(f"  Wrote:   {wg0_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
