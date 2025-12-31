#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any


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
            Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "WireGuard" / "wg.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\\Program Files (x86)")) / "WireGuard" / "wg.exe",
        ]
        for c in candidates:
            if c.exists():
                return [str(c)]
        return ["wg.exe"]

    return ["wg"]


def ensure_wg_available(wg_cmd: List[str]) -> None:
    exe = wg_cmd[0]
    exe_path = Path(exe)
    resolved = shutil.which(exe)

    if exe_path.expanduser().exists() or resolved:
        return

    system = platform.system()
    if system == "Windows":
        install_hint = "Install WireGuard from https://www.wireguard.com/install/ and ensure wg.exe is available in PATH."
    elif system == "Linux":
        install_hint = (
            "Install WireGuard tools (e.g., `sudo apt install wireguard-tools`) or download from "
            "https://www.wireguard.com/install/."
        )
    else:
        install_hint = "See https://www.wireguard.com/install/ for WireGuard installation instructions for your platform."

    raise RuntimeError(
        "WireGuard command (wg) was not found; build cannot continue without it.\n"
        f"{install_hint}"
    )


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


def load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
    except ImportError as e:
        raise RuntimeError(
            "PyYAML is required to read net_config.yaml. "
            "Install it with `python -m pip install pyyaml`."
        ) from e

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("net_config.yaml must contain a mapping at the top level.")
    return data


def require_mapping(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a mapping.")
    return value


def require_list(value: Any, label: str) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    raise RuntimeError(f"{label} must be a list.")


def first_mapping_item(mapping: Dict[str, Any], label: str) -> Tuple[str, Any]:
    if not mapping:
        raise RuntimeError(f"{label} must not be empty.")
    for k, v in mapping.items():
        return str(k), v
    raise RuntimeError(f"{label} must not be empty.")


def parse_ipv4_cidr(value: str, label: str) -> Tuple[str, str]:
    try:
        iface = ipaddress.ip_interface(value)
    except ValueError as e:
        raise RuntimeError(f"{label} must be an IPv4 CIDR (e.g. 192.168.1.50/24).") from e
    if not isinstance(iface, ipaddress.IPv4Interface):
        raise RuntimeError(f"{label} must be an IPv4 CIDR.")
    return str(iface.ip), str(iface.network.netmask)


def parse_ipv4_address(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"{label} must be a string.")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as e:
        raise RuntimeError(f"{label} must be a valid IPv4 address.") from e
    if not isinstance(ip, ipaddress.IPv4Address):
        raise RuntimeError(f"{label} must be a valid IPv4 address.")
    return value


def parse_endpoint(value: Any, label: str) -> Tuple[str, int]:
    if not isinstance(value, str) or ":" not in value:
        raise RuntimeError(f"{label} must be in HOST:PORT format.")
    host, port_str = value.rsplit(":", 1)
    host = host.strip()
    if not host:
        raise RuntimeError(f"{label} must include a host.")
    parse_ipv4_address(host, f"{label} host")
    try:
        port = int(port_str)
    except ValueError as e:
        raise RuntimeError(f"{label} port must be an integer.") from e
    if not (0 <= port <= 65535):
        raise RuntimeError(f"{label} port must be between 0 and 65535.")
    return host, port


def parse_keepalive(value: Any, label: str) -> int:
    if isinstance(value, bool) or value is None:
        raise RuntimeError(f"{label} must be an integer.")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise RuntimeError(f"{label} must be an integer.")


def parse_bool(value: Any, label: str) -> bool:
    if isinstance(value, bool):
        return value
    raise RuntimeError(f"{label} must be true or false.")


def extract_net_config(
    net_config_path: Path,
    *,
    iface_type: str,
) -> Dict[str, Any]:
    data = load_yaml(net_config_path)
    network = require_mapping(data.get("network"), "network")

    iface_candidates = [k for k in network.keys() if k in ("ethernets", "wifis")]
    if not iface_candidates:
        raise RuntimeError("network must contain ethernets or wifis.")

    first_iface_type = iface_candidates[0]
    if iface_type != first_iface_type:
        if iface_type in iface_candidates and len(iface_candidates) > 1:
            raise RuntimeError(
                f"Only the first interface definition is valid; "
                f"use --iface-type {first_iface_type}."
            )
        raise RuntimeError(f"network.{iface_type} is missing or not the first definition.")

    iface_root = require_mapping(network.get(iface_type), f"network.{iface_type}")
    iface_name, iface_cfg_raw = first_mapping_item(iface_root, f"network.{iface_type}")
    if len(iface_name) != 2:
        raise RuntimeError(f"Interface name must be exactly 2 characters: {iface_name}")
    iface_cfg = require_mapping(iface_cfg_raw, f"network.{iface_type}.{iface_name}")

    dhcp4 = parse_bool(iface_cfg.get("dhcp4"), f"network.{iface_type}.{iface_name}.dhcp4")
    iface_addresses = require_list(
        iface_cfg.get("addresses"), f"network.{iface_type}.{iface_name}.addresses"
    )
    endpoint_ip, endpoint_mask = parse_ipv4_cidr(
        str(iface_addresses[0]),
        f"network.{iface_type}.{iface_name}.addresses[0]",
    )
    gateway_ip = parse_ipv4_address(
        iface_cfg.get("gateway4"),
        f"network.{iface_type}.{iface_name}.gateway4",
    )

    nameservers = require_mapping(
        iface_cfg.get("nameservers"), f"network.{iface_type}.{iface_name}.nameservers"
    )
    ns_addresses = require_list(
        nameservers.get("addresses"),
        f"network.{iface_type}.{iface_name}.nameservers.addresses",
    )
    dns_server_ip = parse_ipv4_address(
        ns_addresses[0],
        f"network.{iface_type}.{iface_name}.nameservers.addresses[0]",
    )

    wifi_ssid = ""
    wifi_password = ""
    if iface_type == "wifis":
        access_points = require_mapping(
            iface_cfg.get("access-points"), f"network.{iface_type}.{iface_name}.access-points"
        )
        wifi_ssid, ap_cfg_raw = first_mapping_item(
            access_points, f"network.{iface_type}.{iface_name}.access-points"
        )
        ap_cfg = require_mapping(
            ap_cfg_raw,
            f"network.{iface_type}.{iface_name}.access-points.{wifi_ssid}",
        )
        if "password" not in ap_cfg:
            raise RuntimeError(
                f"network.{iface_type}.{iface_name}.access-points.{wifi_ssid}.password is required."
            )
        wifi_password = str(ap_cfg["password"])

    tunnels = require_mapping(network.get("tunnels"), "network.tunnels")
    wg = require_mapping(tunnels.get("wg"), "network.tunnels.wg")

    wg_addresses = require_list(wg.get("addresses"), "network.tunnels.wg.addresses")
    wg_address, wg_mask = parse_ipv4_cidr(
        str(wg_addresses[0]), "network.tunnels.wg.addresses[0]"
    )

    wg_routes = require_list(wg.get("routes"), "network.tunnels.wg.routes")
    first_route = wg_routes[0]
    if not isinstance(first_route, dict):
        raise RuntimeError("network.tunnels.wg.routes[0] must be a mapping.")
    wg_gateway_ip = parse_ipv4_address(
        first_route.get("via"), "network.tunnels.wg.routes[0].via"
    )

    peers = require_list(wg.get("peers"), "network.tunnels.wg.peers")
    first_peer = peers[0]
    if not isinstance(first_peer, dict):
        raise RuntimeError("network.tunnels.wg.peers[0] must be a mapping.")

    keepalive = parse_keepalive(
        first_peer.get("keepalive"), "network.tunnels.wg.peers[0].keepalive"
    )
    allowed_ips = require_list(
        first_peer.get("allowed-ips"), "network.tunnels.wg.peers[0].allowed-ips"
    )
    allowed_ip, allowed_mask = parse_ipv4_cidr(
        str(allowed_ips[0]), "network.tunnels.wg.peers[0].allowed-ips[0]"
    )

    endpoint_host, endpoint_port = parse_endpoint(
        first_peer.get("endpoint"), "network.tunnels.wg.peers[0].endpoint"
    )

    listen_port = wg.get("listen-port")
    if listen_port is None:
        raise RuntimeError("network.tunnels.wg.listen-port is required.")
    if isinstance(listen_port, bool):
        raise RuntimeError("network.tunnels.wg.listen-port must be an integer.")
    try:
        listen_port_int = int(listen_port)
    except ValueError as e:
        raise RuntimeError("network.tunnels.wg.listen-port must be an integer.") from e
    if not (0 <= listen_port_int <= 65535):
        raise RuntimeError("network.tunnels.wg.listen-port must be between 0 and 65535.")

    return {
        "wifi_ssid": wifi_ssid,
        "wifi_password": wifi_password,
        "enable_dhcp": 1 if dhcp4 else 0,
        "dns_server_ip": dns_server_ip,
        "endpoint_ip": endpoint_ip,
        "endpoint_mask": endpoint_mask,
        "endpoint_gateway_ip": gateway_ip,
        "wg_address": wg_address,
        "wg_mask": wg_mask,
        "wg_gateway_ip": wg_gateway_ip,
        "wg_keepalive": keepalive,
        "wg_allowed_ip": allowed_ip,
        "wg_allowed_mask": allowed_mask,
        "wg_endpoint_ip": endpoint_host,
        "wg_endpoint_port": endpoint_port,
        "wg_listen_port": listen_port_int,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=".", help="Output directory for keys and wg0.conf")
    ap.add_argument(
        "--argument-definitions-h",
        required=True,
        help="Path to argument_definitions.h/.in to patch and copy to outdir",
    )
    ap.add_argument("--wg-tool", default=None, help="Explicit path to wg.exe / wg (optional)")
    ap.add_argument("--require-all", type=int, default=1, help="1: error if any macro is missing, 0: replace what exists")

    ap.add_argument("--net-config", default="net_config.yaml", help="Path to net_config.yaml")
    ap.add_argument("--iface-type", default="wifis", choices=["wifis", "ethernets"], help="Interface type to use (default: wifis)")
    ap.add_argument("--wg0-conf", default="wg0.conf", help="wg0.conf filename (written to outdir)")

    args = ap.parse_args()

    wg_cmd = find_wg_tool(args.wg_tool)
    ensure_wg_available(wg_cmd)

    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    argument_definitions_src = Path(args.argument_definitions_h).resolve()
    if not argument_definitions_src.exists():
        raise FileNotFoundError(
            f"--argument-definitions-h not found: {argument_definitions_src}"
        )

    argument_definitions_out = outdir / "argument_definitions.h"
    shutil.copyfile(argument_definitions_src, argument_definitions_out)

    pico_kp, _, _ = load_or_generate("pico", wg_cmd, outdir)
    pc_kp, _, _ = load_or_generate("pc", wg_cmd, outdir)

    net_config = extract_net_config(Path(args.net_config), iface_type=args.iface_type)

    # Replace the requested macros in argument_definitions.h
    replacements: Dict[str, Tuple[str, bool]] = {
        "WIFI_SSID": (net_config["wifi_ssid"], True),
        "WIFI_PASSWORD": (net_config["wifi_password"], True),
        "ENABLE_DHCP": (str(net_config["enable_dhcp"]), False),
        "DNS_SERVER_IP": (net_config["dns_server_ip"], True),
        "ENDPOINT_IP": (net_config["endpoint_ip"], True),
        "ENDPOINT_SUBNET_MASK_IP": (net_config["endpoint_mask"], True),
        "ENDPOINT_GATEWAY_IP": (net_config["endpoint_gateway_ip"], True),
        "WG_PRIVATE_KEY": (pico_kp.private_key_b64, True),
        "WG_PUBLIC_KEY": (pc_kp.public_key_b64, True),
        "WG_ADDRESS": (net_config["wg_address"], True),
        "WG_SUBNET_MASK_IP": (net_config["wg_mask"], True),
        "WG_GATEWAY_IP": (net_config["wg_gateway_ip"], True),
        "WG_KEEPALIVE": (str(net_config["wg_keepalive"]), False),
        "WG_ALLOWED_IP": (net_config["wg_allowed_ip"], True),
        "WG_ALLOWED_IP_MASK_IP": (net_config["wg_allowed_mask"], True),
        "WG_ENDPOINT_IP": (net_config["wg_endpoint_ip"], True),
        "WG_ENDPOINT_PORT": (str(net_config["wg_endpoint_port"]), False),
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
        pc_tunnel_ip=net_config["wg_allowed_ip"],
        pico_lan_ip=net_config["endpoint_ip"],
        pico_listen_port=net_config["wg_listen_port"],
        allowed_ips=f"{net_config['wg_address']}/32",
    )

    print("OK")
    print(f"  Patched: {argument_definitions_out}")
    print(f"  Wrote:   {wg0_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
