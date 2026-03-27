#!/usr/bin/env python3
"""
NetGuard – Home Network Manager
Scans the local network, tracks devices, and blocks unknown ones via ARP spoofing.
"""

import os
import json
import time
import threading
import subprocess
import logging
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import ARP, Ether, srp, sendp, conf

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("netguard")

app = Flask(__name__)
CORS(app)

DATA_FILE = Path("/data/devices.json")
DATA_FILE.parent.mkdir(parents=True, exist_ok=True)

# ── in-memory state ──────────────────────────────────────────────
devices: dict = {}          # mac → device dict
blocked: set  = set()       # macs currently being ARP-spoofed
spoof_threads: dict = {}    # mac → thread

GATEWAY_IP  = os.environ.get("GATEWAY_IP",  "192.168.1.1")
SUBNET      = os.environ.get("SUBNET",      "192.168.1.0/24")
IFACE       = os.environ.get("IFACE",       "eth0")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "30"))   # seconds

conf.verb = 0  # silence scapy


# ── persistence ──────────────────────────────────────────────────
def load():
    global devices, blocked
    if DATA_FILE.exists():
        try:
            data = json.loads(DATA_FILE.read_text())
            devices = data.get("devices", {})
            blocked = set(data.get("blocked", []))
            log.info(f"Loaded {len(devices)} devices, {len(blocked)} blocked")
        except Exception as e:
            log.warning(f"Could not load data: {e}")

def save():
    DATA_FILE.write_text(json.dumps({
        "devices": devices,
        "blocked": list(blocked)
    }, indent=2))


# ── vendor lookup (offline, using OUI prefix) ────────────────────
OUI_MAP = {
    "00:50:56": "VMware",    "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "00:1a:11": "Google",
    "f4:f5:d8": "Google",    "54:60:09": "Google",
    "ac:bc:32": "Apple",     "00:03:93": "Apple",
    "3c:22:fb": "Apple",     "a4:c3:f0": "Apple",
    "fc:fb:fb": "Cisco",     "00:1e:58": "D-Link",
    "14:91:82": "TP-Link",   "50:c7:bf": "TP-Link",
    "74:da:38": "Edimax",    "00:90:f5": "Edimax",
}

def get_vendor(mac: str) -> str:
    prefix = mac[:8].upper().replace("-", ":")
    return OUI_MAP.get(prefix, "Unknown")


# ── network scan ─────────────────────────────────────────────────
def scan_network():
    log.info(f"Scanning {SUBNET} on {IFACE} …")
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=SUBNET),
            timeout=3, iface=IFACE, inter=0.1
        )
        found = {}
        for _, rcv in ans:
            mac = rcv[Ether].src.lower()
            ip  = rcv[ARP].psrc
            found[mac] = ip
        return found
    except Exception as e:
        log.error(f"Scan failed: {e}")
        return {}

def update_devices(found: dict):
    now = datetime.utcnow().isoformat()
    changed = False
    for mac, ip in found.items():
        if mac not in devices:
            devices[mac] = {
                "mac": mac, "ip": ip,
                "name": "",
                "vendor": get_vendor(mac),
                "trusted": False,
                "first_seen": now,
                "last_seen": now,
                "online": True,
            }
            log.info(f"New device: {mac} @ {ip}")
            changed = True
        else:
            devices[mac]["ip"]        = ip
            devices[mac]["last_seen"] = now
            devices[mac]["online"]    = True
            if devices[mac].get("vendor") == "Unknown":
                devices[mac]["vendor"] = get_vendor(mac)

    # mark offline
    for mac in list(devices):
        if mac not in found and devices[mac].get("online"):
            devices[mac]["online"] = False
            changed = True

    if changed:
        save()


# ── ARP spoofing (block) ─────────────────────────────────────────
def get_mac(ip: str) -> str | None:
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=IFACE)
    for _, r in ans:
        return r[Ether].src
    return None

def spoof_loop(target_ip: str, target_mac: str, gateway_ip: str, gateway_mac: str):
    """Continuously send spoofed ARP replies to isolate target."""
    log.info(f"Blocking {target_ip} ({target_mac})")
    while target_mac in blocked:
        # tell target: gateway is us
        sendp(Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
              psrc=gateway_ip), iface=IFACE, verbose=False)
        # tell gateway: target is us
        sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
              psrc=target_ip), iface=IFACE, verbose=False)
        time.sleep(2)
    # restore ARP tables
    sendp(Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
          psrc=gateway_ip, hwsrc=gateway_mac), count=5, iface=IFACE, verbose=False)
    sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
          psrc=target_ip, hwsrc=target_mac), count=5, iface=IFACE, verbose=False)
    log.info(f"Unblocked {target_ip} ({target_mac}), ARP restored")

def start_block(mac: str):
    dev = devices.get(mac)
    if not dev:
        return False
    gw_mac = get_mac(GATEWAY_IP)
    if not gw_mac:
        log.error("Cannot resolve gateway MAC")
        return False
    blocked.add(mac)
    t = threading.Thread(target=spoof_loop,
                         args=(dev["ip"], mac, GATEWAY_IP, gw_mac),
                         daemon=True)
    spoof_threads[mac] = t
    t.start()
    save()
    return True

def stop_block(mac: str):
    blocked.discard(mac)
    save()
    # thread will exit on next iteration


# ── background scanner ───────────────────────────────────────────
def scanner_loop():
    while True:
        found = scan_network()
        update_devices(found)
        time.sleep(SCAN_INTERVAL)


# ── REST API ─────────────────────────────────────────────────────
@app.route("/api/devices")
def api_devices():
    return jsonify(list(devices.values()))

@app.route("/api/devices/<mac>/name", methods=["POST"])
def api_rename(mac):
    mac = mac.lower()
    body = request.json or {}
    if mac in devices:
        devices[mac]["name"] = body.get("name", "")
        save()
        return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404

@app.route("/api/devices/<mac>/trust", methods=["POST"])
def api_trust(mac):
    mac = mac.lower()
    body = request.json or {}
    if mac in devices:
        devices[mac]["trusted"] = bool(body.get("trusted", True))
        # auto-unblock if trusting
        if devices[mac]["trusted"] and mac in blocked:
            stop_block(mac)
        save()
        return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404

@app.route("/api/devices/<mac>/block", methods=["POST"])
def api_block(mac):
    mac = mac.lower()
    body = request.json or {}
    action = body.get("block", True)
    if mac not in devices:
        return jsonify({"error": "not found"}), 404
    if action:
        ok = start_block(mac)
        return jsonify({"ok": ok, "blocked": True})
    else:
        stop_block(mac)
        return jsonify({"ok": True, "blocked": False})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    found = scan_network()
    update_devices(found)
    return jsonify({"scanned": len(found)})

@app.route("/api/status")
def api_status():
    return jsonify({
        "gateway": GATEWAY_IP,
        "subnet": SUBNET,
        "iface": IFACE,
        "total": len(devices),
        "online": sum(1 for d in devices.values() if d.get("online")),
        "blocked": len(blocked),
        "trusted": sum(1 for d in devices.values() if d.get("trusted")),
    })


# ── startup ──────────────────────────────────────────────────────
if __name__ == "__main__":
    load()
    threading.Thread(target=scanner_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
