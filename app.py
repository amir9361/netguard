#!/usr/bin/env python3
"""
NetGuard – Enhanced Device Detection
- OUI database (full IEEE lookup)
- mDNS/Bonjour hostname resolution
- nmap OS + port fingerprinting
- HTTP banner grabbing
"""

import os, json, time, threading, logging, socket, subprocess, requests
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import ARP, Ether, srp, sendp, conf
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("netguard")

app = Flask(__name__)
CORS(app)

DATA_FILE = Path("/data/devices.json")
DATA_FILE.parent.mkdir(parents=True, exist_ok=True)

devices: dict = {}
blocked: set  = set()
spoof_threads: dict = {}
mdns_names: dict = {}   # ip → hostname from mDNS

GATEWAY_IP    = os.environ.get("GATEWAY_IP",    "192.168.1.1")
SUBNET        = os.environ.get("SUBNET",        "192.168.1.0/24")
IFACE         = os.environ.get("IFACE",         "wlan0")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "30"))

conf.verb = 0

# ── OUI database (full IEEE CSV) ─────────────────────────────────
OUI_DB: dict = {}

def load_oui_db():
    global OUI_DB
    oui_file = Path("/data/oui.csv")
    if not oui_file.exists():
        log.info("Downloading OUI database…")
        try:
            r = requests.get(
                "https://standards-oui.ieee.org/oui/oui.csv",
                timeout=30, stream=True
            )
            oui_file.write_bytes(r.content)
            log.info("OUI database downloaded")
        except Exception as e:
            log.warning(f"Could not download OUI DB: {e}")
            return
    try:
        count = 0
        for line in oui_file.read_text(errors="ignore").splitlines()[1:]:
            parts = line.split(",")
            if len(parts) >= 3:
                prefix = parts[1].strip().upper()   # e.g. 00-50-56
                vendor = parts[2].strip().strip('"')
                OUI_DB[prefix] = vendor
                count += 1
        log.info(f"Loaded {count} OUI entries")
    except Exception as e:
        log.warning(f"OUI load error: {e}")

def get_vendor(mac: str) -> str:
    prefix = mac[:8].upper().replace(":", "-")
    if OUI_DB:
        return OUI_DB.get(prefix, "Unknown")
    # fallback hardcoded map
    fallback = {
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "AC:BC:32": "Apple",        "3C:22:FB": "Apple",
        "A4:C3:F0": "Apple",        "F4:F5:D8": "Google",
        "14:91:82": "TP-Link",      "50:C7:BF": "TP-Link",
        "FC:FB:FB": "Cisco",        "00:50:56": "VMware",
    }
    return fallback.get(mac[:8].upper(), "Unknown")


# ── mDNS listener ────────────────────────────────────────────────
class MDNSListener(ServiceListener):
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            try:
                ip = socket.inet_ntoa(info.addresses[0])
                hostname = info.server.rstrip(".")
                mdns_names[ip] = hostname
                log.info(f"mDNS: {ip} → {hostname}")
                if ip in [d["ip"] for d in devices.values()]:
                    for mac, dev in devices.items():
                        if dev["ip"] == ip and not dev.get("name"):
                            dev["mdns_name"] = hostname
                            save()
            except Exception:
                pass
    update_service = add_service
    remove_service = lambda self, *a: None

def start_mdns():
    try:
        zc = Zeroconf()
        types = [
            "_http._tcp.local.", "_https._tcp.local.",
            "_workstation._tcp.local.", "_device-info._tcp.local.",
            "_apple-mobdev2._tcp.local.", "_smb._tcp.local.",
        ]
        for t in types:
            ServiceBrowser(zc, t, MDNSListener())
        log.info("mDNS listener started")
    except Exception as e:
        log.warning(f"mDNS failed: {e}")


# ── hostname via reverse DNS ──────────────────────────────────────
def get_hostname(ip: str) -> str:
    # check mDNS cache first
    if ip in mdns_names:
        return mdns_names[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass
    return ""


# ── HTTP banner grab ──────────────────────────────────────────────
def grab_http_banner(ip: str) -> str:
    for scheme, port in [("http", 80), ("https", 443), ("http", 8080), ("http", 8443)]:
        try:
            r = requests.get(
                f"{scheme}://{ip}:{port}",
                timeout=2, verify=False,
                allow_redirects=True
            )
            server = r.headers.get("Server", "")
            title = ""
            if "<title>" in r.text.lower():
                start = r.text.lower().find("<title>") + 7
                end   = r.text.lower().find("</title>", start)
                title = r.text[start:end].strip()[:60]
            if title:
                return title
            if server:
                return server
        except Exception:
            pass
    return ""


# ── nmap fingerprint ─────────────────────────────────────────────
def nmap_scan(ip: str) -> dict:
    result = {"os": "", "ports": [], "device_type": ""}
    try:
        out = subprocess.check_output(
            ["nmap", "-O", "--osscan-guess", "-sV",
             "--version-intensity", "3",
             "-T4", "--host-timeout", "15s",
             "-p", "22,23,80,443,445,8080,8443,554,5000,9100",
             ip],
            timeout=20, stderr=subprocess.DEVNULL, text=True
        )
        # extract OS
        for line in out.splitlines():
            if "OS details:" in line:
                result["os"] = line.split("OS details:")[1].strip()
                break
            elif "Running:" in line and not result["os"]:
                result["os"] = line.split("Running:")[1].strip()

        # extract open ports
        open_ports = []
        for line in out.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split("/")[0]
                    svc  = parts[2] if len(parts) > 2 else ""
                    open_ports.append(f"{port}/{svc}")
        result["ports"] = open_ports[:8]

        # guess device type from OS string
        os_lower = result["os"].lower()
        if any(k in os_lower for k in ["android", "ios", "iphone", "ipad"]):
            result["device_type"] = "📱 Mobile"
        elif any(k in os_lower for k in ["windows"]):
            result["device_type"] = "💻 Windows PC"
        elif any(k in os_lower for k in ["linux", "ubuntu", "debian"]):
            result["device_type"] = "🐧 Linux"
        elif any(k in os_lower for k in ["mac os", "darwin", "apple"]):
            result["device_type"] = "🍎 Mac"
        elif any(k in os_lower for k in ["router", "openwrt", "mikrotik"]):
            result["device_type"] = "📡 Router"

    except subprocess.TimeoutExpired:
        log.debug(f"nmap timeout for {ip}")
    except Exception as e:
        log.debug(f"nmap error for {ip}: {e}")
    return result


# ── deep scan (runs in background per device) ────────────────────
def deep_scan_device(mac: str, ip: str):
    """Run nmap + HTTP banner in background for a single device."""
    log.info(f"Deep scan: {ip}")
    updates = {}

    # hostname
    hn = get_hostname(ip)
    if hn:
        updates["hostname"] = hn
        if not devices.get(mac, {}).get("name"):
            updates["mdns_name"] = hn

    # HTTP banner
    banner = grab_http_banner(ip)
    if banner:
        updates["http_banner"] = banner
        log.info(f"HTTP banner {ip}: {banner}")

    # nmap
    nm = nmap_scan(ip)
    if nm["os"]:
        updates["os"] = nm["os"]
        log.info(f"nmap OS {ip}: {nm['os']}")
    if nm["ports"]:
        updates["open_ports"] = nm["ports"]
    if nm["device_type"]:
        updates["device_type"] = nm["device_type"]

    if updates and mac in devices:
        devices[mac].update(updates)
        save()


# ── persistence ──────────────────────────────────────────────────
def load():
    global devices, blocked
    if DATA_FILE.exists():
        try:
            data = json.loads(DATA_FILE.read_text())
            devices = data.get("devices", {})
            blocked = set(data.get("blocked", []))
            log.info(f"Loaded {len(devices)} devices")
        except Exception as e:
            log.warning(f"Load error: {e}")

def save():
    DATA_FILE.write_text(json.dumps({"devices": devices, "blocked": list(blocked)}, indent=2))


# ── ARP scan ─────────────────────────────────────────────────────
def scan_network():
    log.info(f"Scanning {SUBNET} on {IFACE} …")
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=SUBNET),
            timeout=3, iface=IFACE, inter=0.1
        )
        return {rcv[Ether].src.lower(): rcv[ARP].psrc for _, rcv in ans}
    except Exception as e:
        log.error(f"Scan failed: {e}")
        return {}

def update_devices(found: dict):
    now = datetime.utcnow().isoformat()
    new_macs = []
    for mac, ip in found.items():
        if mac not in devices:
            devices[mac] = {
                "mac": mac, "ip": ip,
                "name": "", "vendor": get_vendor(mac),
                "trusted": False, "blocked": False,
                "first_seen": now, "last_seen": now, "online": True,
            }
            log.info(f"New: {mac} @ {ip}")
            new_macs.append(mac)
        else:
            devices[mac].update({"ip": ip, "last_seen": now, "online": True})
            if devices[mac].get("vendor") in ("Unknown", ""):
                devices[mac]["vendor"] = get_vendor(mac)
    for mac in devices:
        if mac not in found:
            devices[mac]["online"] = False
    save()
    # deep scan new devices in background
    for mac in new_macs:
        ip = devices[mac]["ip"]
        threading.Thread(target=deep_scan_device, args=(mac, ip), daemon=True).start()


# ── ARP block ────────────────────────────────────────────────────
def get_mac_addr(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=IFACE)
    for _, r in ans: return r[Ether].src
    return None

def spoof_loop(tip, tmac, gip, gmac):
    while tmac in blocked:
        sendp(Ether(dst=tmac)/ARP(op=2,pdst=tip,hwdst=tmac,psrc=gip), iface=IFACE, verbose=False)
        sendp(Ether(dst=gmac)/ARP(op=2,pdst=gip,hwdst=gmac,psrc=tip), iface=IFACE, verbose=False)
        time.sleep(2)
    sendp(Ether(dst=tmac)/ARP(op=2,pdst=tip,hwdst=tmac,psrc=gip,hwsrc=gmac), count=5, iface=IFACE, verbose=False)
    sendp(Ether(dst=gmac)/ARP(op=2,pdst=gip,hwdst=gmac,psrc=tip,hwsrc=tmac), count=5, iface=IFACE, verbose=False)

def start_block(mac):
    dev = devices.get(mac)
    if not dev: return False
    gw_mac = get_mac_addr(GATEWAY_IP)
    if not gw_mac: return False
    blocked.add(mac); devices[mac]["blocked"] = True
    t = threading.Thread(target=spoof_loop, args=(dev["ip"], mac, GATEWAY_IP, gw_mac), daemon=True)
    spoof_threads[mac] = t; t.start(); save(); return True

def stop_block(mac):
    blocked.discard(mac)
    if mac in devices: devices[mac]["blocked"] = False
    save()


# ── REST API ─────────────────────────────────────────────────────
@app.route("/api/devices")
def api_devices(): return jsonify(list(devices.values()))

@app.route("/api/devices/<mac>/name", methods=["POST"])
def api_rename(mac):
    mac = mac.lower()
    if mac in devices:
        devices[mac]["name"] = request.json.get("name", ""); save()
        return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404

@app.route("/api/devices/<mac>/trust", methods=["POST"])
def api_trust(mac):
    mac = mac.lower()
    if mac in devices:
        devices[mac]["trusted"] = bool(request.json.get("trusted", True))
        if devices[mac]["trusted"] and mac in blocked: stop_block(mac)
        save(); return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404

@app.route("/api/devices/<mac>/block", methods=["POST"])
def api_block(mac):
    mac = mac.lower()
    if mac not in devices: return jsonify({"error": "not found"}), 404
    if request.json.get("block", True):
        return jsonify({"ok": start_block(mac), "blocked": True})
    stop_block(mac); return jsonify({"ok": True, "blocked": False})

@app.route("/api/devices/<mac>/deepscan", methods=["POST"])
def api_deepscan(mac):
    mac = mac.lower()
    if mac not in devices: return jsonify({"error": "not found"}), 404
    ip = devices[mac]["ip"]
    threading.Thread(target=deep_scan_device, args=(mac, ip), daemon=True).start()
    return jsonify({"ok": True, "message": f"Deep scan started for {ip}"})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    found = scan_network(); update_devices(found)
    return jsonify({"scanned": len(found)})

@app.route("/api/status")
def api_status():
    return jsonify({
        "gateway": GATEWAY_IP, "subnet": SUBNET, "iface": IFACE,
        "total": len(devices),
        "online": sum(1 for d in devices.values() if d.get("online")),
        "blocked": len(blocked),
        "trusted": sum(1 for d in devices.values() if d.get("trusted")),
        "oui_loaded": len(OUI_DB) > 0,
    })


# ── background scanner ───────────────────────────────────────────
def scanner_loop():
    while True:
        update_devices(scan_network())
        time.sleep(SCAN_INTERVAL)


# ── startup ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    load()
    threading.Thread(target=load_oui_db, daemon=True).start()
    threading.Thread(target=start_mdns,  daemon=True).start()
    threading.Thread(target=scanner_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
