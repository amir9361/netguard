#!/usr/bin/env python3
"""
NetGuard – Comprehensive Device Detection
Techniques:
  1. OUI / MAC prefix database (IEEE)
  2. DHCP fingerprinting (Option 55 list → OS signature)
  3. NetBIOS name resolution (Windows hostname)
  4. SSDP / UPnP discovery (smart devices)
  5. mDNS / Bonjour (Apple + Linux)
  6. TCP SYN fingerprinting (window size + options)
  7. HTTP User-Agent sniffing (proxy listener)
  8. nmap OS + port detection
  9. TTL + randomized MAC heuristics
  10. HTTP banner grab
"""

import os, json, time, threading, logging, socket, re
import subprocess, requests
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import ARP, Ether, IP, TCP, DHCP, srp, sendp, sniff, conf
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import urllib3
urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("netguard")

app = Flask(__name__)
CORS(app)

DATA_FILE = Path("/data/devices.json")
DATA_FILE.parent.mkdir(parents=True, exist_ok=True)

devices: dict = {}
blocked: set  = set()
spoof_threads: dict = {}
mdns_names: dict = {}
dhcp_cache: dict = {}
ua_cache: dict   = {}

GATEWAY_IP    = os.environ.get("GATEWAY_IP",    "192.168.1.1")
SUBNET        = os.environ.get("SUBNET",        "192.168.1.0/24")
IFACE         = os.environ.get("IFACE",         "wlan0")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "30"))
conf.verb = 0


# ── 1. OUI DATABASE ──────────────────────────────────────────────
OUI_DB: dict = {}

def load_oui_db():
    global OUI_DB
    oui_file = Path("/data/oui.csv")
    if not oui_file.exists():
        log.info("Downloading OUI database…")
        try:
            r = requests.get("https://standards-oui.ieee.org/oui/oui.csv", timeout=30)
            oui_file.write_bytes(r.content)
        except Exception as e:
            log.warning(f"OUI download failed: {e}"); return
    try:
        for line in oui_file.read_text(errors="ignore").splitlines()[1:]:
            parts = line.split(",")
            if len(parts) >= 3:
                OUI_DB[parts[1].strip().upper()] = parts[2].strip().strip('"')
        log.info(f"OUI DB: {len(OUI_DB)} entries")
    except Exception as e:
        log.warning(f"OUI load error: {e}")

def get_vendor(mac: str) -> str:
    prefix = mac[:8].upper().replace(":", "-")
    if OUI_DB:
        return OUI_DB.get(prefix, "Unknown")
    fallback = {
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "AC:BC:32": "Apple", "3C:22:FB": "Apple", "A4:C3:F0": "Apple",
        "F4:F5:D8": "Google", "14:91:82": "TP-Link", "50:C7:BF": "TP-Link",
    }
    return fallback.get(mac[:8].upper(), "Unknown")


# ── 2. DHCP FINGERPRINTING ───────────────────────────────────────
DHCP_SIGNATURES = {
    "1,3,6,15,26,28,51,58,59,43":             ("Android",        "📱 Android"),
    "1,3,6,15,26,28,51,58,59":                ("Android (older)","📱 Android"),
    "1,121,3,6,15,119,252,95,44,46":          ("Windows 10/11",  "💻 Windows"),
    "1,15,3,6,44,46,47,31,33,121,249,252":    ("Windows 7/8",    "💻 Windows"),
    "1,121,3,6,15,119,252":                   ("macOS",          "🍎 Mac"),
    "1,3,6,15,119,252":                        ("macOS (older)",  "🍎 Mac"),
    "1,3,6,12,15,17,23,28,29,31,33,40,41,42": ("Linux",         "🐧 Linux"),
    "1,3,6,15,44,46,47,57,58,59,116":         ("iOS / iPadOS",  "📱 iOS"),
}

def dhcp_sniffer():
    def handle(pkt):
        try:
            if not (pkt.haslayer(DHCP) and pkt.haslayer(Ether)): return
            mac = pkt[Ether].src.lower()
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "param_req_list":
                    opt55 = ",".join(str(b) for b in opt[1])
                    if dhcp_cache.get(mac) == opt55: return
                    dhcp_cache[mac] = opt55
                    for sig, (os_name, dev_type) in DHCP_SIGNATURES.items():
                        if opt55 == sig or opt55.startswith(sig[:12]):
                            if mac in devices:
                                devices[mac].update({
                                    "dhcp_os": os_name, "device_type": dev_type,
                                    "detect_method": "DHCP fingerprint"
                                })
                                log.info(f"DHCP {mac}: {os_name}")
                                save()
                            break
        except Exception:
            pass
    log.info("DHCP sniffer started")
    sniff(filter="udp and (port 67 or port 68)", prn=handle, iface=IFACE, store=0)


# ── 3. NetBIOS ───────────────────────────────────────────────────
def netbios_query(ip: str) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        query = (
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00"
            b"\x21\x00\x01"
        )
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57:
            num_names = data[56]
            for i in range(num_names):
                offset = 57 + i * 18
                if offset + 16 > len(data): break
                name = data[offset:offset+15].decode("ascii", errors="ignore").strip()
                if data[offset+15] == 0x00 and name:
                    return name
    except Exception:
        pass
    return ""


# ── 4. SSDP / UPnP ───────────────────────────────────────────────
SSDP_PATTERNS = [
    (r"android",                              "📱 Android",    "Android"),
    (r"chromecast|googlecast|cast",           "📺 Chromecast", "Google Chromecast"),
    (r"playstation|ps[345]",                  "🎮 PlayStation","PlayStation"),
    (r"xbox",                                 "🎮 Xbox",       "Xbox"),
    (r"samsung.*tv|tizen",                    "📺 Samsung TV", "Samsung Smart TV"),
    (r"lg.*tv|webos",                         "📺 LG TV",      "LG Smart TV"),
    (r"roku",                                 "📺 Roku",       "Roku"),
    (r"apple.*tv",                            "📺 Apple TV",   "Apple TV"),
    (r"amazon|alexa|echo",                    "🏠 Echo",       "Amazon Echo"),
    (r"nest|google home",                     "🏠 Google Home","Google Nest"),
    (r"ring|doorbell",                        "🔔 Ring",       "Ring"),
    (r"synology|qnap|nas",                    "💾 NAS",        "NAS"),
    (r"printer|jetdirect|epson|canon.*print", "🖨 Printer",    "Printer"),
    (r"camera|ipcam|hikvision|dahua",         "📷 Camera",     "IP Camera"),
    (r"openwrt|dd-wrt|mikrotik",              "📡 Router",     "Router"),
]

def ssdp_discover(ip: str) -> dict:
    result = {}
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\nST: ssdp:all\r\n\r\n"
    ).encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(msg, (ip, 1900))
        data, _ = s.recvfrom(4096)
        s.close()
        resp = data.decode(errors="ignore").lower()
        for pattern, dev_type, name in SSDP_PATTERNS:
            if re.search(pattern, resp):
                result.update({"device_type": dev_type, "ssdp_device": name, "detect_method": "SSDP"})
                log.info(f"SSDP {ip}: {name}")
                break
        loc = re.search(r"location:\s*(http[^\r\n]+)", resp)
        if loc:
            try:
                desc = requests.get(loc.group(1).strip(), timeout=2, verify=False)
                fn = re.search(r"<friendlyName>([^<]+)</friendlyName>", desc.text)
                if fn: result["upnp_name"] = fn.group(1).strip()
            except Exception:
                pass
    except Exception:
        pass
    return result


# ── 5. mDNS ──────────────────────────────────────────────────────
class MDNSListener(ServiceListener):
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            try:
                ip = socket.inet_ntoa(info.addresses[0])
                hostname = info.server.rstrip(".")
                mdns_names[ip] = hostname
                for mac, dev in devices.items():
                    if dev["ip"] == ip:
                        dev.update({"mdns_name": hostname, "detect_method": "mDNS"})
                        save(); break
                log.info(f"mDNS {ip} → {hostname}")
            except Exception:
                pass
    update_service = add_service
    remove_service = lambda self, *a: None

def start_mdns():
    try:
        zc = Zeroconf()
        for t in ["_http._tcp.local.","_workstation._tcp.local.","_device-info._tcp.local.",
                   "_apple-mobdev2._tcp.local.","_googlecast._tcp.local.","_airplay._tcp.local.",
                   "_printer._tcp.local.","_smb._tcp.local."]:
            ServiceBrowser(zc, t, MDNSListener())
        log.info("mDNS started")
    except Exception as e:
        log.warning(f"mDNS error: {e}")


# ── 6. TCP SYN FINGERPRINT ───────────────────────────────────────
def tcp_syn_fingerprint(ip: str) -> str:
    try:
        pkt = IP(dst=ip)/TCP(dport=80, flags="S",
                              options=[("MSS",1460),("NOP",None),("WScale",8),("SACKOK",""),("NOP",None),("NOP",None)])
        ans = conf.L3socket().sr1(pkt, timeout=2, verbose=0)
        if ans and ans.haslayer(TCP) and ans[TCP].flags & 0x12:
            w = ans[TCP].window
            if w == 65535:                  return "macOS / iOS"
            if w == 64240:                  return "Windows 10/11"
            if w in range(28000, 32000):    return "Linux / Android"
            if w == 8192:                   return "Windows 7"
            if w in range(14000, 16000):    return "Android"
    except Exception:
        pass
    return ""


# ── 7. HTTP USER-AGENT SNIFFER ───────────────────────────────────
UA_PATTERNS = [
    (r"Android (\d+)[^;)]*;?\s*([^)]+)\)",  "📱 Android",  lambda m: f"Android {m.group(1)} – {m.group(2).strip()[:30]}"),
    (r"iPhone.*CPU iPhone OS ([\d_]+)",      "📱 iOS",      lambda m: f"iPhone iOS {m.group(1).replace('_','.')}"),
    (r"iPad.*CPU OS ([\d_]+)",               "📱 iOS",      lambda m: f"iPad iOS {m.group(1).replace('_','.')}"),
    (r"Windows NT (10\.0)",                  "💻 Windows",  lambda m: "Windows 10/11"),
    (r"Windows NT (6\.1)",                   "💻 Windows",  lambda m: "Windows 7"),
    (r"Macintosh.*Mac OS X ([\d_]+)",        "🍎 Mac",      lambda m: f"macOS {m.group(1).replace('_','.')}"),
    (r"Linux.*Ubuntu",                       "🐧 Linux",    lambda m: "Ubuntu"),
    (r"CrOS",                                "💻 ChromeOS", lambda m: "ChromeOS"),
    (r"PlayStation (\d)",                    "🎮 PlayStation", lambda m: f"PlayStation {m.group(1)}"),
    (r"Nintendo",                            "🎮 Nintendo", lambda m: "Nintendo Switch"),
]

def ua_sniffer():
    def handle(pkt):
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): return
            payload = bytes(pkt[TCP].payload).decode("utf-8", errors="ignore")
            if "User-Agent:" not in payload: return
            m = re.search(r"User-Agent: ([^\r\n]+)", payload)
            if not m: return
            ua = m.group(1).strip()
            src_ip = pkt[IP].src
            if ua_cache.get(src_ip) == ua: return
            ua_cache[src_ip] = ua
            for mac, dev in devices.items():
                if dev.get("ip") == src_ip:
                    dev["user_agent"] = ua[:120]
                    for pattern, dev_type, formatter in UA_PATTERNS:
                        match = re.search(pattern, ua)
                        if match:
                            dev.update({
                                "device_type": dev_type,
                                "ua_os": formatter(match),
                                "detect_method": "HTTP User-Agent"
                            })
                            log.info(f"UA {src_ip}: {dev['ua_os']}")
                            break
                    save(); break
        except Exception:
            pass
    log.info("UA sniffer started")
    sniff(filter="tcp port 80", prn=handle, iface=IFACE, store=0)


# ── 8. nmap ───────────────────────────────────────────────────────
def nmap_scan(ip: str) -> dict:
    result = {"os":"", "ports":[], "device_type":""}
    try:
        out = subprocess.check_output(
            ["nmap","-O","--osscan-guess","-sV","--version-intensity","3",
             "-T4","--host-timeout","15s",
             "-p","22,23,80,135,139,443,445,548,554,5000,5555,7000,8080,8443,9100,49152",ip],
            timeout=20, stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            if "OS details:" in line:
                result["os"] = line.split("OS details:")[1].strip(); break
            elif "Running:" in line and not result["os"]:
                result["os"] = line.split("Running:")[1].strip()
        result["ports"] = [
            f"{l.split()[0].split('/')[0]}/{l.split()[2]}"
            for l in out.splitlines()
            if "/tcp" in l and "open" in l and len(l.split()) >= 3
        ][:8]
        o = result["os"].lower()
        if "android" in o:    result["device_type"] = "📱 Android"
        elif "windows" in o:  result["device_type"] = "💻 Windows"
        elif "mac os" in o or "darwin" in o: result["device_type"] = "🍎 Mac"
        elif "ios" in o:      result["device_type"] = "📱 iOS"
        elif "linux" in o:    result["device_type"] = "🐧 Linux"
        elif "freebsd" in o:  result["device_type"] = "🎮 PlayStation" if "sony" in o else "🐡 FreeBSD"
    except Exception as e:
        log.debug(f"nmap {ip}: {e}")
    return result


# ── 9. TTL + MAC heuristics ───────────────────────────────────────
def is_randomized_mac(mac: str) -> bool:
    try: return bool(int(mac.split(":")[0], 16) & 0x02)
    except: return False

def get_ttl(ip: str) -> int:
    try:
        out = subprocess.check_output(["ping","-c","1","-W","1",ip],
                                       timeout=3, stderr=subprocess.DEVNULL, text=True)
        for t in out.split():
            if t.lower().startswith("ttl="):
                return int(t.split("=")[1])
    except: pass
    return 0


# ── 10. HTTP BANNER ───────────────────────────────────────────────
def grab_http_banner(ip: str) -> str:
    for scheme, port in [("http",80),("https",443),("http",8080),("http",8008)]:
        try:
            r = requests.get(f"{scheme}://{ip}:{port}", timeout=2, verify=False, allow_redirects=True)
            title = re.search(r"<title>([^<]{1,80})</title>", r.text, re.I)
            if title: return title.group(1).strip()
            server = r.headers.get("Server","")
            if server: return server
        except: pass
    return ""


# ── DEEP SCAN ────────────────────────────────────────────────────
def deep_scan_device(mac: str, ip: str):
    log.info(f"Deep scan: {ip}")
    upd = {}
    vendor = devices.get(mac, {}).get("vendor", "")

    # DNS + mDNS + NetBIOS
    try:
        hn = socket.gethostbyaddr(ip)[0]
        if hn and hn != ip: upd["hostname"] = hn
    except: pass
    if ip in mdns_names: upd["mdns_name"] = mdns_names[ip]
    nb = netbios_query(ip)
    if nb:
        upd.update({"netbios_name": nb, "detect_method": "NetBIOS"})
        if not upd.get("device_type"): upd["device_type"] = "💻 Windows"
        log.info(f"NetBIOS {ip}: {nb}")

    # SSDP
    ssdp = ssdp_discover(ip)
    if ssdp: upd.update(ssdp)

    # TCP SYN
    tcp_os = tcp_syn_fingerprint(ip)
    if tcp_os and not upd.get("device_type"):
        upd["tcp_os"] = tcp_os
        if "android" in tcp_os.lower():   upd["device_type"] = "📱 Android"
        elif "ios" in tcp_os.lower() or "macos" in tcp_os.lower(): upd["device_type"] = "🍎 Apple"
        elif "windows" in tcp_os.lower(): upd["device_type"] = "💻 Windows"

    # TTL
    ttl = get_ttl(ip)
    if ttl:
        upd["ttl"] = ttl
        if not upd.get("device_type"):
            if ttl in range(60,70):
                upd["device_type"] = "📱 Android (likely)" if is_randomized_mac(mac) else "🐧 Linux / Android"
            elif ttl in range(125,135): upd["device_type"] = "💻 Windows"
            elif ttl == 255:            upd["device_type"] = "📡 Network Device"

    # HTTP banner
    banner = grab_http_banner(ip)
    if banner:
        upd["http_banner"] = banner
        if not upd.get("device_type"):
            b = banner.lower()
            if "android" in b: upd["device_type"] = "📱 Android"
            elif "apple" in b: upd["device_type"] = "🍎 Apple"
            elif "windows" in b: upd["device_type"] = "💻 Windows"

    # nmap (last resort)
    if not upd.get("device_type") or not upd.get("os"):
        nm = nmap_scan(ip)
        if nm["os"]:    upd["os"]         = nm["os"]
        if nm["ports"]: upd["open_ports"] = nm["ports"]
        if nm["device_type"] and not upd.get("device_type"):
            upd["device_type"] = nm["device_type"]

    # vendor fallback
    if not upd.get("device_type"):
        v = vendor.lower()
        if any(x in v for x in ["samsung","xiaomi","huawei","oppo","vivo","oneplus","motorola","realme"]):
            upd["device_type"] = "📱 Android"
        elif "apple" in v:
            upd["device_type"] = "🍎 Apple"

    upd["randomized_mac"] = is_randomized_mac(mac)

    if upd and mac in devices:
        devices[mac].update(upd)
        save()
    log.info(f"Done: {ip} → {upd.get('device_type','?')} [{upd.get('detect_method','multi')}]")


# ── PERSISTENCE ──────────────────────────────────────────────────
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


# ── ARP SCAN ─────────────────────────────────────────────────────
def scan_network():
    log.info(f"Scanning {SUBNET} on {IFACE}…")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=SUBNET),
                     timeout=3, iface=IFACE, inter=0.1)
        return {rcv[Ether].src.lower(): rcv[ARP].psrc for _, rcv in ans}
    except Exception as e:
        log.error(f"Scan failed: {e}"); return {}

def update_devices(found: dict):
    now = datetime.utcnow().isoformat()
    new_macs = []
    for mac, ip in found.items():
        if mac not in devices:
            devices[mac] = {
                "mac": mac, "ip": ip, "name": "", "vendor": get_vendor(mac),
                "trusted": False, "blocked": False,
                "first_seen": now, "last_seen": now, "online": True,
            }
            log.info(f"New: {mac} @ {ip}")
            new_macs.append(mac)
        else:
            devices[mac].update({"ip": ip, "last_seen": now, "online": True})
            if devices[mac].get("vendor") in ("Unknown",""):
                devices[mac]["vendor"] = get_vendor(mac)
    for mac in devices:
        if mac not in found: devices[mac]["online"] = False
    save()
    for mac in new_macs:
        threading.Thread(target=deep_scan_device, args=(mac, devices[mac]["ip"]), daemon=True).start()


# ── ARP BLOCK ────────────────────────────────────────────────────
def get_mac_addr(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=IFACE)
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
        devices[mac]["name"] = request.json.get("name",""); save()
        return jsonify({"ok": True})
    return jsonify({"error":"not found"}), 404

@app.route("/api/devices/<mac>/trust", methods=["POST"])
def api_trust(mac):
    mac = mac.lower()
    if mac in devices:
        devices[mac]["trusted"] = bool(request.json.get("trusted", True))
        if devices[mac]["trusted"] and mac in blocked: stop_block(mac)
        save(); return jsonify({"ok": True})
    return jsonify({"error":"not found"}), 404

@app.route("/api/devices/<mac>/block", methods=["POST"])
def api_block(mac):
    mac = mac.lower()
    if mac not in devices: return jsonify({"error":"not found"}), 404
    if request.json.get("block", True):
        return jsonify({"ok": start_block(mac), "blocked": True})
    stop_block(mac); return jsonify({"ok": True, "blocked": False})

@app.route("/api/devices/<mac>/deepscan", methods=["POST"])
def api_deepscan(mac):
    mac = mac.lower()
    if mac not in devices: return jsonify({"error":"not found"}), 404
    threading.Thread(target=deep_scan_device, args=(mac, devices[mac]["ip"]), daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    found = scan_network(); update_devices(found)
    return jsonify({"scanned": len(found)})

@app.route("/api/status")
def api_status():
    return jsonify({
        "gateway": GATEWAY_IP, "subnet": SUBNET, "iface": IFACE,
        "total":   len(devices),
        "online":  sum(1 for d in devices.values() if d.get("online")),
        "blocked": len(blocked),
        "trusted": sum(1 for d in devices.values() if d.get("trusted")),
        "oui_loaded": len(OUI_DB) > 0,
    })


# ── STARTUP ──────────────────────────────────────────────────────
def scanner_loop():
    while True:
        update_devices(scan_network())
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    load()
    threading.Thread(target=load_oui_db,  daemon=True).start()
    threading.Thread(target=start_mdns,   daemon=True).start()
    threading.Thread(target=dhcp_sniffer, daemon=True).start()
    threading.Thread(target=ua_sniffer,   daemon=True).start()
    threading.Thread(target=scanner_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
