# tools/plugins/asset_inventory/run.py
#
# Runs a broader passive fingerprint than nmap_scan's defaults (OS detection,
# service versions, default NSE scripts), then applies a heuristic
# classifier to label what kind of device this looks like. Entirely
# read-only — never attempts authentication or exploitation, only
# interprets data nmap already legitimately collects.
#
# Classification is a best-effort heuristic, not a certainty — it's meant
# to save you from having to eyeball raw port lists yourself, not to be
# authoritative. Always shown alongside its signals so you can judge it.

import subprocess
import xml.etree.ElementTree as ET

NMAP_TIMEOUT = 180

# Port -> hint fragments used by the classifier below.
PRINTER_PORTS = {9100, 631, 515}
IOT_PORTS = {1883, 8883, 5683}
FILE_SHARE_PORTS = {445, 139, 2049}
DB_PORTS = {3306, 5432, 1433, 27017, 6379}
ROUTER_HINT_PORTS = {53, 67, 68}

PRINTER_VENDOR_STRINGS = ["hp", "canon", "epson", "brother", "laserjet", "jetdirect", "lexmark", "xerox"]
ROUTER_VENDOR_STRINGS = ["tp-link", "netgear", "ubiquiti", "cisco", "mikrotik", "d-link", "asus", "linksys", "openwrt"]
NAS_VENDOR_STRINGS = ["synology", "qnap", "western digital", "freenas", "truenas"]
IOT_VENDOR_STRINGS = ["espressif", "raspberry pi", "arduino", "shelly", "tasmota", "sonoff"]
IOT_SERVER_STRINGS = ["lighttpd", "goahead", "boa/", "mongoose"]


def run_nmap_profile(target: str) -> str:
    result = subprocess.run(
        ["nmap", "-O", "-sV", "--script=default", "-oX", "-", target],
        capture_output=True, text=True, timeout=NMAP_TIMEOUT,
    )
    if result.returncode != 0:
        raise Exception(f"nmap failed: {result.stderr.strip()}")
    return result.stdout


def parse_nmap_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    host_el = root.find("host")
    if host_el is None:
        return {"ports": [], "os": None, "vendor": None, "hostname": None}

    ports = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            service_el = port_el.find("service")
            ports.append({
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol"),
                "service": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "banner": " ".join(filter(None, [
                    service_el.get("product") if service_el is not None else None,
                    service_el.get("version") if service_el is not None else None,
                    service_el.get("extrainfo") if service_el is not None else None,
                ])) if service_el is not None else "",
            })

    os_guess = None
    os_el = host_el.find("os")
    if os_el is not None:
        match = os_el.find("osmatch")
        if match is not None:
            os_guess = match.get("name")

    vendor = None
    hostname = None
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") == "mac" and addr_el.get("vendor"):
            vendor = addr_el.get("vendor")
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        hn = hostnames_el.find("hostname")
        if hn is not None:
            hostname = hn.get("name")

    return {"ports": ports, "os": os_guess, "vendor": vendor, "hostname": hostname}


def classify_device(parsed: dict) -> dict:
    ports = {p["port"] for p in parsed["ports"]}
    banners = " ".join(p["banner"].lower() for p in parsed["ports"] if p["banner"])
    os_guess = (parsed["os"] or "").lower()
    vendor = (parsed["vendor"] or "").lower()

    signals = []
    scores = {"router": 0, "printer": 0, "iot": 0, "nas": 0, "workstation": 0, "server": 0}

    if ports & PRINTER_PORTS:
        scores["printer"] += 3
        signals.append(f"printer port(s) open: {sorted(ports & PRINTER_PORTS)}")
    if any(s in banners or s in vendor for s in PRINTER_VENDOR_STRINGS):
        scores["printer"] += 2
        signals.append("printer vendor string matched")

    if any(s in vendor for s in ROUTER_VENDOR_STRINGS) or "openwrt" in os_guess:
        scores["router"] += 3
        signals.append("router vendor/OS string matched")
    if ports & ROUTER_HINT_PORTS:
        scores["router"] += 1
        signals.append(f"router-associated port(s) open: {sorted(ports & ROUTER_HINT_PORTS)}")

    if ports & IOT_PORTS:
        scores["iot"] += 3
        signals.append(f"IoT protocol port(s) open: {sorted(ports & IOT_PORTS)}")
    if any(s in vendor for s in IOT_VENDOR_STRINGS) or any(s in banners for s in IOT_SERVER_STRINGS):
        scores["iot"] += 2
        signals.append("IoT vendor/server string matched")

    if any(s in vendor for s in NAS_VENDOR_STRINGS):
        scores["nas"] += 3
        signals.append("NAS vendor string matched")
    if (ports & FILE_SHARE_PORTS) and not any(s in os_guess for s in ["windows 10", "windows 11", "mac os"]):
        scores["nas"] += 1
        signals.append("file-sharing ports open without a desktop OS match")

    if any(s in os_guess for s in ["windows 10", "windows 11", "windows 7", "mac os", "macos"]):
        scores["workstation"] += 3
        signals.append(f"desktop OS fingerprint: {parsed['os']}")
    if 3389 in ports:
        scores["workstation"] += 1
        signals.append("RDP port open")

    if ports & DB_PORTS:
        scores["server"] += 2
        signals.append(f"database port(s) open: {sorted(ports & DB_PORTS)}")
    if any(s in os_guess for s in ["linux", "server", "unix"]) and len(ports) >= 3:
        scores["server"] += 1
        signals.append(f"server-like OS with {len(ports)} open ports")

    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return {"classification": "unclassified", "confidence": "none", "signals": ["no distinguishing signals found"]}

    confidence = "high" if scores[best] >= 3 else "low"
    return {"classification": best, "confidence": confidence, "signals": signals}


def execute(target: str, profile: str, **kwargs) -> dict:
    xml_text = run_nmap_profile(target)
    parsed = parse_nmap_xml(xml_text)
    classification = classify_device(parsed)

    return {
        "asset_inventory": {
            "target": target,
            "hostname": parsed["hostname"],
            "os_guess": parsed["os"],
            "mac_vendor": parsed["vendor"],
            "open_ports": parsed["ports"],
            "classification": classification["classification"],
            "confidence": classification["confidence"],
            "signals": classification["signals"],
        }
    }
