#!/usr/bin/env python3
"""
Parse Nmap XML output and generate service host:port pairs.
Prefers hostnames over IPs when available.
"""

import argparse
import csv
import os
import sys
import xml.etree.ElementTree as ET

DEBUG = False
URLS_TXT_EXCLUDED_KEYWORDS = [
    "httpapi",
    "ssdp",
    "upnp",
]

def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)


def is_excluded_service(service_elem):
    """Check if service should be excluded from urls.txt based on product/extrainfo."""
    product = (service_elem.get("product") or "").lower()
    extrainfo = (service_elem.get("extrainfo") or "").lower()
    combined = f"{product} {extrainfo}"
    for excluded in URLS_TXT_EXCLUDED_KEYWORDS:
        if excluded in combined:
            debug(f"  EXCLUDED: matched '{excluded}' in '{combined}'")
            return True
    return False


def iter_open_tcp_services(root):
    """Yield (target, ip_address, port, service_elem, service_info) for open TCP ports."""
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip_address = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip_address = addr.get("addr")
                break

        if not ip_address:
            continue

        hostname = None
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")

        target = hostname if hostname else ip_address
        debug(f"Processing host: {ip_address} (target: {target})")

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            if port.get("protocol") != "tcp":
                continue

            port_num = int(port.get("portid"))

            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            if service is None:
                debug(f"  Port {port_num}: no service element, skipping")
                continue

            service_name = (service.get("name") or "").lower()
            conf = int(service.get("conf") or 0)
            tunnel = (service.get("tunnel") or "").lower()
            product = (service.get("product") or "").lower()
            extrainfo = (service.get("extrainfo") or "").lower()

            service_info = {
                "service_name": service_name,
                "tunnel": tunnel,
                "combined": " ".join([service_name, product, extrainfo]),
                "conf": conf,
            }

            yield target, ip_address, port_num, service, service_info


def build_urls(root):
    urls = []
    seen = set()
    for target, ip_address, port_num, service_elem, service_info in iter_open_tcp_services(root):
        service_name = service_info["service_name"]
        if "http" not in service_name:
            continue
        if is_excluded_service(service_elem):
            continue
        if service_info["tunnel"] == "ssl" or "https" in service_name:
            protocol = "https"
        else:
            protocol = "http"
        if (protocol == "http" and port_num == 80) or (protocol == "https" and port_num == 443):
            url = f"{protocol}://{target}"
        else:
            url = f"{protocol}://{target}:{port_num}"
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
        debug(f"  Port {port_num}: URL YIELDING {url}")
    return urls


def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = {}
    results_low = {}
    seen = {}
    seen_low = {}
    port_targets = {}
    port_seen = {}

    for target, ip_address, port_num, service_elem, service_info in iter_open_tcp_services(root):
        if port_num not in port_targets:
            port_targets[port_num] = []
            port_seen[port_num] = set()
        if target not in port_seen[port_num]:
            port_seen[port_num].add(target)
            port_targets[port_num].append(target)
        service_name = service_info["service_name"] or "unknown"
        if service_name not in results:
            results[service_name] = []
            results_low[service_name] = []
            seen[service_name] = set()
            seen_low[service_name] = set()

        pair = f"{target}:{port_num}"
        is_low_conf = service_info["conf"] < 10
        if is_low_conf:
            if pair in seen_low[service_name]:
                continue
            seen_low[service_name].add(pair)
            results_low[service_name].append(pair)
            debug(f"  Port {port_num}: {service_name} LOW CONF YIELDING {pair}")
        else:
            if pair in seen[service_name]:
                continue
            seen[service_name].add(pair)
            results[service_name].append(pair)
            debug(f"  Port {port_num}: {service_name} YIELDING {pair}")

    affected = []
    affected_seen = set()
    for target, ip_address, port_num, service_elem, service_info in iter_open_tcp_services(root):
        key = (ip_address, port_num)
        if key in affected_seen:
            continue
        affected_seen.add(key)
        hostname = target if target != ip_address else "-"
        service_name = service_info["service_name"] or "unknown"
        affected.append({
            "IP Address": ip_address,
            "Hostname": hostname,
            "Service": f"{service_name} ({port_num}/tcp)",
        })

    urls = build_urls(root)
    return results, results_low, port_targets, urls, affected


def write_outputs(results, results_low, port_targets, urls, affected, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    urls_file = os.path.join(output_dir, "urls.txt")
    with open(urls_file, "w") as f:
        if urls:
            f.write("\n".join(urls) + "\n")
    print(f"Wrote {len(urls)} entries to {urls_file}", file=sys.stderr)

    for name in sorted(results):
        pairs = results[name]
        if not pairs:
            continue
        output_file = os.path.join(output_dir, f"{name}.txt")
        with open(output_file, "w") as f:
            f.write("\n".join(pairs) + "\n")
        print(f"Wrote {len(pairs)} entries to {output_file}", file=sys.stderr)

    for port_num in sorted(port_targets):
        targets = port_targets[port_num]
        if not targets:
            continue
        output_file = os.path.join(output_dir, f"{port_num}.txt")
        with open(output_file, "w") as f:
            f.write("\n".join(targets) + "\n")
        print(f"Wrote {len(targets)} entries to {output_file}", file=sys.stderr)

    affected_file = os.path.join(output_dir, "affected_systems.csv")
    with open(affected_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["IP Address", "Hostname", "Service"])
        writer.writeheader()
        writer.writerows(affected)
    print(f"Wrote {len(affected)} entries to {affected_file}", file=sys.stderr)

    low_dir = os.path.join(output_dir, "low_confidence")
    low_written = False
    for name in sorted(results_low):
        pairs = results_low[name]
        if not pairs:
            continue
        if not low_written:
            os.makedirs(low_dir, exist_ok=True)
            low_written = True
        output_file = os.path.join(low_dir, f"{name}.txt")
        with open(output_file, "w") as f:
            f.write("\n".join(pairs) + "\n")
        print(f"Wrote {len(pairs)} entries to {output_file}", file=sys.stderr)


def main():
    global DEBUG
    parser = argparse.ArgumentParser(
        description="Extract service host:port pairs from Nmap XML output"
    )
    parser.add_argument(
        "xml_file",
        help="Nmap XML output file"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="results",
        help="Output directory (default: ./results)"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug output"
    )

    args = parser.parse_args()

    if args.debug:
        DEBUG = True

    try:
        results, results_low, port_ips, urls, affected = parse_nmap_xml(args.xml_file)
    except FileNotFoundError:
        print(f"Error: File not found: {args.xml_file}", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)

    write_outputs(results, results_low, port_ips, urls, affected, args.output_dir)


if __name__ == "__main__":
    main()
