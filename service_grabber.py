#!/usr/bin/env python3
"""
Parse Nmap XML output and generate service host:port pairs.
Prefers hostnames over IPs when available.
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET

DEBUG = False

EXCLUDED_HTTP_KEYWORDS = [
    "httpapi",
    "ssdp",
    "upnp",
]


def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)


def is_excluded_http(service_elem):
    """Check if service should be excluded based on product/extrainfo."""
    product = (service_elem.get("product") or "").lower()
    extrainfo = (service_elem.get("extrainfo") or "").lower()
    combined = product + " " + extrainfo

    return any(keyword in combined for keyword in EXCLUDED_HTTP_KEYWORDS)


def match_service_name(expected):
    return lambda info, elem: info["service_name"] == expected


def is_mssql(service_info):
    service_name = service_info["service_name"]
    combined = service_info["combined"]
    return "ms-sql" in service_name or "mssql" in service_name or \
        any(keyword in combined for keyword in ["microsoft sql", "sql server", "mssql"])


def is_postgres(service_info):
    service_name = service_info["service_name"]
    combined = service_info["combined"]
    return "postgresql" in service_name or service_name == "postgres" or \
        any(keyword in combined for keyword in ["postgres", "postgresql"])


def is_http(service_info, service_elem):
    if service_info["service_name"] != "http":
        return False
    if service_info["tunnel"] == "ssl":
        return False
    return not is_excluded_http(service_elem)


def is_https(service_info, service_elem):
    if service_info["service_name"] != "https" and service_info["tunnel"] != "ssl":
        return False
    return not is_excluded_http(service_elem)


def iter_open_tcp_services(root):
    """Yield (target, port, service_elem, service_info) for open TCP ports."""
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
            if conf < 10:
                debug(f"  Port {port_num}: low-confidence service (conf={conf}), skipping")
                continue
            tunnel = (service.get("tunnel") or "").lower()
            product = (service.get("product") or "").lower()
            extrainfo = (service.get("extrainfo") or "").lower()

            service_info = {
                "service_name": service_name,
                "tunnel": tunnel,
                "combined": " ".join([service_name, product, extrainfo]),
            }

            yield target, port_num, service, service_info


def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    services = {
        "mssql": {"match": lambda info, elem: is_mssql(info)},
        "postgres": {"match": lambda info, elem: is_postgres(info)},
        "http": {"match": is_http},
        "https": {"match": is_https},
        "blackice-icecap": {"match": match_service_name("blackice-icecap")},
        "d-fence": {"match": match_service_name("d-fence")},
        "domain": {"match": match_service_name("domain")},
        "domain-s": {"match": match_service_name("domain-s")},
        "http-proxy": {"match": match_service_name("http-proxy")},
        "https-alt": {"match": match_service_name("https-alt")},
        "ipcam": {"match": match_service_name("ipcam")},
        "iscsi": {"match": match_service_name("iscsi")},
        "kerberos-sec": {"match": match_service_name("kerberos-sec")},
        "kpasswd5": {"match": match_service_name("kpasswd5")},
        "ldap": {"match": match_service_name("ldap")},
        "mc-nmf": {"match": match_service_name("mc-nmf")},
        "memcached": {"match": match_service_name("memcached")},
        "microsoft-ds": {"match": match_service_name("microsoft-ds")},
        "ms-cluster-net": {"match": match_service_name("ms-cluster-net")},
        "ms-wbt-server": {"match": match_service_name("ms-wbt-server")},
        "mshvlm": {"match": match_service_name("mshvlm")},
        "msmq": {"match": match_service_name("msmq")},
        "msrpc": {"match": match_service_name("msrpc")},
        "ncacn_http": {"match": match_service_name("ncacn_http")},
        "netbios-ssn": {"match": match_service_name("netbios-ssn")},
        "pando-pub": {"match": match_service_name("pando-pub")},
        "papachi-p2p-srv": {"match": match_service_name("papachi-p2p-srv")},
        "pcsync-http": {"match": match_service_name("pcsync-http")},
        "rtsp": {"match": match_service_name("rtsp")},
        "rxmon": {"match": match_service_name("rxmon")},
        "slx": {"match": match_service_name("slx")},
        "smtp": {"match": match_service_name("smtp")},
        "soap": {"match": match_service_name("soap")},
        "ssh": {"match": match_service_name("ssh")},
        "tcpwrapped": {"match": match_service_name("tcpwrapped")},
        "telnet": {"match": match_service_name("telnet")},
        "unknown": {"match": match_service_name("unknown")},
        "us-srv": {"match": match_service_name("us-srv")},
        "vmrdp": {"match": match_service_name("vmrdp")},
        "vrml-multi-use": {"match": match_service_name("vrml-multi-use")},
    }

    results = {name: [] for name in services}
    seen = {name: set() for name in services}

    for target, port_num, service_elem, service_info in iter_open_tcp_services(root):
        for name, service_def in services.items():
            if not service_def["match"](service_info, service_elem):
                continue

            pair = f"{target}:{port_num}"
            if pair in seen[name]:
                continue

            seen[name].add(pair)
            results[name].append(pair)
            debug(f"  Port {port_num}: {name} YIELDING {pair}")

    return results


def write_outputs(results, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for name, pairs in results.items():
        output_file = os.path.join(output_dir, f"{name}.txt")
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
        results = parse_nmap_xml(args.xml_file)
    except FileNotFoundError:
        print(f"Error: File not found: {args.xml_file}", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)

    write_outputs(results, args.output_dir)


if __name__ == "__main__":
    main()
