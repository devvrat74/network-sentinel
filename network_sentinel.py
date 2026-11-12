#!/usr/bin/env python3
"""
Network Sentinel - a small, consent-based network and security-log auditor.

Use only against systems you own or have explicit permission to assess.
This tool performs TCP connection checks (not stealth scanning), and analyzes
a local authentication log for repeated failed-login events.
"""
import argparse
import ipaddress
import os
import socket
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

APP_NAME = "Network Sentinel"
LOG_FILE = "sentinel_activity.log"
AUTH_LOG = "auth_events.log"
DEFAULT_PORTS = [22, 80, 443, 445, 3389]


def timestamp():
    """Return a human-readable local timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def validate_target(target):
    """Validate an IPv4/IPv6 address or a hostname; return normalized text."""
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        # Resolve hostnames before scanning. getaddrinfo also validates reachability
        # of DNS resolution without sending application data to the host.
        try:
            socket.getaddrinfo(target, None)
            return target
        except socket.gaierror as exc:
            raise ValueError("Enter a valid IP address or resolvable hostname.") from exc


def validate_ports(raw_ports):
    """Convert comma-separated ports into unique integers in the TCP port range."""
    ports = []
    for item in raw_ports.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError as exc:
            raise ValueError(f"'{item}' is not an integer port.") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Port {port} is outside the valid range 1-65535.")
        if port not in ports:
            ports.append(port)
    if not ports:
        raise ValueError("Provide at least one port.")
    return ports


def write_activity(message):
    """Append an activity record to the application log."""
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(f"[{timestamp()}] {message}\n")


def initialize_auth_log():
    """Create a small demonstration authentication log using write mode."""
    if not os.path.exists(AUTH_LOG):
        with open(AUTH_LOG, "w", encoding="utf-8") as file:
            file.write("# Demo format: timestamp,username,source_ip,status\n")
            file.write("2026-11-12 09:00:00,admin,192.0.2.10,FAILED\n")
            file.write("2026-11-12 09:01:00,admin,192.0.2.10,FAILED\n")
            file.write("2026-11-12 09:02:00,guest,198.51.100.7,SUCCESS\n")


def scan_tcp_ports(target, ports, timeout=0.8):
    """Attempt ordinary TCP connections and return open/closed/filtered results."""
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            status = sock.connect_ex((target, port))
            state = "OPEN" if status == 0 else "CLOSED/FILTERED"
            results.append((port, state))
        except (socket.timeout, OSError) as exc:
            results.append((port, f"ERROR: {exc.__class__.__name__}"))
        finally:
            sock.close()
    return results


def analyze_auth_log(threshold=3):
    """
    Read the authentication log and count FAILED events by source IP.
    Return a dictionary of sources at or above the threshold.
    """
    failures = {}
    with open(AUTH_LOG, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(",")
            if len(fields) != 4:
                continue
            _event_time, _username, source_ip, status = fields
            if status.strip().upper() != "FAILED":
                continue
            try:
                source_ip = str(ipaddress.ip_address(source_ip.strip()))
            except ValueError:
                continue
            failures[source_ip] = failures.get(source_ip, 0) + 1

    return {ip: count for ip, count in failures.items() if count >= threshold}


def ask_menu_choice():
    """Get a valid menu selection; continue skips invalid entries."""
    while True:
        choice = input("\nSelect an option (1-3, or 0 to exit): ").strip()
        if not choice:
            print(Fore.YELLOW + "Input cannot be blank. Try again.")
            continue
        if choice in {"0", "1", "2", "3"}:
            return int(choice)
        print(Fore.YELLOW + "Invalid choice. Enter 0, 1, 2, or 3.")


def run_scan():
    """Collect target and ports, scan, display and log results."""
    while True:
        raw_target = input("Target IP/hostname (authorized systems only): ")
        try:
            target = validate_target(raw_target)
            break
        except ValueError as exc:
            print(Fore.RED + str(exc))
            continue

    raw_ports = input(f"TCP ports (comma-separated; default {DEFAULT_PORTS}): ").strip()
    if not raw_ports:
        ports = DEFAULT_PORTS
    else:
        try:
            ports = validate_ports(raw_ports)
        except ValueError as exc:
            print(Fore.RED + str(exc))
            return

    print(f"\nScanning {target} on {len(ports)} TCP port(s)...")
    results = scan_tcp_ports(target, ports)
    for port, state in results:
        color = Fore.GREEN if state == "OPEN" else Fore.YELLOW
        print(f"TCP/{port:<5} {color}{state}")

    opened = [str(port) for port, state in results if state == "OPEN"]
    summary = f"Scan target={target}; ports={ports}; open={opened or 'none'}"
    write_activity(summary)
    print(Fore.CYAN + "Scan summary appended to " + LOG_FILE)


def run_log_analysis():
    """Ask for threshold and report repeated failed authentication attempts."""
    while True:
        raw = input("Alert threshold for failed logins per source IP (default 3): ").strip()
        if not raw:
            threshold = 3
            break
        try:
            threshold = int(raw)
            if threshold < 1:
                print(Fore.YELLOW + "Threshold must be at least 1.")
                continue
            break
        except ValueError:
            print(Fore.YELLOW + "Enter a whole number.")
            continue

    initialize_auth_log()
    alerts = analyze_auth_log(threshold)
    if alerts:
        print(Fore.RED + "\nPotential brute-force indicators:")
        for source_ip, count in alerts.items():
            print(f"  {source_ip}: {count} failed attempts")
    else:
        print(Fore.GREEN + "No source IP met the alert threshold.")

    write_activity(f"Log analysis completed; threshold={threshold}; alerts={alerts}")
    print(Fore.CYAN + f"Analysis event appended to {LOG_FILE}")


def view_activity_log():
    """Read and display the activity log; create it if it does not exist."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as file:
            file.write(f"[{timestamp()}] {APP_NAME} initialized.\n")
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        contents = file.read()
    print("\n--- Activity Log ---")
    print(contents if contents.strip() else "(Log is empty.)")


def main():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--version", action="version", version="Network Sentinel 1.0")
    parser.parse_args()

    print(Fore.CYAN + "=" * 54)
    print(Fore.CYAN + f" {APP_NAME} | Authorized Security Assessment")
    print(Fore.CYAN + "=" * 54)
    print("Use only on systems you own or are explicitly authorized to test.")
    initialize_auth_log()

    while True:
        print("\n1. TCP port check")
        print("2. Analyze authentication log")
        print("3. View activity log")
        print("0. Exit")
        choice = ask_menu_choice()

        if choice == 1:
            run_scan()
        elif choice == 2:
            run_log_analysis()
        elif choice == 3:
            view_activity_log()
        else:
            print("Exiting Network Sentinel.")
            break

    write_activity("Application closed normally.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
