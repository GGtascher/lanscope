import csv
import ipaddress
import json
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import psutil
from mac_vendor_lookup import MacLookup
from rich.console import Console
from rich.table import Table


console = Console()

JSON_FILE = Path("known_devices.json")
CSV_FILE = Path("network_scan.csv")

MAX_HOSTS = 254
THREADS = 64
PING_TIMEOUT_MS = 350


def run_command(command, timeout=10):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        return result.stdout

    except Exception:
        return ""


def powershell_json(script, timeout=10):
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"$ProgressPreference='SilentlyContinue'; {script}",
    ]

    output = run_command(command, timeout=timeout).strip()

    if not output:
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def get_windows_network_info():
    script = """
    $c = Get-NetIPConfiguration |
        Where-Object {
            $_.NetAdapter.Status -eq 'Up' -and
            $_.IPv4Address -ne $null -and
            $_.IPv4DefaultGateway -ne $null
        } |
        Select-Object -First 1

    if ($c) {
        [PSCustomObject]@{
            InterfaceAlias = $c.InterfaceAlias
            InterfaceIndex = $c.InterfaceIndex
            IPv4Address = ($c.IPv4Address | Select-Object -First 1).IPAddress
            PrefixLength = ($c.IPv4Address | Select-Object -First 1).PrefixLength
            Gateway = ($c.IPv4DefaultGateway | Select-Object -First 1).NextHop
            DNSServers = @($c.DNSServer.ServerAddresses)
        } | ConvertTo-Json -Depth 4 -Compress
    }
    """

    return powershell_json(script)


def get_adapter_info(interface_index):
    script = f"""
    Get-NetAdapter -InterfaceIndex {interface_index} |
    Select-Object Name,
                  InterfaceDescription,
                  Status,
                  LinkSpeed,
                  MacAddress,
                  ifIndex |
    ConvertTo-Json -Compress
    """

    return powershell_json(script)


def get_connection_profile(interface_index):
    script = f"""
    Get-NetConnectionProfile -InterfaceIndex {interface_index} |
    Select-Object Name,
                  NetworkCategory,
                  IPv4Connectivity,
                  IPv6Connectivity |
    ConvertTo-Json -Compress
    """

    return powershell_json(script)


def get_fallback_network_info():
    active_ip = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("8.8.8.8", 80))
        active_ip = sock.getsockname()[0]
    except OSError:
        pass
    finally:
        sock.close()

    for interface_name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family != socket.AF_INET:
                continue

            if not address.netmask:
                continue

            if active_ip and address.address != active_ip:
                continue

            if address.address.startswith("127."):
                continue

            interface = ipaddress.IPv4Interface(
                f"{address.address}/{address.netmask}"
            )

            return {
                "InterfaceAlias": interface_name,
                "InterfaceIndex": None,
                "IPv4Address": address.address,
                "PrefixLength": interface.network.prefixlen,
                "Gateway": "Unknown",
                "DNSServers": [],
            }

    return None


def get_network_info():
    info = get_windows_network_info()

    if not info:
        info = get_fallback_network_info()

    if not info:
        raise RuntimeError(
            "Unable."
        )

    local_ip = info["IPv4Address"]
    prefix_length = int(info["PrefixLength"])

    real_network = ipaddress.ip_network(
        f"{local_ip}/{prefix_length}",
        strict=False,
    )

    if prefix_length < 24:
        scan_network = ipaddress.ip_network(
            f"{local_ip}/24",
            strict=False,
        )
    else:
        scan_network = real_network

    info["RealNetwork"] = str(real_network)
    info["ScanNetwork"] = str(scan_network)

    return info


def parse_wifi_info():
    output = run_command(
        ["netsh", "wlan", "show", "interfaces"],
        timeout=5,
    )

    if not output:
        return {}

    result = {}

    key_map = {
        "ssid": "SSID",
        "bssid": "BSSID",
        "signal": "Signal",
        "channel": "Channel",
        "radio type": "RadioType",
        "authentication": "Authentication",
        "cipher": "Cipher",
        "network type": "NetworkType",

        "сигнал": "Signal",
        "канал": "Channel",
        "шифр": "Cipher",

        "тип радіо": "RadioType",
        "автентифікація": "Authentication",
        "аутентифікація": "Authentication",

        "typ radia": "RadioType",
        "uwierzytelnianie": "Authentication",
        "szyfr": "Cipher",
    }

    for line in output.splitlines():
        if ":" not in line:
            continue

        left, right = line.split(":", 1)

        key = left.strip().lower()
        value = right.strip()

        if not value:
            continue

        if key == "ssid":
            result["SSID"] = value
            continue

        if key == "bssid":
            result["BSSID"] = value
            continue

        mapped = key_map.get(key)

        if mapped:
            result[mapped] = value

    return result


def ping_host(ip):
    started = time.perf_counter()

    try:
        result = subprocess.run(
            [
                "ping",
                "-n",
                "1",
                "-w",
                str(PING_TIMEOUT_MS),
                str(ip),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        elapsed = (time.perf_counter() - started) * 1000

        return {
            "ip": str(ip),
            "alive": result.returncode == 0,
            "ping_ms": round(elapsed, 1),
        }

    except Exception:
        return {
            "ip": str(ip),
            "alive": False,
            "ping_ms": None,
        }


def populate_neighbor_table(network):
    hosts = list(network.hosts())

    if len(hosts) > MAX_HOSTS:
        hosts = hosts[:MAX_HOSTS]

    console.print(
        f"Check address: [cyan]{len(hosts)}[/cyan]"
    )

    if hosts:
        console.print(
            f"Zone: [cyan]{hosts[0]} - {hosts[-1]}[/cyan]"
        )

    results = {}

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {
            executor.submit(ping_host, host): host
            for host in hosts
        }

        completed = 0

        for future in as_completed(futures):
            completed += 1

            try:
                result = future.result()
                results[result["ip"]] = result
            except Exception:
                pass

            if completed % 25 == 0 or completed == len(hosts):
                console.print(
                    f"[dim]Checked {completed}/{len(hosts)}[/dim]"
                )

    console.print(
        "[green]End.[/green]"
    )

    return results


def get_neighbors(interface_index, network):
    console.print(
        "[yellow]Collect ARP / Neighbor table...[/yellow]"
    )

    if interface_index is not None:
        script = f"""
        Get-NetNeighbor -InterfaceIndex {interface_index} -AddressFamily IPv4 |
        Where-Object {{
            $_.State -ne 'Unreachable' -and
            $_.LinkLayerAddress -ne $null
        }} |
        Select-Object IPAddress,
                      LinkLayerAddress,
                      State |
        ConvertTo-Json -Depth 3 -Compress
        """

        data = powershell_json(script)

        if data:
            if isinstance(data, dict):
                data = [data]

            devices = []

            for item in data:
                ip_text = item.get("IPAddress")
                mac = item.get("LinkLayerAddress")

                if not ip_text or not mac:
                    continue

                try:
                    ip = ipaddress.IPv4Address(ip_text)
                except ValueError:
                    continue

                if ip not in network:
                    continue

                mac = mac.replace("-", ":").upper()

                if mac in {
                    "00:00:00:00:00:00",
                    "FF:FF:FF:FF:FF:FF",
                }:
                    continue

                devices.append(
                    {
                        "ip": ip_text,
                        "mac": mac,
                        "neighbor_state": item.get(
                            "State",
                            "Unknown",
                        ),
                    }
                )

            if devices:
                return unique_devices(devices)

    return get_neighbors_from_arp(network)


def get_neighbors_from_arp(network):
    output = run_command(["arp", "-a"])

    pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\s+"
        r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+"
        r"(dynamic|static)",
        re.IGNORECASE,
    )

    devices = []

    for match in pattern.finditer(output):
        ip_text = match.group(1)
        mac = match.group(2).replace("-", ":").upper()

        try:
            ip = ipaddress.IPv4Address(ip_text)
        except ValueError:
            continue

        if ip not in network:
            continue

        if mac in {
            "00:00:00:00:00:00",
            "FF:FF:FF:FF:FF:FF",
        }:
            continue

        devices.append(
            {
                "ip": ip_text,
                "mac": mac,
                "neighbor_state": match.group(3).title(),
            }
        )

    return unique_devices(devices)


def unique_devices(devices):
    result = {}

    for device in devices:
        result[device["mac"]] = device

    return list(result.values())


def resolve_hostname(ip):
    old_timeout = socket.getdefaulttimeout()

    try:
        socket.setdefaulttimeout(0.8)

        hostname, _, _ = socket.gethostbyaddr(ip)

        return hostname

    except Exception:
        return "Unknown"

    finally:
        socket.setdefaulttimeout(old_timeout)


def create_mac_lookup():
    try:
        return MacLookup()
    except Exception:
        return None


def resolve_vendor(mac, lookup):
    if lookup is None:
        return "Unknown"

    try:
        return lookup.lookup(mac)
    except Exception:
        return "Unknown"


def is_locally_administered_mac(mac):
    try:
        first_byte = int(
            mac.split(":")[0],
            16,
        )

        return bool(first_byte & 0x02)

    except Exception:
        return False


def guess_device_type(ip, hostname, vendor, gateway):
    hostname_lower = hostname.lower()
    vendor_lower = vendor.lower()

    if ip == gateway:
        return "Router / Gateway"

    phone_words = [
        "iphone",
        "galaxy",
        "android",
        "pixel",
        "phone",
        "oneplus",
    ]

    if any(word in hostname_lower for word in phone_words):
        return "Smartphone"

    computer_words = [
        "desktop",
        "laptop",
        "notebook",
        "pc-",
        "computer",
    ]

    if any(word in hostname_lower for word in computer_words):
        return "Computer"

    if "raspberry" in vendor_lower:
        return "Raspberry Pi / IoT"

    if any(
        x in vendor_lower
        for x in [
            "tp-link",
            "ubiquiti",
            "netgear",
            "cisco",
            "mikrotik",
            "aruba",
        ]
    ):
        return "Network Device"

    if "apple" in vendor_lower:
        return "Apple Device"

    if any(
        x in vendor_lower
        for x in [
            "intel",
            "lenovo",
            "dell",
            "asus",
            "acer",
            "gigabyte",
            "micro-star",
        ]
    ):
        return "Computer"

    if any(
        x in vendor_lower
        for x in [
            "samsung",
            "xiaomi",
            "oppo",
            "vivo",
        ]
    ):
        return "Mobile / IoT"

    return "Unknown"


def enrich_device(item, lookup, gateway, ping_results):
    ip = item["ip"]
    mac = item["mac"]

    hostname = resolve_hostname(ip)
    vendor = resolve_vendor(mac, lookup)

    ping_info = ping_results.get(
        ip,
        {},
    )

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "device_type": guess_device_type(
            ip,
            hostname,
            vendor,
            gateway,
        ),
        "neighbor_state": item.get(
            "neighbor_state",
            "Unknown",
        ),
        "ping_ms": ping_info.get("ping_ms"),
        "randomized_mac": is_locally_administered_mac(mac),
    }


def enrich_devices(
    devices,
    lookup,
    gateway,
    ping_results,
):
    if not devices:
        return []

    console.print(
        f"[yellow]Collecting "
        f"{len(devices)} devices...[/yellow]"
    )

    enriched = []

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {
            executor.submit(
                enrich_device,
                device,
                lookup,
                gateway,
                ping_results,
            ): device
            for device in devices
        }

        completed = 0

        for future in as_completed(futures):
            completed += 1

            try:
                enriched.append(
                    future.result()
                )
            except Exception:
                pass

            console.print(
                f"[dim]Information: "
                f"{completed}/{len(devices)}[/dim]"
            )

    return enriched


def load_previous_devices():
    if not JSON_FILE.exists():
        return {}

    try:
        with open(
            JSON_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            devices = json.load(file)

        return {
            device["mac"]: device
            for device in devices
            if device.get("mac")
        }

    except Exception:
        return {}


def save_json(devices):
    with open(
        JSON_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            devices,
            file,
            indent=4,
            ensure_ascii=False,
        )


def save_csv(devices):
    fields = [
        "ip",
        "mac",
        "hostname",
        "vendor",
        "device_type",
        "neighbor_state",
        "ping_ms",
        "randomized_mac",
        "status",
        "first_seen",
        "last_seen",
    ]

    with open(
        CSV_FILE,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(devices)


def print_network_info(
    info,
    adapter,
    profile,
    wifi,
):
    table = Table(
        title="Network Information",
        show_header=False,
        show_lines=False,
    )

    table.add_column(
        "Property",
        style="bold",
    )
    table.add_column(
        "Value",
        style="cyan",
    )

    table.add_row(
        "Interface",
        str(info.get("InterfaceAlias", "Unknown")),
    )

    if adapter:
        table.add_row(
            "Adapter",
            str(
                adapter.get(
                    "InterfaceDescription",
                    "Unknown",
                )
            ),
        )

        table.add_row(
            "Adapter MAC",
            str(
                adapter.get(
                    "MacAddress",
                    "Unknown",
                )
            ),
        )

        table.add_row(
            "Link Speed",
            str(
                adapter.get(
                    "LinkSpeed",
                    "Unknown",
                )
            ),
        )

    table.add_row(
        "Local IPv4",
        str(info.get("IPv4Address", "Unknown")),
    )

    table.add_row(
        "Prefix",
        f"/{info.get('PrefixLength', '?')}",
    )

    table.add_row(
        "Real Network",
        str(info.get("RealNetwork", "Unknown")),
    )

    table.add_row(
        "Scan Network",
        str(info.get("ScanNetwork", "Unknown")),
    )

    table.add_row(
        "Gateway",
        str(info.get("Gateway", "Unknown")),
    )

    dns = info.get("DNSServers", [])

    if isinstance(dns, list):
        dns_text = ", ".join(dns)
    else:
        dns_text = str(dns)

    table.add_row(
        "DNS",
        dns_text or "Unknown",
    )

    if profile:
        table.add_row(
            "Network Name",
            str(profile.get("Name", "Unknown")),
        )

        table.add_row(
            "Network Category",
            str(
                profile.get(
                    "NetworkCategory",
                    "Unknown",
                )
            ),
        )

    if wifi:
        table.add_row(
            "Wi-Fi SSID",
            wifi.get("SSID", "Unknown"),
        )

        table.add_row(
            "BSSID",
            wifi.get("BSSID", "Unknown"),
        )

        table.add_row(
            "Signal",
            wifi.get("Signal", "Unknown"),
        )

        table.add_row(
            "Channel",
            wifi.get("Channel", "Unknown"),
        )

        table.add_row(
            "Radio",
            wifi.get("RadioType", "Unknown"),
        )

        table.add_row(
            "Authentication",
            wifi.get(
                "Authentication",
                "Unknown",
            ),
        )

        table.add_row(
            "Cipher",
            wifi.get("Cipher", "Unknown"),
        )

    console.print()
    console.print(table)


def print_device_table(devices):
    table = Table(
        title="Detected Network Devices",
        show_lines=True,
    )

    table.add_column(
        "Status",
        justify="center",
    )

    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Hostname")
    table.add_column("Vendor")
    table.add_column("Device Type")
    table.add_column("State")
    table.add_column("Ping")

    for device in devices:
        if device["status"] == "NEW":
            status = "[yellow]NEW[/yellow]"
        else:
            status = "[green]KNOWN[/green]"

        ping = device.get("ping_ms")

        if ping is None:
            ping_text = "-"
        else:
            ping_text = f"{ping:.1f} ms"

        mac = device["mac"]

        if device.get("randomized_mac"):
            mac += " *"

        table.add_row(
            status,
            device["ip"],
            mac,
            device["hostname"],
            device["vendor"],
            device["device_type"],
            device["neighbor_state"],
            ping_text,
        )

    console.print()
    console.print(table)

    console.print(
        "[dim]* = locally administered / "
        "possibly randomized MAC[/dim]"
    )


def ip_sort(device):
    try:
        return int(
            ipaddress.IPv4Address(
                device["ip"]
            )
        )
    except Exception:
        return 0


def main():
    console.print()
    console.print(
        "[bold cyan]LanScope 2.0[/bold cyan]"
    )

    console.print(
        "Windows Local Network Analyzer"
    )

    try:
        info = get_network_info()
    except RuntimeError as error:
        console.print(
            f"[bold red]{error}[/bold red]"
        )
        return

    interface_index = info.get(
        "InterfaceIndex"
    )

    adapter = None
    profile = None

    if interface_index:
        adapter = get_adapter_info(
            interface_index
        )

        profile = get_connection_profile(
            interface_index
        )

    wifi = parse_wifi_info()

    print_network_info(
        info,
        adapter,
        profile,
        wifi,
    )

    scan_network = ipaddress.ip_network(
        info["ScanNetwork"],
        strict=False,
    )

    console.print()
    console.print(
        "[bold yellow]Start...[/bold yellow]"
    )

    ping_results = populate_neighbor_table(
        scan_network
    )

    neighbors = get_neighbors(
        interface_index,
        scan_network,
    )

    console.print(
        f"Records in neighbor table: "
        f"[cyan]{len(neighbors)}[/cyan]"
    )

    lookup = create_mac_lookup()

    enriched = enrich_devices(
        neighbors,
        lookup,
        str(info.get("Gateway", "Unknown")),
        ping_results,
    )

    previous = load_previous_devices()

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    final_devices = []

    for device in enriched:
        previous_device = previous.get(
            device["mac"]
        )

        if previous_device:
            status = "KNOWN"

            first_seen = previous_device.get(
                "first_seen",
                previous_device.get(
                    "last_seen",
                    now,
                ),
            )
        else:
            status = "NEW"
            first_seen = now

        device["status"] = status
        device["first_seen"] = first_seen
        device["last_seen"] = now

        final_devices.append(device)

    final_devices.sort(
        key=ip_sort
    )

    print_device_table(
        final_devices
    )

    current_macs = {
        device["mac"]
        for device in final_devices
    }

    offline = [
        device
        for mac, device in previous.items()
        if mac not in current_macs
    ]

    console.print()

    console.print(
        f"Devices found: "
        f"[bold green]{len(final_devices)}[/bold green]"
    )

    new_count = sum(
        device["status"] == "NEW"
        for device in final_devices
    )

    console.print(
        f"New devices: "
        f"[yellow]{new_count}[/yellow]"
    )

    if offline:
        console.print()
        console.print(
            "[red]Unknown earlier, "
            "Founded now:[/red]"
        )

        for device in offline:
            console.print(
                f"  {device.get('ip', '?')} | "
                f"{device.get('mac', '?')} | "
                f"{device.get('hostname', 'Unknown')}"
            )

    save_json(
        final_devices
    )

    save_csv(
        final_devices
    )

    console.print()
    console.print(
        f"JSON: [cyan]{JSON_FILE.resolve()}[/cyan]"
    )

    console.print(
        f"CSV:  [cyan]{CSV_FILE.resolve()}[/cyan]"
    )

    console.print()
    console.print(
        "[bold green]Finish.[/bold green]"
    )


if __name__ == "__main__":
    main()
