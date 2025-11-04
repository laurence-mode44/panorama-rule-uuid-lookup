#!/usr/bin/env python3
# Version: 1.3.1-panorama-rule-uuid-lookup  (PAN-OS Classic Path)
"""
Panorama Rule UUID Lookup — Mode44 (v1.3.1)
-------------------------------------------
This build is validated against Panorama systems where device groups
live at the classic PAN-OS path:

    /config/devices/entry/device-group

Confirmed working on Panorama 10.x / early 11.0.x.

Features
--------
• Dual-auth: XML API keygen (username/password) and REST_API_TOKEN (future-ready)
• Searches Shared pre/post + Device Group pre/post Security rulebases
• Reads rule names from rule_list.txt (one per line)
• Human-readable Rich table + CSV export
• Secure Mode44 design: runtime credentials only, optional SSL verify, defusedxml

If your environment uses the SCM-style hierarchy:
    /config/devices/entry[@name='localhost.localdomain']/device-group
use this version as reference and switch the XPaths accordingly
(planned v1.7 branch).

Author : Laurence Curling (Mode44 Ltd)
License: MIT
"""

import requests, urllib3, getpass, csv, sys
from pathlib import Path
from defusedxml import ElementTree as ET
from rich.console import Console
from rich.table import Table

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === authentication ==========================================================
def get_panorama_token():
    """
    Unified authentication for Panorama.
    Supports REST_API_TOKEN or classic XML API keygen.
    Returns dict: {host, token, is_rest, verify}
    """
    console.print("[bold cyan]=== Panorama Authentication ===[/bold cyan]")
    host = console.input("Panorama URL (e.g. https://192.168.0.190): ").strip()
    if not host.startswith("http"):
        host = "https://" + host

    mode = console.input("Use REST_API_TOKEN? (y/N): ").lower().startswith("y")
    skip_verify = console.input("Skip SSL verification? (y/N): ").lower().startswith("y")
    verify = not skip_verify
    if skip_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if mode:
        token = getpass.getpass("Enter REST_API_TOKEN: ").strip()
        return {"host": host, "token": token, "is_rest": True, "verify": verify}

    # Classic XML API keygen flow
    user = console.input("Username: ").strip()
    pw = getpass.getpass("Password: ")
    try:
        url = f"{host.rstrip('/')}/api/"
        params = {"type": "keygen", "user": user, "password": pw}
        r = requests.get(url, params=params, verify=verify, timeout=20)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        key = root.findtext(".//key")
        if not key:
            msg = root.findtext(".//msg") or "No key returned"
            raise RuntimeError(msg)
        console.print("[green]Login successful (XML API key).[/green]")
        return {"host": host, "token": key, "is_rest": False, "verify": verify}
    except Exception as ex:
        console.print(f"[red]Login failed:[/red] {ex}")
        raise


# === API helper ==============================================================
def api_get(host: str, token: str, xpath: str, verify: bool, is_rest=False):
    """Perform XML config GET using either key= or REST_API_TOKEN="""
    url = f"{host.rstrip('/')}/api/"
    params = {"type": "config", "action": "get", "xpath": xpath}
    if is_rest:
        params["REST_API_TOKEN"] = token
    else:
        params["key"] = token
    r = requests.get(url, params=params, verify=verify, timeout=60)
    r.raise_for_status()
    return ET.fromstring(r.text)


# === device-group discovery ==================================================
def get_device_groups(host: str, token: str, verify: bool, is_rest: bool):
    """
    Retrieve device-group names for PAN-OS Classic Path:
    /config/devices/entry/device-group
    """
    xpath = "/config/devices/entry/device-group"
    console.print(f"[dim]Querying device groups at: {xpath}[/dim]")

    xml = api_get(host, token, xpath, verify, is_rest)
    xml = xml.find(".//device-group") or xml
    dgs = [e.get("name") for e in xml.findall("./entry") if e.get("name")]

    if dgs:
        console.print(f"[cyan]Discovered {len(dgs)} device groups: {', '.join(dgs)}[/cyan]")
    else:
        console.print(f"[red]No device groups found via {xpath}[/red]")
    return sorted(dgs)


# === rule UUID lookup ========================================================
def find_rule_uuids(host, token, verify, rule_names, is_rest):
    results = []

    # shared pre/post
    console.print("[bold cyan]Scanning Shared Pre/Post Rules[/bold cyan]")
    shared_bases = {
        "shared-pre": "/config/shared/pre-rulebase/security/rules",
        "shared-post": "/config/shared/post-rulebase/security/rules"
    }
    for label, xpath in shared_bases.items():
        try:
            xml = api_get(host, token, xpath, verify, is_rest)
            for e in xml.findall(".//entry"):
                name, uuid = e.get("name", ""), e.get("uuid", "")
                if name.lower() in rule_names:
                    results.append({
                        "device_group": "shared",
                        "location": label,
                        "name": name,
                        "uuid": uuid
                    })
        except Exception as ex:
            console.print(f"[yellow]Warning:[/yellow] shared {label}: {ex}")

    # device-groups
    dgs = get_device_groups(host, token, verify, is_rest)
    prefix = "/config/devices/entry/device-group"
    for dg in dgs:
        console.print(f"[bold cyan]Scanning device group:[/bold cyan] {dg}")
        for section in ("pre-rulebase", "post-rulebase"):
            xpath = f"{prefix}/entry[@name='{dg}']/{section}/security/rules"
            try:
                xml = api_get(host, token, xpath, verify, is_rest)
                entries = xml.findall(".//entry")
                console.print(f"[dim]{dg} → {section}: found {len(entries)} entries[/dim]")
                for e in entries:
                    name, uuid = e.get("name", ""), e.get("uuid", "")
                    if name.lower() in rule_names:
                        results.append({
                            "device_group": dg,
                            "location": "pre" if section.startswith("pre") else "post",
                            "name": name,
                            "uuid": uuid
                        })
            except Exception as ex:
                console.print(f"[yellow]Warning:[/yellow] {dg} {section}: {ex}")

    return results


# === output/export ===========================================================
def output_results(results):
    if not results:
        console.print("[red]No matching rules found.[/red]")
        return
    t = Table(title="Panorama Rule UUID Lookup Results")
    t.add_column("Device Group"); t.add_column("Location")
    t.add_column("Rule Name"); t.add_column("UUID")
    for r in results:
        t.add_row(r["device_group"], r["location"], r["name"], r["uuid"])
    console.print(t)

    out_path = Path("rule_uuid_lookup.csv")
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["device_group","location","name","uuid"])
        w.writeheader(); w.writerows(results)
    console.print(f"[green]✓ Exported results to {out_path.resolve()}[/green]")


# === main ===================================================================
def main():
    console.print("[bold cyan]=== Panorama Rule UUID Lookup (v1.3.1 – Classic Path) ===[/bold cyan]\n")

    auth = get_panorama_token()
    host, token, is_rest, verify = auth["host"], auth["token"], auth["is_rest"], auth["verify"]

    list_file = console.input("Path to rule list file (default: rule_list.txt): ").strip() or "rule_list.txt"
    if not Path(list_file).exists():
        console.print(f"[red]File not found:[/red] {list_file}")
        sys.exit(1)

    with open(list_file, "r", encoding="utf-8") as f:
        rule_names = [line.strip().lower() for line in f if line.strip()]
    console.print(f"[cyan]Loaded {len(rule_names)} rule names from file.[/cyan]\n")

    results = find_rule_uuids(host, token, verify, set(rule_names), is_rest)
    output_results(results)
    console.print("[bold green]Lookup complete.[/bold green]")


if __name__ == "__main__":
    main()
