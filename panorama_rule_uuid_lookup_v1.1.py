#!/usr/bin/env python3
# Version: 1.1-panorama-rule-uuid-lookup
"""
Panorama Rule UUID Lookup (with Shared Rules)
---------------------------------------------
Reads a list of rule names from a text file and searches across
all device-groups *and shared pre/post rulebases* on a Panorama.
Outputs the rule UUIDs in a human-readable table and CSV file.

Security model:
  • Runtime credential prompts (no stored passwords)
  • Optional SSL verification
  • Safe XML parsing with defusedxml
  • Rich table + CSV export
"""

import requests, urllib3, getpass, csv, sys
from pathlib import Path
from defusedxml import ElementTree as ET
from rich.console import Console
from rich.table import Table

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === API helpers ============================================================
def get_api_key(host: str, user: str, pw: str, verify: bool) -> str:
    url = f"{host.rstrip('/')}/api/"
    r = requests.get(url, params={"type": "keygen", "user": user, "password": pw},
                     verify=verify, timeout=20)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    key = root.findtext(".//key")
    if not key:
        raise RuntimeError("Login failed – no key returned.")
    return key


def api_get(host: str, key: str, xpath: str, verify: bool):
    url = f"{host.rstrip('/')}/api/"
    r = requests.get(url, params={"type": "config", "action": "get",
                                  "xpath": xpath, "key": key},
                     verify=verify, timeout=60)
    r.raise_for_status()
    return ET.fromstring(r.text)


def get_device_groups(host: str, key: str, verify: bool):
    xpath = "/config/devices/entry/device-group"
    xml = api_get(host, key, xpath, verify)
    return [e.get("name") for e in xml.findall(".//entry")]


# === rule search ============================================================
def find_rule_uuids(host, key, verify, rule_names):
    results = []

    # shared pre/post first
    console.print("[bold cyan]Scanning Shared Pre/Post Rules[/bold cyan]")
    shared_bases = {
        "shared-pre": "/config/shared/pre-rulebase/security/rules",
        "shared-post": "/config/shared/post-rulebase/security/rules"
    }
    for label, xpath in shared_bases.items():
        try:
            xml = api_get(host, key, xpath, verify)
            entries = xml.findall(".//entry")
            for e in entries:
                name = e.get("name", "")
                uuid = e.get("uuid", "")
                if name.lower() in rule_names:
                    results.append({
                        "device_group": "shared",
                        "location": label,
                        "name": name,
                        "uuid": uuid
                    })
        except Exception as ex:
            console.print(f"[yellow]Warning:[/yellow] shared {label}: {ex}")

    # now device groups
    dgs = get_device_groups(host, key, verify)
    if not dgs:
        console.print("[red]No device groups found on Panorama.[/red]")
        return results

    for dg in dgs:
        console.print(f"[bold cyan]Scanning device group:[/bold cyan] {dg}")
        for section in ("pre-rulebase", "post-rulebase"):
            xpath = f"/config/devices/entry/device-group/entry[@name='{dg}']/{section}/security/rules"
            try:
                xml = api_get(host, key, xpath, verify)
                entries = xml.findall(".//entry")
                for e in entries:
                    name = e.get("name", "")
                    uuid = e.get("uuid", "")
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


# === output/export ==========================================================
def output_results(results):
    if not results:
        console.print("[red]No matching rules found.[/red]")
        return

    t = Table(title="Panorama Rule UUID Lookup Results")
    t.add_column("Device Group")
    t.add_column("Location")
    t.add_column("Rule Name")
    t.add_column("UUID")

    for r in results:
        t.add_row(r["device_group"], r["location"], r["name"], r["uuid"])

    console.print(t)

    out_path = Path("rule_uuid_lookup.csv")
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["device_group","location","name","uuid"])
        w.writeheader()
        w.writerows(results)
    console.print(f"[green]✓ Exported results to {out_path.resolve()}[/green]")


# === main ===================================================================
def main():
    console.print("[bold cyan]=== Panorama Rule UUID Lookup (v1.1 – with Shared Rules) ===[/bold cyan]\n")
    host = console.input("Panorama URL (e.g. https://192.168.0.190): ").strip()
    if not host.startswith("http"): host = "https://" + host
    user = console.input("Username: ").strip()
    pw = getpass.getpass("Password: ")
    skip_verify = console.input("Skip SSL verification? (y/N): ").lower().startswith("y")
    verify = not skip_verify
    if skip_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    list_file = console.input("Path to rule list file (default: rule_list.txt): ").strip() or "rule_list.txt"
    if not Path(list_file).exists():
        console.print(f"[red]File not found:[/red] {list_file}")
        sys.exit(1)

    with open(list_file, "r", encoding="utf-8") as f:
        rule_names = [line.strip().lower() for line in f if line.strip()]
    console.print(f"[cyan]Loaded {len(rule_names)} rule names from file.[/cyan]\n")

    console.print("[bold]Authenticating...[/bold]")
    key = get_api_key(host, user, pw, verify)
    console.print("[green]Login successful.[/green]\n")

    results = find_rule_uuids(host, key, verify, set(rule_names))
    output_results(results)
    console.print("[bold green]Lookup complete.[/bold green]")


if __name__ == "__main__":
    main()
