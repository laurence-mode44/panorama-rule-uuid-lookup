# Mode44 Panorama Rule UUID Lookup

**Version:** v1.1  
**Author:** Laurence Curling — Mode44 Ltd  
**License:** MIT  
**Status:** Public, read-only, educational + operational use

---

## 🧠 Overview

The **Mode44 Panorama Rule UUID Lookup** is a secure, read-only Python utility for
extracting rule UUIDs from a **Palo Alto Networks Panorama** configuration.  
It searches every **device group** and **shared pre/post rulebase** for any rule
names listed in a local text file, then outputs a formatted table and CSV report.

This project follows the **Mode44 Secure Automation Framework**:
- No credentials are stored
- Authentication prompts at runtime
- Optional SSL verification toggle
- XML safely parsed with `defusedxml`
- Exports human-readable and machine-readable reports

---

## ⚙️ Features

- ✅ Searches **shared pre/post** and **device-group** security rulebases  
- ✅ Reads rule names from a plain-text file (`rule_list.txt`)  
- ✅ Prints UUIDs in a Rich-formatted table  
- ✅ Exports full results to `rule_uuid_lookup.csv`  
- ✅ No write operations — read-only API queries  
- ✅ Uses strong Python security practices (SSL toggle, safe XML, runtime auth)

---

## 🧰 Requirements

- Python 3.8+  
- `requests`, `defusedxml`, `rich` (install via pip)

```bash
python3 -m pip install requests defusedxml rich
