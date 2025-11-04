# Mode44 Panorama Rule UUID Lookup

**Author:** Laurence Curling — Mode44 Ltd  
**License:** MIT  
**Status:** Public / Read-only / Production-ready  

---

## 🧠 Overview

The **Mode44 Panorama Rule UUID Lookup** utility connects securely to a Palo Alto Networks **Panorama** management server and extracts rule UUIDs by rule name.

This tool is designed for auditors, analysts, and engineers who need to correlate security policy names with unique UUIDs across **Shared** and **Device-Group** rulebases.

It is a **read-only** automation utility following the Mode44 secure-coding standard:
- No credentials are stored.
- SSL verification optional (for labs).
- Safe XML parsing with `defusedxml`.
- Rich human-readable terminal output.
- Exportable CSV reports.

---

## ⚙️ Features

| Feature | Description |
|----------|--------------|
| 🔐 Secure dual authentication | Supports classic **XML API keygen** (username/password) and **REST_API_TOKEN** (future SCM/11.1+). |
| 📂 Multi-rulebase search | Scans **Shared Pre/Post** and all **Device-Group** Security rulebases. |
| 🧾 CSV export | Writes results to `rule_uuid_lookup.csv` with columns for DG, location, rule name, and UUID. |
| 🧱 Safe parsing | Uses `defusedxml` to eliminate XML entity exploits. |
| 🧰 Portable | Runs on any host with Python ≥ 3.8 and `requests`, `rich`. |

---

## 🧩 Requirements

Install dependencies:

```bash
python3 -m pip install requests defusedxml rich
