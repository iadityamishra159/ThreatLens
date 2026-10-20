# 🔍 ThreatLens — Cyber Threat Intelligence Analyzer

> A professional, single-file Python cybersecurity application for investigating
> Indicators of Compromise (IOCs) using the VirusTotal threat intelligence platform.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B?logo=streamlit&logoColor=white)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-394EFF?logo=virustotal&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e)

---

## Overview

ThreatLens queries the [VirusTotal](https://www.virustotal.com) threat intelligence
platform to retrieve reputation and multi-engine detection data for the four major IOC
categories used in day-to-day security investigations:

| IOC Category | Examples |
|---|---|
| IPv4 / IPv6 addresses | `8.8.8.8`, `2606:4700:4700::1111` |
| Domain names | `malicious-domain.example` |
| HTTP / HTTPS URLs | `https://example.com/path?q=1` |
| File hashes | MD5 · SHA-1 · SHA-256 |

The application runs fully without an API key in **Demonstration Mode**, making it
suitable for offline portfolio demos and screencasts.

---

## Features

- **Live IOC analysis** via the VirusTotal v3 API
- **Automatic type detection** — no need to specify what you are analyzing
- **Color-coded risk classification** — Malicious · Suspicious · Clean · Inconclusive
- **Interactive charts** — detection donut chart and per-engine verdict bar chart (Plotly)
- **Recommended defensive actions** tailored to the risk level and IOC type
- **Downloadable reports** in CSV, JSON, and PDF (ReportLab) formats
- **Local investigation history** stored in SQLite with full search and filtering
- **Demonstration mode** — clearly labelled sample data when no API key is present
- **Privacy notices** before every external lookup
- Professional blue-and-white Streamlit dashboard

---

## Requirements

- Python **3.11** or later
- Internet connection for live API lookups
- VirusTotal API key (free tier: 4 requests/min, 500/day) — optional

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/threatlens.git
cd threatlens

# 2. (Recommended) Create and activate a virtual environment
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Configuration

### VirusTotal API Key

ThreatLens reads the API key from the `VIRUSTOTAL_API_KEY` environment variable.
The key is **never** stored in the database, written to disk, or shown in the UI.

**Windows PowerShell — current session only:**

```powershell
$env:VIRUSTOTAL_API_KEY = "your_api_key_here"
```

**Windows — persistent user environment variable:**

```powershell
[System.Environment]::SetEnvironmentVariable(
    "VIRUSTOTAL_API_KEY", "your_api_key_here", "User"
)
# Restart your terminal for the change to take effect.
```

**macOS / Linux:**

```bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

**Streamlit secrets (alternative):**

Create `.streamlit/secrets.toml` in the project root:

```toml
VIRUSTOTAL_API_KEY = "your_api_key_here"
```

> Get a free API key at [virustotal.com](https://www.virustotal.com) → sign up → API key.

---

## Running the Application

```bash
streamlit run app.py
```

The dashboard opens automatically at `http://localhost:8501`.

### Demonstration Mode

Run without setting `VIRUSTOTAL_API_KEY`:

```bash
streamlit run app.py
```

The app starts in **Demonstration Mode**. Every analysis returns clearly labelled
sample data — one distinct dataset per IOC type. A blue info banner in the UI and
a warning label in every downloaded report make it unambiguous that no live API
call was made.

---

## Project Structure

```
threatlens/
├── app.py                  # Complete application — single source file
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── LICENSE.md               # License file
```

> `threatlens_history.db` is generated automatically at runtime. Add it to `.gitignore`
> to avoid committing local investigation data.

---

## Architecture

All application logic lives in [`app.py`](app.py) (≈ 1,450 lines), organized into
eight clearly separated layers:

```
app.py
├── Constants & configuration
├── Database layer          — SQLite via stdlib sqlite3
├── Indicator validation    — classify_indicator()
├── VirusTotal API          — lookup_virustotal()
├── Demonstration mode      — get_demo_result()
├── Risk engine             — classify_risk(), get_recommended_actions()
├── Report generation       — build_csv/json/pdf_report()
└── Streamlit dashboard     — render_*() + main()
```

### Risk Classification Rules

| Condition | Risk Level |
|---|---|
| ≥ 3 malicious engines | **Malicious** |
| 1–2 malicious engines OR ≥ 2 suspicious engines | **Suspicious** |
| 0 malicious + 0 suspicious engines | **No Significant Detections** |
| 0 total engine results | **Inconclusive** |
| API lookup failed | **Lookup Failed** |

Thresholds are defined as named constants in `app.py` and can be adjusted.

---

## API Reference

ThreatLens uses the **VirusTotal v3 REST API**:

| IOC Type | Endpoint |
|---|---|
| IPv4 / IPv6 | `GET /api/v3/ip_addresses/{ip}` |
| Domain | `GET /api/v3/domains/{domain}` |
| URL | `GET /api/v3/urls/{base64url_id}` |
| File hash | `GET /api/v3/files/{hash}` |

URLs are encoded as base64url (no padding) per the VirusTotal v3 specification.

---

## Security & Privacy Notes

- API keys are read from environment variables and **never** stored, logged, or displayed.
- Only hash strings are accepted for file investigations — no files are uploaded or executed.
- URLs are submitted as strings for reputation lookup — they are never opened or fetched.
- SQLite stores only metadata (indicator, type, risk level, counts, timestamp) — no raw API
  response payloads, no credentials.
- A privacy notice is displayed before every external lookup.

---

## Limitations

- **Not exhaustive.** Zero detections do not guarantee an indicator is safe.
- **Data staleness.** Results reflect the last time VirusTotal analyzed the indicator,
  which may be days or weeks ago.
- **Free tier rate limits.** 4 requests per minute and 500 per day on the free API plan.
- **No ML / behavioral analysis.** ThreatLens uses reputation and signature-based data
  from VirusTotal's aggregated engine results only.
- **Single provider.** The architecture supports adding further providers (e.g. AlienVault
  OTX) as future extensions.

---

## Dependencies

| Package | Purpose | Minimum Version |
|---|---|---|
| [Streamlit](https://streamlit.io) | Interactive web dashboard | 1.32.0 |
| [Requests](https://docs.python-requests.org) | HTTP API client | 2.31.0 |
| [Pandas](https://pandas.pydata.org) | Data processing and tables | 2.0.0 |
| [Plotly](https://plotly.com/python) | Interactive charts | 5.18.0 |
| [ReportLab](https://www.reportlab.com) | PDF report generation | 4.0.0 |

All other imports (`sqlite3`, `ipaddress`, `re`, `base64`, `csv`, `io`, `json`,
`os`, `time`, `urllib`, `datetime`, `typing`) are Python standard library modules.

---

## License

This project is licensed under the [MIT License](LICENSE.md).

---

## Disclaimer

ThreatLens is an independent cybersecurity research and portfolio project.
Threat intelligence data is sourced from VirusTotal and may be incomplete,
delayed, or inaccurate. This tool does not constitute professional security
or legal advice. Always validate findings with multiple sources and apply
analyst judgment before taking action.
