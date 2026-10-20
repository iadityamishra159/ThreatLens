"""
ThreatLens — Cyber Threat Intelligence Analyzer
================================================
A professional cybersecurity application for investigating Indicators of
Compromise (IOCs) using the VirusTotal threat intelligence platform.

Supports: IP addresses, domain names, URLs, and file hashes (MD5/SHA-1/SHA-256).

Usage:
    streamlit run app.py

API key (optional — runs in demonstration mode without one):
    Windows:  $env:VIRUSTOTAL_API_KEY = "your_key_here"
    Linux/Mac: export VIRUSTOTAL_API_KEY="your_key_here"
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import sqlite3
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Optional

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_TITLE = "ThreatLens"
APP_SUBTITLE = "Cyber Threat Intelligence Analyzer"
APP_VERSION = "1.0.0"
DB_PATH = "threatlens_history.db"

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_PROVIDER_NAME = "VirusTotal"
VT_TIMEOUT = 20  # seconds

INDICATOR_TYPES = {
    "ipv4": "IPv4 Address",
    "ipv6": "IPv6 Address",
    "domain": "Domain Name",
    "url": "URL",
    "md5": "MD5 Hash",
    "sha1": "SHA-1 Hash",
    "sha256": "SHA-256 Hash",
}

RISK_LEVELS = {
    "malicious": {"label": "MALICIOUS", "color": "#c0392b", "bg": "#fde8e8", "icon": "🔴"},
    "suspicious": {"label": "SUSPICIOUS", "color": "#e67e22", "bg": "#fef3e2", "icon": "🟠"},
    "clean": {"label": "NO SIGNIFICANT DETECTIONS", "color": "#27ae60", "bg": "#e8f8f0", "icon": "🟢"},
    "inconclusive": {"label": "INCONCLUSIVE", "color": "#2980b9", "bg": "#e8f4fd", "icon": "🔵"},
    "failed": {"label": "LOOKUP FAILED", "color": "#7f8c8d", "bg": "#f4f6f7", "icon": "⚪"},
}

# Thresholds for risk classification
MALICIOUS_THRESHOLD = 3       # ≥ 3 malicious engines → Malicious
SUSPICIOUS_THRESHOLD = 1      # ≥ 1 malicious or ≥ 2 suspicious → Suspicious
SUSPICIOUS_ENGINE_THRESHOLD = 2

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create the investigation history table if it does not exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS investigations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator   TEXT    NOT NULL,
            ioc_type    TEXT    NOT NULL,
            lookup_mode TEXT    NOT NULL,
            provider    TEXT    NOT NULL,
            risk_level  TEXT    NOT NULL,
            malicious   INTEGER DEFAULT 0,
            suspicious  INTEGER DEFAULT 0,
            harmless    INTEGER DEFAULT 0,
            undetected  INTEGER DEFAULT 0,
            total       INTEGER DEFAULT 0,
            timestamp   TEXT    NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_investigation(
    indicator: str,
    ioc_type: str,
    lookup_mode: str,
    provider: str,
    risk_level: str,
    stats: dict[str, int],
    timestamp: str,
) -> None:
    """Persist an investigation record to SQLite."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO investigations
            (indicator, ioc_type, lookup_mode, provider, risk_level,
             malicious, suspicious, harmless, undetected, total, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            indicator,
            ioc_type,
            lookup_mode,
            provider,
            risk_level,
            stats.get("malicious", 0),
            stats.get("suspicious", 0),
            stats.get("harmless", 0),
            stats.get("undetected", 0),
            stats.get("total", 0),
            timestamp,
        ),
    )
    conn.commit()
    conn.close()


def load_history() -> pd.DataFrame:
    """Load all investigation records as a DataFrame."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT * FROM investigations ORDER BY id DESC", conn
    )
    conn.close()
    return df


def clear_history() -> None:
    """Delete all rows from the investigations table."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM investigations")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Indicator validation and classification
# ---------------------------------------------------------------------------

# Compiled patterns
_RE_MD5    = re.compile(r"^[0-9a-fA-F]{32}$")
_RE_SHA1   = re.compile(r"^[0-9a-fA-F]{40}$")
_RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)


def classify_indicator(raw: str) -> tuple[str, str, str]:
    """
    Identify the type of an IOC string.

    Returns:
        (normalized_indicator, ioc_type_key, error_message)
        ioc_type_key is empty string on error.
    """
    indicator = raw.strip()

    if not indicator:
        return "", "", "Input is empty."

    # URL — must come before domain check
    if indicator.lower().startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(indicator)
        if parsed.netloc:
            return indicator, "url", ""
        return indicator, "", "URL appears malformed (no host found)."

    # IPv4 / IPv6
    try:
        addr = ipaddress.ip_address(indicator)
        if isinstance(addr, ipaddress.IPv4Address):
            return indicator, "ipv4", ""
        return indicator, "ipv6", ""
    except ValueError:
        pass

    # File hashes
    if _RE_SHA256.match(indicator):
        return indicator.lower(), "sha256", ""
    if _RE_SHA1.match(indicator):
        return indicator.lower(), "sha1", ""
    if _RE_MD5.match(indicator):
        return indicator.lower(), "md5", ""

    # Domain
    if _RE_DOMAIN.match(indicator):
        return indicator.lower(), "domain", ""

    return indicator, "", (
        "Could not identify the indicator type. "
        "Expected an IPv4/IPv6 address, domain name, HTTP/HTTPS URL, "
        "or MD5/SHA-1/SHA-256 hash."
    )


# ---------------------------------------------------------------------------
# VirusTotal API integration
# ---------------------------------------------------------------------------

def _vt_headers(api_key: str) -> dict[str, str]:
    return {"x-apikey": api_key, "Accept": "application/json"}


def _vt_request(url: str, api_key: str) -> tuple[Optional[dict], str]:
    """
    Perform a GET request to the VirusTotal v3 API.

    Returns:
        (response_data_or_None, error_message)
    """
    try:
        resp = requests.get(url, headers=_vt_headers(api_key), timeout=VT_TIMEOUT)
        if resp.status_code == 200:
            return resp.json(), ""
        if resp.status_code == 401:
            return None, "Invalid API key (HTTP 401). Check your VIRUSTOTAL_API_KEY."
        if resp.status_code == 404:
            return None, "Indicator not found in VirusTotal database (HTTP 404)."
        if resp.status_code == 429:
            return None, "VirusTotal API rate limit reached (HTTP 429). Wait and retry."
        return None, f"VirusTotal returned HTTP {resp.status_code}."
    except requests.exceptions.Timeout:
        return None, f"Request timed out after {VT_TIMEOUT}s. Check your connection."
    except requests.exceptions.ConnectionError:
        return None, "Connection error. Check your internet connection."
    except requests.exceptions.RequestException as exc:
        return None, f"Request failed: {exc}"


def lookup_virustotal(indicator: str, ioc_type: str, api_key: str) -> dict[str, Any]:
    """
    Query VirusTotal for an IOC and return a normalized result dict.

    The result dict always contains:
        success, provider, lookup_mode, indicator, ioc_type,
        error, raw_stats, last_analysis_date, reputation,
        engine_results, total_engines
    """
    result: dict[str, Any] = {
        "success": False,
        "provider": VT_PROVIDER_NAME,
        "lookup_mode": "live",
        "indicator": indicator,
        "ioc_type": ioc_type,
        "error": "",
        "raw_stats": {},
        "last_analysis_date": None,
        "reputation": None,
        "engine_results": {},
        "total_engines": 0,
    }

    if ioc_type in ("ipv4", "ipv6"):
        url = f"{VT_BASE_URL}/ip_addresses/{urllib.parse.quote(indicator, safe='')}"
    elif ioc_type == "domain":
        url = f"{VT_BASE_URL}/domains/{urllib.parse.quote(indicator, safe='')}"
    elif ioc_type == "url":
        # VirusTotal v3: URL ID = base64url(url) without padding
        url_id = base64.urlsafe_b64encode(indicator.encode()).rstrip(b"=").decode()
        url = f"{VT_BASE_URL}/urls/{url_id}"
    elif ioc_type in ("md5", "sha1", "sha256"):
        url = f"{VT_BASE_URL}/files/{indicator}"
    else:
        result["error"] = f"Unsupported indicator type: {ioc_type}"
        return result

    data, error = _vt_request(url, api_key)
    if error:
        result["error"] = error
        return result

    try:
        attrs = data["data"]["attributes"]

        # Last analysis stats
        stats = attrs.get("last_analysis_stats", {})
        result["raw_stats"] = {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout":    stats.get("timeout", 0),
        }
        total = sum(result["raw_stats"].values())
        result["total_engines"] = total

        # Last analysis date
        ts = attrs.get("last_analysis_date") or attrs.get("last_modification_date")
        if ts:
            result["last_analysis_date"] = datetime.fromtimestamp(
                int(ts), tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Reputation score (IP/domain only)
        result["reputation"] = attrs.get("reputation")

        # Per-engine results (first 50 engines that made a verdict)
        engines = attrs.get("last_analysis_results", {})
        condensed: dict[str, str] = {}
        for engine, detail in engines.items():
            cat = detail.get("category", "undetected")
            if cat in ("malicious", "suspicious"):
                condensed[engine] = cat
        result["engine_results"] = condensed

        result["success"] = True
    except (KeyError, TypeError, ValueError) as exc:
        result["error"] = f"Unexpected response format from VirusTotal: {exc}"

    return result


# ---------------------------------------------------------------------------
# Demonstration mode — realistic but clearly labelled sample data
# ---------------------------------------------------------------------------

_DEMO_SAMPLES: dict[str, dict[str, Any]] = {
    "ipv4": {
        "raw_stats": {"malicious": 15, "suspicious": 2, "harmless": 63, "undetected": 10, "timeout": 0},
        "reputation": -42,
        "last_analysis_date": "2024-11-15 08:30:00 UTC",
        "engine_results": {
            "Abusix": "malicious", "AlphaSOC": "malicious", "G-Data": "malicious",
            "Webroot": "suspicious", "CRDF": "malicious",
        },
        "total_engines": 90,
    },
    "ipv6": {
        "raw_stats": {"malicious": 0, "suspicious": 1, "harmless": 55, "undetected": 20, "timeout": 0},
        "reputation": 0,
        "last_analysis_date": "2024-11-10 14:22:00 UTC",
        "engine_results": {"Webroot": "suspicious"},
        "total_engines": 76,
    },
    "domain": {
        "raw_stats": {"malicious": 5, "suspicious": 3, "harmless": 55, "undetected": 15, "timeout": 0},
        "reputation": -18,
        "last_analysis_date": "2024-11-12 10:00:00 UTC",
        "engine_results": {
            "Fortinet": "malicious", "Sophos": "malicious", "Kaspersky": "malicious",
            "BitDefender": "suspicious", "TrendMicro": "suspicious",
        },
        "total_engines": 78,
    },
    "url": {
        "raw_stats": {"malicious": 8, "suspicious": 1, "harmless": 57, "undetected": 8, "timeout": 0},
        "reputation": None,
        "last_analysis_date": "2024-11-14 16:45:00 UTC",
        "engine_results": {
            "ESET": "malicious", "Kaspersky": "malicious", "Avira": "malicious",
            "Google Safebrowsing": "malicious", "Sophos": "suspicious",
        },
        "total_engines": 74,
    },
    "md5": {
        "raw_stats": {"malicious": 52, "suspicious": 4, "harmless": 0, "undetected": 14, "timeout": 2},
        "reputation": None,
        "last_analysis_date": "2024-11-13 09:15:00 UTC",
        "engine_results": {
            "CrowdStrike": "malicious", "SentinelOne": "malicious", "Kaspersky": "malicious",
            "Sophos": "malicious", "ESET-NOD32": "malicious",
        },
        "total_engines": 72,
    },
    "sha1": {
        "raw_stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 68, "timeout": 0},
        "reputation": None,
        "last_analysis_date": "2024-10-29 11:00:00 UTC",
        "engine_results": {},
        "total_engines": 68,
    },
    "sha256": {
        "raw_stats": {"malicious": 2, "suspicious": 1, "harmless": 0, "undetected": 64, "timeout": 1},
        "reputation": None,
        "last_analysis_date": "2024-11-11 07:30:00 UTC",
        "engine_results": {"Avira": "malicious", "ClamAV": "malicious", "Webroot": "suspicious"},
        "total_engines": 68,
    },
}


def get_demo_result(indicator: str, ioc_type: str) -> dict[str, Any]:
    """Return a clearly labelled demonstration result for the given IOC type."""
    sample = _DEMO_SAMPLES.get(ioc_type, _DEMO_SAMPLES["domain"])
    stats = sample["raw_stats"].copy()
    return {
        "success": True,
        "provider": VT_PROVIDER_NAME,
        "lookup_mode": "demonstration",
        "indicator": indicator,
        "ioc_type": ioc_type,
        "error": "",
        "raw_stats": stats,
        "last_analysis_date": sample["last_analysis_date"],
        "reputation": sample["reputation"],
        "engine_results": sample["engine_results"].copy(),
        "total_engines": sample["total_engines"],
    }


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------

def classify_risk(result: dict[str, Any]) -> tuple[str, str]:
    """
    Determine a risk level key and a plain-English explanation.

    Returns:
        (risk_level_key, explanation)
    """
    if not result.get("success"):
        return "failed", f"Lookup did not complete. Reason: {result.get('error', 'Unknown error.')}"

    stats = result.get("raw_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = result.get("total_engines", 0)

    if total == 0:
        return "inconclusive", (
            "No analysis engines reported results. "
            "The indicator may not yet have been analyzed by this provider."
        )

    if malicious >= MALICIOUS_THRESHOLD:
        return "malicious", (
            f"{malicious} out of {total} analysis engines flagged this indicator as malicious. "
            f"This exceeds the classification threshold of {MALICIOUS_THRESHOLD}. "
            "Treat this indicator as a confirmed threat and take immediate defensive action."
        )

    if malicious > 0 or suspicious >= SUSPICIOUS_ENGINE_THRESHOLD:
        return "suspicious", (
            f"{malicious} engine(s) flagged this as malicious and "
            f"{suspicious} as suspicious (out of {total} total). "
            "This indicator should be treated with caution. "
            "Investigate further before trusting or allowing this resource."
        )

    if malicious == 0 and suspicious == 0:
        return "clean", (
            f"None of the {total} analysis engines reported malicious or suspicious activity. "
            "Note: Absence of detections does not guarantee safety. "
            "Threat intelligence coverage is not exhaustive and may be outdated."
        )

    return "inconclusive", (
        f"{malicious} malicious and {suspicious} suspicious detections were observed "
        f"out of {total} engines. The evidence is insufficient for a definitive verdict."
    )


def get_recommended_actions(risk_level: str, ioc_type: str) -> list[str]:
    """Return defensive action recommendations based on risk level and IOC type."""
    base: list[str] = []

    if risk_level == "malicious":
        base = [
            "Block this indicator immediately at your perimeter firewall and endpoint controls.",
            "Search your SIEM / log management platform for historical connections to this indicator.",
            "Isolate any systems that have recently communicated with this indicator.",
            "Escalate to your incident response team for further investigation.",
            "Add the indicator to your threat intelligence blocklists and EDR exclusion rules.",
        ]
        if ioc_type == "url":
            base.append("Report the URL to your web proxy / DNS filtering solution for blocking.")
        elif ioc_type in ("ipv4", "ipv6"):
            base.append("Create ACL or firewall rules to deny all traffic to/from this IP.")
        elif ioc_type == "domain":
            base.append("Configure your DNS resolver to block or sinkhole this domain.")
        elif ioc_type in ("md5", "sha1", "sha256"):
            base.append("Quarantine and submit the file to your AV/EDR platform for analysis.")

    elif risk_level == "suspicious":
        base = [
            "Investigate all recent connections or references to this indicator in your environment.",
            "Consider blocking as a precaution until further analysis clears the indicator.",
            "Cross-reference with additional threat intelligence sources for corroboration.",
            "Alert your security operations team for monitoring.",
        ]

    elif risk_level == "clean":
        base = [
            "No immediate action required based on current threat intelligence.",
            "Continue standard monitoring practices.",
            "Re-evaluate if additional context or new intelligence changes the risk profile.",
            "Remember: a clean result does not guarantee the indicator is safe.",
        ]

    elif risk_level == "inconclusive":
        base = [
            "Gather additional context from other threat intelligence sources.",
            "Apply the principle of least privilege — restrict access until the indicator is cleared.",
            "Monitor for unusual activity related to this indicator.",
        ]

    else:  # failed
        base = [
            "Retry the lookup — the API service may be temporarily unavailable.",
            "Verify your API key is valid and has not exceeded its quota.",
            "Manually investigate the indicator using the VirusTotal web interface.",
        ]

    return base


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_csv_report(result: dict[str, Any], risk_level: str, explanation: str) -> str:
    """Return a CSV string for the investigation result."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "indicator", "ioc_type", "provider", "lookup_mode", "risk_level",
        "malicious", "suspicious", "harmless", "undetected", "total_engines",
        "last_analysis_date", "reputation", "risk_explanation", "timestamp",
    ])
    stats = result.get("raw_stats", {})
    writer.writerow([
        result["indicator"],
        INDICATOR_TYPES.get(result["ioc_type"], result["ioc_type"]),
        result["provider"],
        result["lookup_mode"],
        RISK_LEVELS.get(risk_level, {}).get("label", risk_level),
        stats.get("malicious", 0),
        stats.get("suspicious", 0),
        stats.get("harmless", 0),
        stats.get("undetected", 0),
        result.get("total_engines", 0),
        result.get("last_analysis_date", "N/A"),
        result.get("reputation", "N/A"),
        explanation,
        datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    ])
    return output.getvalue()


def build_json_report(
    result: dict[str, Any],
    risk_level: str,
    explanation: str,
    recommended_actions: list[str],
) -> str:
    """Return a JSON string for the investigation result."""
    stats = result.get("raw_stats", {})
    report = {
        "report_metadata": {
            "application": f"{APP_TITLE} — {APP_SUBTITLE}",
            "version": APP_VERSION,
            "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "lookup_mode": result.get("lookup_mode", "unknown"),
            "disclaimer": (
                "This report was generated by ThreatLens. "
                "Threat intelligence data is provided by external services and "
                "may be incomplete, delayed, or inaccurate. "
                "Do not rely solely on this report for security decisions."
                + (" THIS REPORT CONTAINS DEMONSTRATION DATA — NOT LIVE INTELLIGENCE."
                   if result.get("lookup_mode") == "demonstration" else "")
            ),
        },
        "indicator": {
            "value": result["indicator"],
            "type": INDICATOR_TYPES.get(result["ioc_type"], result["ioc_type"]),
            "type_key": result["ioc_type"],
        },
        "provider": {
            "name": result["provider"],
            "last_analysis_date": result.get("last_analysis_date"),
            "total_engines": result.get("total_engines", 0),
            "reputation_score": result.get("reputation"),
        },
        "analysis_statistics": {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout":    stats.get("timeout", 0),
        },
        "risk_assessment": {
            "risk_level": RISK_LEVELS.get(risk_level, {}).get("label", risk_level),
            "explanation": explanation,
        },
        "flagging_engines": result.get("engine_results", {}),
        "recommended_actions": recommended_actions,
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def build_pdf_report(
    result: dict[str, Any],
    risk_level: str,
    explanation: str,
    recommended_actions: list[str],
) -> bytes:
    """Return a PDF byte string for the investigation result using ReportLab."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    style_normal = styles["Normal"]
    style_normal.fontSize = 10
    style_normal.leading = 15

    # Custom styles
    style_title = ParagraphStyle(
        "TLTitle",
        fontSize=20,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1a3a5c"),
        spaceAfter=4,
    )
    style_subtitle = ParagraphStyle(
        "TLSubtitle",
        fontSize=13,
        fontName="Helvetica",
        textColor=colors.HexColor("#2c6fad"),
        spaceAfter=12,
    )
    style_h2 = ParagraphStyle(
        "TLH2",
        fontSize=12,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1a3a5c"),
        spaceBefore=12,
        spaceAfter=4,
    )
    style_body = ParagraphStyle(
        "TLBody",
        fontSize=10,
        fontName="Helvetica",
        leading=15,
        spaceAfter=6,
    )
    style_disclaimer = ParagraphStyle(
        "TLDisclaimer",
        fontSize=8,
        fontName="Helvetica-Oblique",
        textColor=colors.HexColor("#7f8c8d"),
        leading=12,
    )
    style_demo_banner = ParagraphStyle(
        "TLDemo",
        fontSize=11,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#856404"),
        backColor=colors.HexColor("#fff3cd"),
        spaceBefore=6,
        spaceAfter=6,
        borderPad=6,
    )

    risk_info = RISK_LEVELS.get(risk_level, RISK_LEVELS["inconclusive"])
    stats = result.get("raw_stats", {})
    is_demo = result.get("lookup_mode") == "demonstration"

    flowables = []

    # Header
    flowables.append(Paragraph(APP_TITLE, style_title))
    flowables.append(Paragraph(APP_SUBTITLE, style_subtitle))
    flowables.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2c6fad")))
    flowables.append(Spacer(1, 0.1 * inch))

    # Demo banner
    if is_demo:
        flowables.append(
            Paragraph(
                "⚠  DEMONSTRATION MODE — This report contains simulated data. "
                "No live API lookup was performed.",
                style_demo_banner,
            )
        )

    # Metadata table
    meta_data = [
        ["Report Generated", datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Indicator", result["indicator"]],
        ["Type", INDICATOR_TYPES.get(result["ioc_type"], result["ioc_type"])],
        ["Provider", result["provider"]],
        ["Lookup Mode", result["lookup_mode"].title()],
        ["Last Analysis (Provider)", result.get("last_analysis_date") or "Not available"],
    ]
    meta_table = Table(meta_data, colWidths=[2.2 * inch, 5 * inch])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f0fe")),
            ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",   (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#c5cae9")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f5f7ff")]),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    flowables.append(meta_table)
    flowables.append(Spacer(1, 0.15 * inch))

    # Risk assessment
    flowables.append(Paragraph("Risk Assessment", style_h2))
    risk_color = colors.HexColor(risk_info["color"])
    risk_table = Table(
        [[f'{risk_info["icon"]}  {risk_info["label"]}']],
        colWidths=[7.2 * inch],
    )
    risk_table.setStyle(
        TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor(risk_info["bg"])),
            ("TEXTCOLOR",     (0, 0), (-1, -1), risk_color),
            ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 13),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("BOX",           (0, 0), (-1, -1), 1, risk_color),
        ])
    )
    flowables.append(risk_table)
    flowables.append(Spacer(1, 0.08 * inch))
    flowables.append(Paragraph(explanation, style_body))

    # Detection statistics
    flowables.append(Paragraph("Detection Statistics", style_h2))
    det_data = [
        ["Category", "Count"],
        ["Malicious",  str(stats.get("malicious",  0))],
        ["Suspicious", str(stats.get("suspicious", 0))],
        ["Harmless",   str(stats.get("harmless",   0))],
        ["Undetected", str(stats.get("undetected", 0))],
        ["Timeout",    str(stats.get("timeout",    0))],
        ["Total Engines", str(result.get("total_engines", 0))],
    ]
    if result.get("reputation") is not None:
        det_data.append(["Provider Reputation Score", str(result["reputation"])])
    det_table = Table(det_data, colWidths=[3.5 * inch, 3.7 * inch])
    det_table.setStyle(
        TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a3a5c")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#c5cae9")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7ff")]),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    flowables.append(det_table)

    # Flagging engines
    engines = result.get("engine_results", {})
    if engines:
        flowables.append(Paragraph("Engines Flagging This Indicator", style_h2))
        eng_data = [["Engine", "Verdict"]] + [[e, v.title()] for e, v in engines.items()]
        eng_table = Table(eng_data, colWidths=[3.5 * inch, 3.7 * inch])
        eng_table.setStyle(
            TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a3a5c")),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE",      (0, 0), (-1, -1), 9),
                ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#c5cae9")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7ff")]),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        flowables.append(eng_table)

    # Recommended actions
    flowables.append(Paragraph("Recommended Defensive Actions", style_h2))
    for i, action in enumerate(recommended_actions, 1):
        flowables.append(Paragraph(f"{i}. {action}", style_body))

    # Disclaimer
    flowables.append(Spacer(1, 0.2 * inch))
    flowables.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7")))
    flowables.append(Spacer(1, 0.05 * inch))
    disclaimer = (
        "Privacy & Accuracy Disclaimer: ThreatLens submits indicators to external "
        "threat intelligence services. Results may be incomplete, delayed, or inaccurate. "
        "This report does not constitute professional legal or compliance advice. "
        "Always validate findings with additional sources before taking action. "
        + ("THIS REPORT CONTAINS DEMONSTRATION DATA ONLY — NOT LIVE INTELLIGENCE. "
           if is_demo else "")
    )
    flowables.append(Paragraph(disclaimer, style_disclaimer))

    doc.build(flowables)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Helper UI components
# ---------------------------------------------------------------------------

def render_risk_badge(risk_level: str) -> None:
    """Render a colour-coded risk badge using st.markdown."""
    info = RISK_LEVELS.get(risk_level, RISK_LEVELS["inconclusive"])
    st.markdown(
        f"""
        <div style="
            display:inline-block;
            background:{info['bg']};
            color:{info['color']};
            border:2px solid {info['color']};
            border-radius:6px;
            padding:8px 20px;
            font-weight:700;
            font-size:1.1em;
            letter-spacing:0.05em;
        ">
            {info['icon']} {info['label']}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_stat_card(label: str, value: int | str, color: str = "#1a3a5c") -> None:
    """Render a small metric card."""
    st.markdown(
        f"""
        <div style="
            background:#f7f9fc;
            border-left:4px solid {color};
            border-radius:4px;
            padding:10px 14px;
            margin-bottom:4px;
        ">
            <div style="font-size:0.78em;color:#57606a;font-weight:600;
                        text-transform:uppercase;letter-spacing:0.04em;">{label}</div>
            <div style="font-size:1.5em;font-weight:700;color:{color};">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def make_detection_chart(stats: dict[str, int]) -> go.Figure:
    """Return a Plotly donut chart of detection statistics."""
    labels = ["Malicious", "Suspicious", "Harmless", "Undetected"]
    values = [
        stats.get("malicious",  0),
        stats.get("suspicious", 0),
        stats.get("harmless",   0),
        stats.get("undetected", 0),
    ]
    chart_colors = ["#c0392b", "#e67e22", "#27ae60", "#95a5a6"]

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.5,
            marker=dict(colors=chart_colors, line=dict(color="#ffffff", width=2)),
            hovertemplate="%{label}: %{value} engine(s)<extra></extra>",
        )
    )
    fig.update_layout(
        margin=dict(t=10, b=10, l=10, r=10),
        legend=dict(orientation="v", x=1.0, y=0.5),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=280,
        showlegend=True,
        font=dict(family="sans-serif", size=12),
    )
    return fig


def make_engine_bar_chart(engine_results: dict[str, str]) -> go.Figure:
    """Return a Plotly horizontal bar chart of flagging engines."""
    malicious_engines  = [e for e, v in engine_results.items() if v == "malicious"]
    suspicious_engines = [e for e, v in engine_results.items() if v == "suspicious"]

    all_engines = malicious_engines + suspicious_engines
    colors_list = ["#c0392b"] * len(malicious_engines) + ["#e67e22"] * len(suspicious_engines)

    fig = go.Figure(
        go.Bar(
            y=all_engines,
            x=[1] * len(all_engines),
            orientation="h",
            marker=dict(color=colors_list),
            hovertemplate="%{y}<extra></extra>",
        )
    )
    fig.update_layout(
        xaxis=dict(visible=False),
        yaxis=dict(tickfont=dict(size=11)),
        margin=dict(t=10, b=10, l=10, r=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=max(200, len(all_engines) * 32),
        showlegend=False,
    )
    return fig


# ---------------------------------------------------------------------------
# Streamlit application
# ---------------------------------------------------------------------------

def get_api_key() -> Optional[str]:
    """Retrieve API key from environment or Streamlit secrets."""
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if key:
        return key
    try:
        key = st.secrets.get("VIRUSTOTAL_API_KEY", "").strip()
        if key:
            return key
    except Exception:
        pass
    return None


def apply_custom_css() -> None:
    """Inject custom CSS for a professional blue-and-white theme."""
    st.markdown(
        """
        <style>
        /* ---- Global ---- */
        html, body, [data-testid="stAppViewContainer"] {
            background-color: #f0f4f8;
        }
        [data-testid="stSidebar"] {
            background-color: #1a3a5c;
        }
        [data-testid="stSidebar"] * {
            color: #e8edf2 !important;
        }
        [data-testid="stSidebar"] .stMarkdown a {
            color: #93c5fd !important;
        }
        /* ---- Header ---- */
        .tl-header {
            background: linear-gradient(135deg, #1a3a5c 0%, #2c6fad 100%);
            color: white;
            padding: 1.5rem 2rem;
            border-radius: 10px;
            margin-bottom: 1.2rem;
        }
        .tl-header h1 {
            margin: 0;
            font-size: 2em;
            font-weight: 800;
            letter-spacing: 0.02em;
        }
        .tl-header p {
            margin: 0.3em 0 0;
            font-size: 1em;
            opacity: 0.85;
        }
        /* ---- Cards ---- */
        .tl-card {
            background: white;
            border-radius: 8px;
            padding: 1.2rem 1.4rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 4px rgba(26,58,92,0.10);
        }
        /* ---- Section headings ---- */
        .tl-section-heading {
            font-size: 1em;
            font-weight: 700;
            color: #1a3a5c;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            border-bottom: 2px solid #2c6fad;
            padding-bottom: 4px;
            margin-bottom: 0.8rem;
        }
        /* ---- Privacy warning ---- */
        .tl-privacy {
            background: #fff3cd;
            border-left: 4px solid #f0ad4e;
            border-radius: 4px;
            padding: 0.7rem 1rem;
            font-size: 0.88em;
            color: #7a5000;
            margin-bottom: 0.8rem;
        }
        /* ---- Demo banner ---- */
        .tl-demo-banner {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            border-radius: 4px;
            padding: 0.6rem 1rem;
            font-size: 0.88em;
            color: #0d47a1;
            margin-bottom: 0.6rem;
        }
        /* ---- Footer ---- */
        .tl-footer {
            text-align: center;
            color: #95a5a6;
            font-size: 0.8em;
            padding: 1.5rem 0 0.5rem;
            border-top: 1px solid #e0e7ef;
            margin-top: 2rem;
        }
        /* ---- Streamlit overrides ---- */
        div[data-testid="stButton"] > button {
            background-color: #2c6fad;
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: 600;
        }
        div[data-testid="stButton"] > button:hover {
            background-color: #1a3a5c;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header() -> None:
    st.markdown(
        f"""
        <div class="tl-header">
            <h1>🔍 {APP_TITLE}</h1>
            <p>{APP_SUBTITLE} &nbsp;·&nbsp; v{APP_VERSION}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar(api_key: Optional[str]) -> None:
    with st.sidebar:
        st.markdown("### 🛡 ThreatLens")
        st.markdown("---")
        if api_key:
            st.success("✅ VirusTotal API key configured")
            st.markdown("**Mode:** Live analysis")
        else:
            st.warning("⚠️ No API key detected")
            st.markdown("**Mode:** Demonstration")
            st.markdown(
                "Set `VIRUSTOTAL_API_KEY` environment variable "
                "to enable live lookups."
            )
        st.markdown("---")
        st.markdown("**Supported IOC Types**")
        for key, label in INDICATOR_TYPES.items():
            st.markdown(f"• {label}")
        st.markdown("---")
        st.markdown("**Providers**")
        st.markdown(f"• {VT_PROVIDER_NAME}")
        st.markdown("---")
        st.markdown(
            '<div style="font-size:0.78em;opacity:0.7;">'
            "ThreatLens uses the VirusTotal public API.<br>"
            "Lookups may disclose submitted indicators to the provider."
            "</div>",
            unsafe_allow_html=True,
        )


def render_analysis_results(result: dict[str, Any]) -> None:
    """Render the complete analysis results section."""
    risk_level, explanation = classify_risk(result)
    recommended = get_recommended_actions(risk_level, result["ioc_type"])
    stats = result.get("raw_stats", {})
    is_demo = result.get("lookup_mode") == "demonstration"

    # Persist to history
    save_investigation(
        indicator=result["indicator"],
        ioc_type=INDICATOR_TYPES.get(result["ioc_type"], result["ioc_type"]),
        lookup_mode=result["lookup_mode"],
        provider=result["provider"],
        risk_level=RISK_LEVELS.get(risk_level, {}).get("label", risk_level),
        stats={
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "total":      result.get("total_engines", 0),
        },
        timestamp=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    # Demo banner
    if is_demo:
        st.markdown(
            '<div class="tl-demo-banner">'
            "ℹ️ <strong>Demonstration Mode</strong> — "
            "The statistics below are simulated sample data. "
            "No live API lookup was performed. "
            "Configure <code>VIRUSTOTAL_API_KEY</code> to enable real analysis."
            "</div>",
            unsafe_allow_html=True,
        )

    # Risk badge
    st.markdown('<div class="tl-section-heading">Risk Classification</div>', unsafe_allow_html=True)
    render_risk_badge(risk_level)
    st.markdown(f"<p style='margin-top:0.7rem;color:#2d3748;'>{explanation}</p>", unsafe_allow_html=True)

    # Summary cards
    st.markdown('<div class="tl-section-heading" style="margin-top:1rem;">Detection Summary</div>', unsafe_allow_html=True)
    cols = st.columns(5)
    card_data = [
        ("Malicious",   stats.get("malicious",  0),  "#c0392b"),
        ("Suspicious",  stats.get("suspicious", 0),  "#e67e22"),
        ("Harmless",    stats.get("harmless",   0),  "#27ae60"),
        ("Undetected",  stats.get("undetected", 0),  "#95a5a6"),
        ("Total Engines", result.get("total_engines", 0), "#2c6fad"),
    ]
    for col, (label, value, color) in zip(cols, card_data):
        with col:
            render_stat_card(label, value, color)

    # Charts
    if result.get("total_engines", 0) > 0:
        st.markdown('<div class="tl-section-heading" style="margin-top:1rem;">Detection Chart</div>', unsafe_allow_html=True)
        c1, c2 = st.columns([1, 1])
        with c1:
            st.plotly_chart(make_detection_chart(stats), use_container_width=True, config={"displayModeBar": False})
        with c2:
            engines = result.get("engine_results", {})
            if engines:
                st.markdown("**Engines flagging this indicator:**")
                st.plotly_chart(make_engine_bar_chart(engines), use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("No engines flagged this indicator as malicious or suspicious.")

    # Technical details
    with st.expander("🔬 Technical Details", expanded=False):
        detail_rows = [
            ("Indicator", result["indicator"]),
            ("Type", INDICATOR_TYPES.get(result["ioc_type"], result["ioc_type"])),
            ("Provider", result["provider"]),
            ("Lookup Mode", result["lookup_mode"].title()),
            ("Last Analysis Date", result.get("last_analysis_date") or "Not available"),
        ]
        if result.get("reputation") is not None:
            detail_rows.append(("Provider Reputation Score", str(result["reputation"])))
        df_detail = pd.DataFrame(detail_rows, columns=["Field", "Value"])
        st.dataframe(df_detail, use_container_width=True, hide_index=True)

        if result.get("engine_results"):
            st.markdown("**Flagging engine verdicts:**")
            eng_df = pd.DataFrame(
                [{"Engine": e, "Verdict": v.title()} for e, v in result["engine_results"].items()]
            )
            st.dataframe(eng_df, use_container_width=True, hide_index=True)

    # Recommended actions
    with st.expander("🛡 Recommended Defensive Actions", expanded=True):
        for i, action in enumerate(recommended, 1):
            st.markdown(f"**{i}.** {action}")

    # Download reports
    st.markdown('<div class="tl-section-heading" style="margin-top:1.2rem;">Download Report</div>', unsafe_allow_html=True)
    d1, d2, d3 = st.columns(3)

    csv_data = build_csv_report(result, risk_level, explanation)
    json_data = build_json_report(result, risk_level, explanation, recommended)
    pdf_data  = build_pdf_report(result, risk_level, explanation, recommended)

    safe_indicator = re.sub(r"[^a-zA-Z0-9._-]", "_", result["indicator"])[:40]
    ts_suffix = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")

    with d1:
        st.download_button(
            "⬇ Download CSV",
            data=csv_data,
            file_name=f"threatlens_{safe_indicator}_{ts_suffix}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            "⬇ Download JSON",
            data=json_data,
            file_name=f"threatlens_{safe_indicator}_{ts_suffix}.json",
            mime="application/json",
            use_container_width=True,
        )
    with d3:
        st.download_button(
            "⬇ Download PDF",
            data=pdf_data,
            file_name=f"threatlens_{safe_indicator}_{ts_suffix}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )


def render_history_section() -> None:
    """Render the investigation history table with search and clear options."""
    st.markdown('<div class="tl-section-heading">Investigation History</div>', unsafe_allow_html=True)

    df = load_history()
    if df.empty:
        st.info("No investigations recorded yet. Analyze an indicator to build history.")
        return

    # Search / filter
    col_search, col_type = st.columns([3, 1])
    with col_search:
        search_term = st.text_input("Search history", placeholder="Filter by indicator…", label_visibility="collapsed")
    with col_type:
        type_filter = st.selectbox(
            "Type filter",
            options=["All types"] + sorted(df["ioc_type"].unique().tolist()),
            label_visibility="collapsed",
        )

    filtered = df.copy()
    if search_term:
        filtered = filtered[filtered["indicator"].str.contains(search_term, case=False, na=False)]
    if type_filter != "All types":
        filtered = filtered[filtered["ioc_type"] == type_filter]

    display_cols = ["timestamp", "indicator", "ioc_type", "lookup_mode", "provider",
                    "risk_level", "malicious", "suspicious", "total"]
    st.dataframe(
        filtered[display_cols].rename(columns={
            "timestamp": "Timestamp", "indicator": "Indicator",
            "ioc_type": "Type", "lookup_mode": "Mode",
            "provider": "Provider", "risk_level": "Risk Level",
            "malicious": "Malicious", "suspicious": "Suspicious", "total": "Total",
        }),
        use_container_width=True,
        hide_index=True,
    )
    st.caption(f"Showing {len(filtered)} of {len(df)} records.")

    if st.button("🗑 Clear all history", type="secondary"):
        clear_history()
        st.success("Investigation history cleared.")
        st.rerun()


def render_about_section() -> None:
    """Render the About & Limitations section."""
    with st.expander("ℹ About ThreatLens & Limitations", expanded=False):
        st.markdown(
            f"""
            **{APP_TITLE} — {APP_SUBTITLE}** (v{APP_VERSION})

            ThreatLens queries the [VirusTotal](https://www.virustotal.com) threat intelligence
            platform to provide reputation and detection data for IP addresses, domain names,
            URLs, and file hashes.

            **Limitations & Disclaimers**

            - **Not exhaustive.** VirusTotal aggregates results from partner security vendors.
              An indicator with zero detections may still be malicious (zero-day, novel threat,
              regional threat, evasion).
            - **Data staleness.** Analysis timestamps reflect when VirusTotal last scanned the
              indicator, not the current moment.
            - **Context matters.** Risk classification thresholds used by ThreatLens are
              heuristic guides, not definitive verdicts. Always apply analyst judgment.
            - **API limits.** The free VirusTotal API tier permits up to 4 lookups per minute
              and 500 per day. Exceeding this will result in rate-limit errors.
            - **Privacy.** Submitting an indicator to ThreatLens may result in that indicator
              being sent to VirusTotal. Do not submit confidential or sensitive indicators
              without appropriate authorization.
            - **No guarantees.** This tool is provided for research and educational purposes.
              It does not constitute professional security advice.

            **Demonstration Mode**

            If no `VIRUSTOTAL_API_KEY` is configured, ThreatLens runs in demonstration mode
            using pre-defined sample data. Demonstration results are clearly labelled and
            should never be treated as real threat intelligence.
            """
        )


# ---------------------------------------------------------------------------
# Main application entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """ThreatLens Streamlit application entry point."""
    st.set_page_config(
        page_title=f"{APP_TITLE} — {APP_SUBTITLE}",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    apply_custom_css()
    init_db()

    api_key = get_api_key()

    render_header()
    render_sidebar(api_key)

    # ---- Main content area -----------------------------------------------
    tab_analyze, tab_history, tab_about = st.tabs(
        ["🔍 Analyze Indicator", "📋 Investigation History", "ℹ About"]
    )

    with tab_analyze:
        # Privacy warning
        st.markdown(
            '<div class="tl-privacy">'
            "⚠️ <strong>Privacy Notice:</strong> Submitting an indicator may disclose it "
            "to the VirusTotal threat intelligence platform. "
            "Do not submit confidential or sensitive indicators without authorization."
            "</div>",
            unsafe_allow_html=True,
        )

        # Provider status
        if api_key:
            st.success(f"✅ **Live Analysis** — Connected to {VT_PROVIDER_NAME} API")
        else:
            st.info(
                f"ℹ️ **Demonstration Mode** — No API key configured. "
                f"Results will use sample data labelled as demonstration. "
                f"Set `VIRUSTOTAL_API_KEY` to enable live lookups."
            )

        st.markdown("---")

        # Input form
        with st.form("indicator_form", clear_on_submit=False):
            indicator_input = st.text_input(
                "Enter an Indicator of Compromise (IOC)",
                placeholder="e.g. 8.8.8.8 · example.com · https://example.com/path · a1b2c3d4…",
                help="Supported: IPv4, IPv6, domain, HTTP/HTTPS URL, MD5, SHA-1, SHA-256",
            )
            submit = st.form_submit_button("🔍 Analyze Indicator", use_container_width=True)

        # Live type detection outside form
        if indicator_input.strip():
            normalized, ioc_type, err = classify_indicator(indicator_input)
            if ioc_type:
                st.markdown(
                    f"**Detected type:** `{INDICATOR_TYPES[ioc_type]}`  "
                    f"&nbsp;|&nbsp; **Normalized:** `{normalized}`"
                )
            else:
                st.warning(f"⚠️ Type detection: {err}")

        # Analysis
        if submit:
            raw_input = indicator_input.strip()
            if not raw_input:
                st.error("Please enter an indicator before submitting.")
            else:
                normalized, ioc_type, err = classify_indicator(raw_input)
                if not ioc_type:
                    st.error(f"❌ Invalid indicator: {err}")
                else:
                    st.markdown("---")
                    with st.spinner(f"Analyzing `{normalized}` …"):
                        if api_key:
                            result = lookup_virustotal(normalized, ioc_type, api_key)
                        else:
                            # Simulate a brief pause to indicate processing
                            time.sleep(0.4)
                            result = get_demo_result(normalized, ioc_type)

                    if result["success"]:
                        render_analysis_results(result)
                    else:
                        st.error(f"❌ Analysis failed: {result['error']}")
                        st.markdown(
                            "**Suggestions:**\n"
                            "- Verify your API key is valid.\n"
                            "- Check your internet connection.\n"
                            "- Try again — the service may be temporarily unavailable.\n"
                            "- Visit [virustotal.com](https://www.virustotal.com) directly."
                        )

    with tab_history:
        render_history_section()

    with tab_about:
        render_about_section()

    # Footer
    st.markdown(
        f'<div class="tl-footer">'
        f"{APP_TITLE} — {APP_SUBTITLE} &nbsp;·&nbsp; v{APP_VERSION} &nbsp;·&nbsp; "
        f"Threat intelligence provided by {VT_PROVIDER_NAME}"
        f"</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
