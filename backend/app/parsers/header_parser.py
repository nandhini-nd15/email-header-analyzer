"""
Core parsing engine. Turns raw RFC 5322 email header text into a
structured Python object we can run analysis on.

Design notes:
- We use Python's built-in `email` package as the base parser because it's
  battle-tested against real-world malformed headers, then we layer our
  own extraction on top for things stdlib doesn't give us directly
  (Received-chain reconstruction, IP extraction, etc).
- We preserve header order and duplicate headers (e.g. multiple
  `Received:` lines) because `msg.get_all()` is required for that -
  `msg["Received"]` only returns the first match.
"""
import re
import ipaddress
from email import message_from_string, message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from typing import Optional
from datetime import datetime

# Matches an IPv4 or bracketed IPv6 address anywhere in a Received header
IPV4_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
IPV6_RE = re.compile(r'\[([0-9a-fA-F:]+:[0-9a-fA-F:]+)\]')

# Received header structure: "from X by Y with Z ...; <date>"
RECEIVED_FROM_RE = re.compile(r'from\s+([^\s;]+(?:\s+\([^)]*\))?)', re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r'\bby\s+([^\s;]+)', re.IGNORECASE)
RECEIVED_WITH_RE = re.compile(r'\bwith\s+([^\s;]+)', re.IGNORECASE)


def decode_mime_header(raw_value: str) -> str:
    """
    Decode MIME-encoded headers like '=?UTF-8?B?SGVsbG8=?=' into readable text.
    Falls back to the raw string if decoding fails - we never want a crash
    here, just degraded output.
    """
    if not raw_value:
        return raw_value
    try:
        parts = decode_header(raw_value)
        decoded = []
        for text, encoding in parts:
            if isinstance(text, bytes):
                decoded.append(text.decode(encoding or "utf-8", errors="replace"))
            else:
                decoded.append(text)
        return "".join(decoded)
    except Exception:
        return raw_value


def extract_ip(text: str) -> Optional[str]:
    """Pull the first plausible public/private IPv4 or IPv6 address out of a Received line."""
    if not text:
        return None
    ipv6_match = IPV6_RE.search(text)
    if ipv6_match:
        candidate = ipv6_match.group(1)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    for match in IPV4_RE.finditer(text):
        candidate = match.group(1)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


def is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def parse_received_header(raw_header: str, warnings: list) -> dict:
    """
    Break a single Received: header into its components.
    Real-world Received headers are messy and non-standardized across
    mail servers, so every extraction here is best-effort with graceful
    fallback to None rather than raising.
    """
    from_match = RECEIVED_FROM_RE.search(raw_header)
    by_match = RECEIVED_BY_RE.search(raw_header)
    with_match = RECEIVED_WITH_RE.search(raw_header)

    # timestamp is after the last semicolon, per RFC 5322
    timestamp = None
    if ";" in raw_header:
        date_part = raw_header.rsplit(";", 1)[-1].strip()
        try:
            timestamp = parsedate_to_datetime(date_part)
        except Exception:
            warnings.append(f"Could not parse timestamp in Received header: '{date_part[:50]}'")

    ip = extract_ip(raw_header)

    return {
        "from_host": from_match.group(1).strip() if from_match else None,
        "by_host": by_match.group(1).strip() if by_match else None,
        "protocol": with_match.group(1).strip() if with_match else None,
        "ip_address": ip,
        "timestamp": timestamp,
        "is_private_ip": is_private_ip(ip),
    }


def build_received_chain(received_headers: list, warnings: list) -> list:
    """
    Received headers appear newest-first in the raw message (each server
    prepends its own). We reverse them to get chronological order
    (sender -> recipient), then compute inter-hop delays.
    """
    chronological = list(reversed(received_headers))
    chain = []
    prev_timestamp = None

    for idx, raw in enumerate(chronological):
        parsed = parse_received_header(raw, warnings)
        delay_seconds = None
        delay_flag = False
        if parsed["timestamp"] and prev_timestamp:
            delay_seconds = (parsed["timestamp"] - prev_timestamp).total_seconds()
            # Flag unusually long gaps between hops (>1 hour) - common in
            # spoofed/relayed spam where the message sat on a compromised
            # relay, or the injected header has a fabricated timestamp.
            if delay_seconds is not None and (delay_seconds > 3600 or delay_seconds < 0):
                delay_flag = True
        if parsed["timestamp"]:
            prev_timestamp = parsed["timestamp"]

        chain.append({
            "hop_index": idx,
            "raw_header": raw,
            "delay_seconds": delay_seconds,
            "delay_flag": delay_flag,
            **parsed,
        })

    return chain


def parse_email_headers(raw_input: bytes | str) -> dict:
    """
    Main entry point. Accepts raw header text (or a full .eml file, we only
    care about the header section) and returns a structured dict ready to
    hand to the analyzers.
    """
    warnings = []

    if isinstance(raw_input, bytes):
        msg = message_from_bytes(raw_input)
    else:
        msg = message_from_string(raw_input)

    # --- Basic headers ---
    from_raw = msg.get("From", "")
    display_name, from_addr = parseaddr(decode_mime_header(from_raw))

    basic_headers = {
        "message_id": msg.get("Message-ID"),
        "from_address": from_addr or None,
        "from_display_name": display_name or None,
        "to_address": msg.get("To"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path"),
        "subject": decode_mime_header(msg.get("Subject", "")) or None,
        "date": msg.get("Date"),
        "x_mailer": msg.get("X-Mailer") or msg.get("User-Agent"),
        "x_originating_ip": msg.get("X-Originating-IP"),
    }

    # --- Received chain (get_all, NOT indexing, to catch every hop) ---
    received_headers = msg.get_all("Received", [])
    if not received_headers:
        warnings.append("No Received headers found - cannot reconstruct routing path. "
                         "This may be a locally-generated or heavily stripped message.")
    received_chain = build_received_chain(received_headers, warnings)

    # --- Authentication-Results (raw, claimed by the last receiving server) ---
    auth_results_headers = msg.get_all("Authentication-Results", [])

    # --- Raw headers dict for the "view raw" UI panel ---
    raw_headers = {}
    for key in msg.keys():
        values = msg.get_all(key)
        raw_headers[key] = values if len(values) > 1 else values[0]

    return {
        "basic_headers": basic_headers,
        "received_chain": received_chain,
        "authentication_results_raw": auth_results_headers,
        "raw_headers": raw_headers,
        "warnings": warnings,
        "_msg_object": msg,  # kept internally for downstream analyzers, stripped before API response
    }