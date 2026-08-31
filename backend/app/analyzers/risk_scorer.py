"""
Spoofing / phishing risk scorer.
"""
import re
from urllib.parse import urlparse
from email.utils import parseaddr


IMPERSONATION_TARGETS = [
    "paypal", "amazon", "microsoft", "apple", "google", "netflix",
    "bank", "irs", "dhl", "fedex", "linkedin", "facebook", "instagram",
]


def get_domain(email_address: str) -> str:
    if not email_address or "@" not in email_address:
        return ""
    return email_address.split("@")[-1].strip(">").lower()


def score_authentication(auth_results: list) -> list:
    signals = []
    for result in auth_results:
        mech = result["mechanism"].upper()
        claimed = result.get("claimed_result")
        verified = result.get("verified_result")

        if claimed == "fail" or verified == "fail":
            weight = 30 if mech == "DMARC" else 25
            signals.append({
                "signal": f"{mech}_FAIL",
                "description": f"{mech} authentication failed - message did not pass sender verification",
                "severity": "critical",
                "weight": weight,
            })
        elif claimed is None and mech != "DKIM":
            signals.append({
                "signal": f"{mech}_MISSING",
                "description": f"No {mech} result present - sender domain may lack {mech} protection",
                "severity": "medium",
                "weight": 12,
            })
        elif verified == "none" and mech == "DMARC":
            signals.append({
                "signal": "DMARC_NOT_PUBLISHED",
                "description": "Sending domain has no DMARC policy - offers no protection against spoofing",
                "severity": "medium",
                "weight": 10,
            })
    return signals


def score_address_mismatches(basic_headers: dict) -> list:
    signals = []
    from_domain = get_domain(basic_headers.get("from_address", ""))

    return_path_addr = parseaddr(basic_headers.get("return_path") or "")[1]
    return_path_domain = get_domain(return_path_addr)
    if return_path_domain and from_domain and return_path_domain != from_domain:
        signals.append({
            "signal": "RETURN_PATH_MISMATCH",
            "description": f"From domain ({from_domain}) does not match Return-Path domain "
                            f"({return_path_domain}) - bounces go to a different domain than the sender claims",
            "severity": "high",
            "weight": 20,
        })

    reply_to_addr = parseaddr(basic_headers.get("reply_to") or "")[1]
    reply_to_domain = get_domain(reply_to_addr)
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        signals.append({
            "signal": "REPLY_TO_MISMATCH",
            "description": f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain}) "
                            f"- replies will be redirected away from the apparent sender",
            "severity": "medium",
            "weight": 15,
        })

    return signals


def score_display_name_spoofing(basic_headers: dict) -> list:
    signals = []
    display_name = (basic_headers.get("from_display_name") or "").lower()
    from_domain = get_domain(basic_headers.get("from_address", ""))

    for brand in IMPERSONATION_TARGETS:
        if brand in display_name and brand not in from_domain:
            signals.append({
                "signal": "DISPLAY_NAME_IMPERSONATION",
                "description": f"Display name references '{brand}' but sending domain "
                                f"'{from_domain}' is unrelated - classic brand impersonation pattern",
                "severity": "high",
                "weight": 25,
            })
            break
    return signals


def score_routing_anomalies(received_chain: list) -> list:
    signals = []
    flagged_hops = [h for h in received_chain if h.get("delay_flag")]
    if flagged_hops:
        signals.append({
            "signal": "ROUTING_ANOMALY",
            "description": f"{len(flagged_hops)} hop(s) in the delivery path show unusual delay "
                            f"or out-of-order timestamps - may indicate a compromised relay or forged header",
            "severity": "medium",
            "weight": 15,
        })
    if not received_chain:
        signals.append({
            "signal": "NO_ROUTING_DATA",
            "description": "No Received headers present - routing path cannot be verified at all",
            "severity": "medium",
            "weight": 10,
        })
    return signals


def score_missing_metadata(basic_headers: dict) -> list:
    signals = []
    if not basic_headers.get("message_id"):
        signals.append({
            "signal": "MISSING_MESSAGE_ID",
            "description": "No Message-ID header - unusual for mail sent through standard mail servers",
            "severity": "low",
            "weight": 5,
        })
    return signals


def compute_risk_assessment(basic_headers: dict, received_chain: list, auth_results: list) -> dict:
    signals = []
    signals += score_authentication(auth_results)
    signals += score_address_mismatches(basic_headers)
    signals += score_display_name_spoofing(basic_headers)
    signals += score_routing_anomalies(received_chain)
    signals += score_missing_metadata(basic_headers)

    total_score = min(sum(s["weight"] for s in signals), 100)

    if total_score >= 60:
        verdict = "Likely Phishing"
    elif total_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Likely Safe"

    return {
        "score": total_score,
        "verdict": verdict,
        "signals": signals,
    }