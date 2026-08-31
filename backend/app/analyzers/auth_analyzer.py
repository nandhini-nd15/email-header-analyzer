"""
Authentication analyzer: SPF, DKIM, DMARC.

Two layers of checking:
1. "Claimed" - parsed from the Authentication-Results header, i.e. what the
   receiving mail server already decided. Fast, no DNS needed.
2. "Verified" - we independently query DNS ourselves and check. This is what
   makes the tool trustworthy rather than just echoing a header that could
   itself be forged by a malicious relay.
"""
import re
import dns.resolver
from typing import Optional


def parse_authentication_results(auth_headers: list) -> dict:
    """
    Parse the Authentication-Results header(s) for spf/dkim/dmarc verdicts.
    Format looks like:
      mx.google.com;
       dkim=pass header.i=@sender.com ...
       spf=pass (google.com: domain of ...) smtp.mailfrom=sender@sender.com;
       dmarc=pass (p=REJECT ...) header.from=sender.com
    """
    combined = " ".join(auth_headers) if auth_headers else ""
    results = {"spf": None, "dkim": None, "dmarc": None}

    for mechanism in results:
        match = re.search(rf'{mechanism}=(\w+)', combined, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()

    return results


def get_txt_records(domain: str) -> list:
    """Fetch TXT records for a domain. Returns empty list on any DNS failure -
    we never want a network hiccup to crash the whole analysis."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        return ["".join([s.decode() if isinstance(s, bytes) else s for s in r.strings])
                for r in answers]
    except Exception:
        return []


def verify_spf(domain: str, sender_ip: Optional[str]) -> dict:
    """
    Lightweight independent SPF check: fetch the domain's SPF TXT record
    and see if it exists / what the catch-all policy is. A full SPF
    evaluator (with recursive `include:` resolution) is a larger effort;
    for the project's "verification" layer we confirm the record's
    existence and policy strictness, which is enough to catch domains
    with no SPF protection at all (a common phishing indicator) and to
    corroborate or contradict the claimed result.
    """
    if not domain:
        return {"verified_result": None, "details": "No sender domain to check"}

    txt_records = get_txt_records(domain)
    spf_record = next((r for r in txt_records if r.startswith("v=spf1")), None)

    if not spf_record:
        return {"verified_result": "none", "details": f"No SPF record published for {domain}"}

    if "-all" in spf_record:
        policy = "hard fail (-all) - strict"
    elif "~all" in spf_record:
        policy = "soft fail (~all)"
    elif "?all" in spf_record:
        policy = "neutral (?all) - weak"
    else:
        policy = "no explicit catch-all"

    return {
        "verified_result": "record_found",
        "details": f"SPF record: {spf_record} | Policy: {policy}",
    }


def verify_dmarc(domain: str) -> dict:
    """Fetch and interpret the domain's DMARC policy record."""
    if not domain:
        return {"verified_result": None, "details": "No domain to check"}

    dmarc_domain = f"_dmarc.{domain}"
    txt_records = get_txt_records(dmarc_domain)
    dmarc_record = next((r for r in txt_records if r.startswith("v=DMARC1")), None)

    if not dmarc_record:
        return {"verified_result": "none",
                "details": f"No DMARC record published for {domain} - domain is unprotected against spoofing"}

    policy_match = re.search(r'p=(\w+)', dmarc_record)
    policy = policy_match.group(1) if policy_match else "unknown"

    return {
        "verified_result": policy,
        "details": f"DMARC record: {dmarc_record}",
    }


def analyze_authentication(auth_headers_raw: list, from_domain: Optional[str],
                            sender_ip: Optional[str]) -> list:
    """
    Main entry point. Returns a list of AuthResult-shaped dicts for
    spf/dkim/dmarc, combining claimed (from header) + independently
    verified (from DNS) results.
    """
    claimed = parse_authentication_results(auth_headers_raw)
    results = []

    # SPF
    spf_verify = verify_spf(from_domain, sender_ip)
    results.append({
        "mechanism": "spf",
        "claimed_result": claimed["spf"],
        "verified_result": spf_verify["verified_result"],
        "domain": from_domain,
        "details": spf_verify["details"],
        "passed": claimed["spf"] == "pass" if claimed["spf"] else None,
    })

    # DKIM - full cryptographic verification requires the message body +
    # dkimpy, wired in at the API layer where we have the full raw message.
    # Here we surface the claimed result; see api routes for verified check.
    results.append({
        "mechanism": "dkim",
        "claimed_result": claimed["dkim"],
        "verified_result": None,
        "domain": from_domain,
        "details": "See independent DKIM signature verification below" if claimed["dkim"]
                    else "No DKIM result found in Authentication-Results header",
        "passed": claimed["dkim"] == "pass" if claimed["dkim"] else None,
    })

    # DMARC
    dmarc_verify = verify_dmarc(from_domain)
    results.append({
        "mechanism": "dmarc",
        "claimed_result": claimed["dmarc"],
        "verified_result": dmarc_verify["verified_result"],
        "domain": from_domain,
        "details": dmarc_verify["details"],
        "passed": claimed["dmarc"] == "pass" if claimed["dmarc"] else None,
    })

    return results


def verify_dkim_signature(raw_message_bytes: bytes) -> dict:
    """
    Cryptographic DKIM verification using dkimpy - actually checks the
    signature against the public key published in DNS, rather than
    trusting a header. Requires the FULL raw message (headers + body),
    since DKIM signs body content too.
    """
    try:
        import dkim
        result = dkim.verify(raw_message_bytes)
        return {"verified_result": "pass" if result else "fail",
                "details": "Cryptographic signature verified against DNS public key"
                           if result else "Signature verification FAILED - message may be tampered with"}
    except Exception as e:
        return {"verified_result": "error", "details": f"Could not verify DKIM signature: {str(e)}"}