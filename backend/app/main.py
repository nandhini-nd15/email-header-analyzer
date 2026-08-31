"""
FastAPI application entrypoint.

Run locally with:
    uvicorn app.main:app --reload --port 8000

Then visit http://localhost:8000/docs for interactive Swagger UI.
"""
from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.parsers.header_parser import parse_email_headers
from app.analyzers.auth_analyzer import analyze_authentication, verify_dkim_signature
from app.analyzers.risk_scorer import compute_risk_assessment, get_domain
from app.utils.geolocation import geolocate_ip

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Email Header Analyzer API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS - allow your frontend dev server + deployed frontend domain.
# IMPORTANT: replace "*" with your actual frontend URL before deploying to production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # e.g. ["http://localhost:5173", "https://yourapp.vercel.app"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_full_analysis(raw_input) -> dict:
    """Shared pipeline used by both the paste and upload endpoints."""
    parsed = parse_email_headers(raw_input)
    msg_object = parsed.pop("_msg_object")

    from_domain = get_domain(parsed["basic_headers"].get("from_address", ""))
    sender_ip = parsed["received_chain"][-1]["ip_address"] if parsed["received_chain"] else None

    # Geolocate each public IP in the hop chain (skip private IPs - no useful location)
    for hop in parsed["received_chain"]:
        if hop.get("ip_address") and not hop.get("is_private_ip"):
            geo = geolocate_ip(hop["ip_address"])
            hop["geo_country"] = geo["country"]
            hop["geo_city"] = geo["city"]
            hop["geo_lat"] = geo["lat"]
            hop["geo_lon"] = geo["lon"]

    auth_results = analyze_authentication(
        parsed["authentication_results_raw"],
        from_domain,
        sender_ip,
    )

    # Attempt real cryptographic DKIM verification if we have the full raw message
    if isinstance(raw_input, (bytes, str)):
        raw_bytes = raw_input if isinstance(raw_input, bytes) else raw_input.encode("utf-8", errors="ignore")
        dkim_verify = verify_dkim_signature(raw_bytes)
        for r in auth_results:
            if r["mechanism"] == "dkim":
                r["verified_result"] = dkim_verify["verified_result"]
                r["details"] = dkim_verify["details"]
                if dkim_verify["verified_result"] in ("pass", "fail"):
                    r["passed"] = dkim_verify["verified_result"] == "pass"

    risk_assessment = compute_risk_assessment(
        parsed["basic_headers"], parsed["received_chain"], auth_results
    )

    return {
        "basic_headers": parsed["basic_headers"],
        "received_chain": parsed["received_chain"],
        "auth_results": auth_results,
        "risk_assessment": risk_assessment,
        "raw_headers": parsed["raw_headers"],
        "warnings": parsed["warnings"],
    }


@app.get("/api/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/analyze")
@limiter.limit("20/minute")
def analyze_pasted_headers(request: Request, payload: dict = Body(...)):
    """
    Accepts JSON: { "raw_headers": "Delivered-To: ...\\nReceived: ..." }
    """
    raw_text = payload.get("raw_headers", "")
    if not raw_text or not raw_text.strip():
        raise HTTPException(status_code=400, detail="raw_headers field is empty")
    try:
        return run_full_analysis(raw_text)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse headers: {str(e)}")


@app.post("/api/analyze/upload")
@limiter.limit("20/minute")
async def analyze_uploaded_eml(request: Request, file: UploadFile = File(...)):
    """Accepts a .eml file upload."""
    if not file.filename.lower().endswith((".eml", ".txt", ".msg")):
        raise HTTPException(status_code=400, detail="Please upload a .eml or .txt file")
    content = await file.read()
    try:
        return run_full_analysis(content)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse file: {str(e)}")