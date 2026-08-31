"""
Pydantic models defining the shape of data flowing through the analyzer
and out to the frontend. Keeping this centralized means backend and
frontend always agree on the contract.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime


class HopInfo(BaseModel):
    """A single hop in the Received: chain, in chronological order."""
    hop_index: int
    raw_header: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    protocol: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: Optional[datetime] = None
    delay_seconds: Optional[float] = None          # delay since previous hop
    delay_flag: bool = False                        # True if delay is anomalously high
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    is_private_ip: bool = False


class AuthResult(BaseModel):
    """Result for one authentication mechanism (SPF/DKIM/DMARC)."""
    mechanism: Literal["spf", "dkim", "dmarc"]
    claimed_result: Optional[str] = None   # what Authentication-Results header said
    verified_result: Optional[str] = None  # what we independently verified
    domain: Optional[str] = None
    details: Optional[str] = None
    passed: Optional[bool] = None


class SpoofSignal(BaseModel):
    """One detected red flag, with the weight it contributed to the risk score."""
    signal: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    weight: int


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Literal["Likely Safe", "Suspicious", "Likely Phishing"]
    signals: List[SpoofSignal]


class BasicHeaders(BaseModel):
    message_id: Optional[str] = None
    from_address: Optional[str] = None
    from_display_name: Optional[str] = None
    to_address: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    x_mailer: Optional[str] = None
    x_originating_ip: Optional[str] = None


class AnalysisResult(BaseModel):
    basic_headers: BasicHeaders
    received_chain: List[HopInfo]
    auth_results: List[AuthResult]
    risk_assessment: RiskAssessment
    raw_headers: dict
    warnings: List[str] = []   # non-fatal parsing issues, e.g. malformed header