"""
IP geolocation lookup using ip-api.com (free, no API key required,
45 requests/minute rate limit - fine for a student project demo).
"""
import requests
from typing import Optional

def geolocate_ip(ip: Optional[str]) -> dict:
    """
    Returns country, city, lat, lon for a public IP.
    Private/loopback IPs and lookup failures return all-None gracefully -
    we never want a geolocation failure to break the whole analysis.
    """
    if not ip:
        return {"country": None, "city": None, "lat": None, "lon": None}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon"},
            timeout=3,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
            }
    except Exception:
        pass

    return {"country": None, "city": None, "lat": None, "lon": None}