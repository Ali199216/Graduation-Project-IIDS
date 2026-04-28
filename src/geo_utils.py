import requests
import streamlit as st
import ipaddress
import random

# Predefined list of 20+ global cities for diversity and fallback testing
MOCK_CITIES = [
    {"city": "London", "country": "United Kingdom", "lat": 51.5074, "lon": -0.1278},
    {"city": "Tokyo", "country": "Japan", "lat": 35.6762, "lon": 139.6503},
    {"city": "New York", "country": "United States", "lat": 40.7128, "lon": -74.0060},
    {"city": "Berlin", "country": "Germany", "lat": 52.5200, "lon": 13.4050},
    {"city": "Cairo", "country": "Egypt", "lat": 30.0444, "lon": 31.2357},
    {"city": "Paris", "country": "France", "lat": 48.8566, "lon": 2.3522},
    {"city": "Sydney", "country": "Australia", "lat": -33.8688, "lon": 151.2093},
    {"city": "Moscow", "country": "Russia", "lat": 55.7558, "lon": 37.6173},
    {"city": "Beijing", "country": "China", "lat": 39.9042, "lon": 116.4074},
    {"city": "Rio de Janeiro", "country": "Brazil", "lat": -22.9068, "lon": -43.1729},
    {"city": "Mumbai", "country": "India", "lat": 19.0760, "lon": 72.8777},
    {"city": "Toronto", "country": "Canada", "lat": 43.6510, "lon": -79.3470},
    {"city": "Cape Town", "country": "South Africa", "lat": -33.9249, "lon": 18.4241},
    {"city": "Seoul", "country": "South Korea", "lat": 37.5665, "lon": 126.9780},
    {"city": "Buenos Aires", "country": "Argentina", "lat": -34.6037, "lon": -58.3816},
    {"city": "Istanbul", "country": "Turkey", "lat": 41.0082, "lon": 28.9784},
    {"city": "Lagos", "country": "Nigeria", "lat": 6.5244, "lon": 3.3792},
    {"city": "Dubai", "country": "UAE", "lat": 25.2048, "lon": 55.2708},
    {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lon": 103.8198},
    {"city": "Los Angeles", "country": "United States", "lat": 34.0522, "lon": -118.2437},
    {"city": "Mexico City", "country": "Mexico", "lat": 19.4326, "lon": -99.1332},
]

# Fixed "Home Base" coordinates — represents YOUR network target on the map
# Used as the destination endpoint for Attack Path Visualization lines
HOME_BASE_COORDS = {"city": "Cairo", "country": "Egypt", "lat": 30.0444, "lon": 31.2357}

# Country name → flag emoji mapping for forensic table display
COUNTRY_FLAGS = {
    "United Kingdom": "🇬🇧", "Japan": "🇯🇵", "United States": "🇺🇸",
    "Germany": "🇩🇪", "Egypt": "🇪🇬", "France": "🇫🇷",
    "Australia": "🇦🇺", "Russia": "🇷🇺", "China": "🇨🇳",
    "Brazil": "🇧🇷", "India": "🇮🇳", "Canada": "🇨🇦",
    "South Africa": "🇿🇦", "South Korea": "🇰🇷", "Argentina": "🇦🇷",
    "Turkey": "🇹🇷", "Nigeria": "🇳🇬", "UAE": "🇦🇪",
    "Singapore": "🇸🇬", "Mexico": "🇲🇽", "Italy": "🇮🇹",
    "Spain": "🇪🇸", "Netherlands": "🇳🇱", "Sweden": "🇸🇪",
    "Norway": "🇳🇴", "Poland": "🇵🇱", "Indonesia": "🇮🇩",
    "Thailand": "🇹🇭", "Vietnam": "🇻🇳", "Iran": "🇮🇷",
    "Israel": "🇮🇱", "Ukraine": "🇺🇦", "Romania": "🇷🇴",
    "Unknown": "🚩",
}

def get_country_flag(country_name: str) -> str:
    """Return flag emoji for a country name. Falls back to 🚩 for unknowns."""
    return COUNTRY_FLAGS.get(country_name, "🚩")

def _get_mock_location():
    """Returns a random location with significant cluster jittering"""
    loc = random.choice(MOCK_CITIES)
    # Generate random offset (e.g. lat + random.uniform(-5, 5))
    lat_jitter = random.uniform(-5.0, 5.0)
    lon_jitter = random.uniform(-5.0, 5.0)
    return (loc["city"], loc["country"], loc["lat"] + lat_jitter, loc["lon"] + lon_jitter)

@st.cache_data(ttl=3600, show_spinner=False)
def get_ip_geolocation(ip_address: str):
    """
    Fetch geolocation data for an IP Address using ip-api.com.
    If private IP, randomly bind to a Major City for demo visual diversity.
    Returns: city, country, latitude, longitude
    """
    if not ip_address or ip_address.lower() == "unknown":
        return _get_mock_location()

    try:
        # Check if Private IP
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback:
            return _get_mock_location()

        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,lat,lon"
        response = requests.get(url, timeout=3)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                # Light jitter to prevent perfect stacking of external IPs as well
                lat_jitter = random.uniform(-0.5, 0.5) 
                lon_jitter = random.uniform(-0.5, 0.5)
                return (
                    data.get("city", "Unknown City"),
                    data.get("country", "Unknown Country"),
                    data.get("lat") + lat_jitter,
                    data.get("lon") + lon_jitter
                )
    except ValueError:
        pass
    except Exception:
        pass
        
    return _get_mock_location()
