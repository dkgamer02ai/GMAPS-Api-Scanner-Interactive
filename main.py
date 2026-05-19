import requests
import json
import warnings
from typing import Optional
from urllib.parse import urlencode
from fastapi import FastAPI, Query, HTTPException, Request

# Suppress SSL warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os

app = FastAPI(
    title="Google Maps API Scanner",
    description="Test which Google Maps APIs are exploitable with your API key",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REQUEST_TIMEOUT = 15
_REQUEST_KWARGS = {"verify": False, "timeout": REQUEST_TIMEOUT}


class APITest(BaseModel):
    name: str
    is_vulnerable: bool
    reason: str
    poc_url: Optional[str] = None
    poc_curl: Optional[str] = None
    cost: Optional[str] = None


class DiscoveryResponse(BaseModel):
    total_tested: int
    vulnerable_count: int
    vulnerable_apis: list[APITest]
    safe_apis: list[APITest]


def _error_message(response, keys=("error_message", "errorMessage")):
    """Safely extract error message from JSON response."""
    try:
        data = response.json()
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            data = data[0]
        for key in keys:
            if key in data:
                val = data[key]
                if isinstance(val, dict) and "message" in val:
                    return val["message"]
                if isinstance(val, str):
                    return val
        if "error" in data and isinstance(data["error"], dict):
            return data["error"].get("message", str(data["error"]))
    except (json.JSONDecodeError, TypeError):
        pass
    if response.content:
        try:
            return response.content[:500].decode("utf-8", errors="replace").strip()
        except Exception:
            return str(response.content[:200])
    return "Unknown error (status %s)" % getattr(response, "status_code", "?")


@app.get("/")
def root():
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(html_path)


@app.get("/api/test/staticmap", response_model=APITest)
def test_staticmap(api_key: str ,
                   center_lat: float = 12.9716,
                   center_lng: float = 77.5946,
                   zoom: int = 14,
                   size: str = "400x400"):
    """Test Static Map API"""
    
    url = f"https://maps.googleapis.com/maps/api/staticmap?center={center_lat},{center_lng}&zoom={zoom}&size={size}&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if response.status_code == 200:
            return APITest(
                name="Static Map API",
                is_vulnerable=True,
                reason="API key accepted - map generated successfully",
                poc_url=url,
                cost="$2 per 1000 requests",
            )
        elif b"PNG" in response.content:
            return APITest(
                name="Static Map API",
                is_vulnerable=False,
                reason="Image returned but may have restrictions",
            )
        else:
            return APITest(
                name="Static Map API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Static Map API", is_vulnerable=False, reason=f"Request failed: {str(e)}"
        )


@app.get("/api/test/streetview", response_model=APITest)
def test_streetview(api_key: str = Query(..., description="Google Maps API Key"),
                   location_lat: float = Query(12.9716),
                   location_lng: float = Query(77.5946),
                   heading: int = Query(235),
                   pitch: int = Query(10)):
    """Test Street View API"""
    url = f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location={location_lat},{location_lng}&fov=90&heading={heading}&pitch={pitch}&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if response.status_code == 200:
            return APITest(
                name="Street View API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$7 per 1000 requests",
            )
        elif b"PNG" in response.content:
            return APITest(
                name="Street View API",
                is_vulnerable=False,
                reason="Manually check response",
            )
        else:
            return APITest(
                name="Street View API",
                is_vulnerable=False,
                reason=str(response.content[:200]),
            )
    except Exception as e:
        return APITest(
            name="Street View API", is_vulnerable=False, reason=f"Request failed: {str(e)}"
        )


@app.get("/api/test/directions", response_model=APITest)
def test_directions(api_key: str = Query(..., description="Google Maps API Key"),
                   origin: str = Query("Indiranagar, Bangalore"),
                   destination: str = Query("Koramangala, Bangalore")):
    """Test Directions API"""
    url = f"https://maps.googleapis.com/maps/api/directions/json?origin={origin}&destination={destination}&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Directions API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$5 per 1000 requests / $10 per 1000 (Advanced)",
            )
        else:
            return APITest(
                name="Directions API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Directions API", is_vulnerable=False, reason=f"Request failed: {str(e)}"
        )


@app.get("/api/test/geocode", response_model=APITest)
def test_geocode(api_key: str = Query(..., description="Google Maps API Key"),
                address: str = Query("Bangalore, India")):
    """Test Geocode API"""
    params = {
        "address": address,
        "key": api_key
    }
    url = f"https://maps.googleapis.com/maps/api/geocode/json?{urlencode(params)}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Geocode API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$5 per 1000 requests",
            )
        else:
            return APITest(
                name="Geocode API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Geocode API", is_vulnerable=False, reason=f"Request failed: {str(e)}"
        )


@app.get("/api/test/distancematrix", response_model=APITest)
def test_distancematrix(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Distance Matrix API - Bangalore locations"""
    url = f"https://maps.googleapis.com/maps/api/distancematrix/json?units=metric&origins=12.9716,77.5946&destinations=12.9352,77.6245|13.0827,80.2707&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Distance Matrix API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$5 per 1000 elements / $10 per 1000 (Advanced)",
            )
        else:
            return APITest(
                name="Distance Matrix API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Distance Matrix API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.get("/api/test/places/findplacefromtext", response_model=APITest)
def test_places_findplacefromtext(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Find Place From Text API - Bangalore"""
    url = f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Restaurants+in+Bangalore&inputtype=textquery&fields=photos,formatted_address,name,rating&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Find Place From Text API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$17 per 1000 elements",
            )
        else:
            return APITest(
                name="Find Place From Text API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Find Place From Text API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.get("/api/test/places/autocomplete", response_model=APITest)
def test_places_autocomplete(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Autocomplete API - Bangalore"""
    url = f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Indi&types=%28cities%29&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Autocomplete API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$2.83 per 1000 requests / $17 per 1000 (Per Session)",
            )
        else:
            return APITest(
                name="Autocomplete API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Autocomplete API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.get("/api/test/elevation", response_model=APITest)
def test_elevation(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Elevation API"""
    params = {
        "key": api_key
    }
    url = f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536%2C-104.9847034&{urlencode(params)}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Elevation API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$5 per 1000 requests",
            )
        else:
            return APITest(
                name="Elevation API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Elevation API", is_vulnerable=False, reason=f"Request failed: {str(e)}"
        )


@app.get("/api/test/timezone", response_model=APITest)
def test_timezone(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Timezone API - Bangalore"""
    url = f"https://maps.googleapis.com/maps/api/timezone/json?location=12.9716,77.5946&timestamp=1331161200&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "errorMessage" not in response.text and "error_message" not in response.text:
            return APITest(
                name="Timezone API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$5 per 1000 requests",
            )
        else:
            return APITest(
                name="Timezone API",
                is_vulnerable=False,
                reason=_error_message(response, ("errorMessage", "error_message")),
            )
    except Exception as e:
        return APITest(
            name="Timezone API", is_vulnerable=False, reason=f"Request failed: {str(e)}"
        )


@app.get("/api/test/roads/nearestroads", response_model=APITest)
def test_roads_nearestroads(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Nearest Roads API - Bangalore area"""
    url = f"https://roads.googleapis.com/v1/nearestRoads?points=12.9716,77.5946|12.9352,77.6245&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error" not in response.text:
            return APITest(
                name="Nearest Roads API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$10 per 1000 requests",
            )
        else:
            return APITest(
                name="Nearest Roads API",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
            )
    except Exception as e:
        return APITest(
            name="Nearest Roads API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.get("/api/test/places/nearbysearch", response_model=APITest)
def test_places_nearbysearch(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Nearby Search API - Bangalore"""
    url = f"https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=12.9716,77.5946&radius=1000&types=restaurant&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Nearby Search API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$32 per 1000 requests",
            )
        else:
            return APITest(
                name="Nearby Search API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Nearby Search API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.get("/api/test/places/textsearch", response_model=APITest)
def test_places_textsearch(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Text Search API - Bangalore"""
    url = f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=hotels+in+Bangalore&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Text Search API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$32 per 1000 requests",
            )
        else:
            return APITest(
                name="Text Search API",
                is_vulnerable=False,
                reason=_error_message(response),
            )
    except Exception as e:
        return APITest(
            name="Text Search API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.post("/api/test/geolocation", response_model=APITest)
def test_geolocation(api_key: str = Query(..., description="Google Maps API Key"),
                    consider_ip: str = Query("true")):
    """Test Geolocation API"""
    url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={api_key}"

    # Build request body
    body = {
        "considerIp": consider_ip.lower() == "true"
    }

    try:
        response = requests.post(
            url,
            data=json.dumps(body),
            headers={"Content-Type": "application/json"},
            **_REQUEST_KWARGS
        )

        if response.status_code == 200 and "error" not in response.text:
            curl_cmd = f'''curl -X POST -d '{json.dumps(body)}' \\
  -H "Content-Type: application/json" \\
  "{url}"'''
            return APITest(
                name="Geolocation API",
                is_vulnerable=True,
                reason="API key accepted - location detected from IP",
                poc_curl=curl_cmd,
                cost="$5 per 1000 requests",
            )
        else:
            return APITest(
                name="Geolocation API",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
            )
    except Exception as e:
        return APITest(
            name="Geolocation API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.post("/api/test/addressvalidation", response_model=APITest)
def test_addressvalidation(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Address Validation API - Bangalore address"""
    url = f"https://addressvalidation.googleapis.com/v1:validateAddress?key={api_key}"
    try:
        postdata = json.dumps(
            {"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Pkwy, Mountain View, CA"]}}
        )
        response = requests.post(
            url,
            data=postdata,
            headers={"Content-Type": "application/json"},
            **_REQUEST_KWARGS,
        )
        if response.status_code == 200 and "error" not in response.text:
            return APITest(
                name="Address Validation API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$5 per 1000 requests",
            )
        else:
            return APITest(
                name="Address Validation API",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
                cost="$5 per 1000 requests",
            )
    except Exception as e:
        return APITest(
            name="Address Validation API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.post("/api/test/airquality", response_model=APITest)
def test_airquality(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Air Quality API"""
    url = f"https://airquality.googleapis.com/v1/currentConditions:lookup?key={api_key}"
    try:
        postdata = json.dumps({"location": {"latitude": 37.419734, "longitude": -122.0827784}})
        response = requests.post(
            url,
            data=postdata,
            headers={"Content-Type": "application/json"},
            **_REQUEST_KWARGS,
        )
        if response.status_code == 200 and "error" not in response.text:
            return APITest(
                name="Air Quality API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="Paid per request",
            )
        else:
            return APITest(
                name="Air Quality API",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
                cost="Paid per request",
            )
    except Exception as e:
        return APITest(
            name="Air Quality API", is_vulnerable=False, reason=f"Request failed: {str(e)}"
        )


@app.get("/api/test/routes/computeroutes", response_model=APITest)
def test_routes_computeroutes(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Routes API (computeRoutes)"""
    url = f"https://routes.googleapis.com/directions/v2:computeRoutes?key={api_key}"
    try:
        headers = {
            "Content-Type": "application/json",
            "X-Goog-FieldMask": "routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline",
        }
        body = {
            "origin": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}},
            "destination": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}},
            "travelMode": "DRIVE",
        }
        response = requests.post(url, data=json.dumps(body), headers=headers, **_REQUEST_KWARGS)
        if response.status_code == 200 and "error" not in response.text and "routes" in response.text:
            return APITest(
                name="Routes API (computeRoutes)",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="Paid per request",
            )
        else:
            return APITest(
                name="Routes API (computeRoutes)",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
            )
    except Exception as e:
        return APITest(
            name="Routes API (computeRoutes)",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.get("/api/test/gemini/files", response_model=APITest)
def test_gemini_files(api_key: str = Query(..., description="Google Maps API Key")):
    """Test Gemini Files API"""
    url = f"https://generativelanguage.googleapis.com/v1beta/files?key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if response.status_code == 200 and "error" not in response.text:
            return APITest(
                name="Gemini Files API",
                is_vulnerable=True,
                reason="Data leak risk - can access uploaded files",
                poc_url=url,
                cost="Paid per request",
            )
        else:
            return APITest(
                name="Gemini Files API",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
            )
    except Exception as e:
        return APITest(
            name="Gemini Files API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
        )


@app.get("/api/test/places/placedetails", response_model=APITest)
def test_placedetails(api_key: str = Query(..., description="Google Maps API Key"),
                     place_id: str = Query("ChIJN1t_tDeuEmsRUsoyG83frY4")):
    """Test Place Details API"""
    params = {"place_id": place_id, "key": api_key}
    url = f"https://maps.googleapis.com/maps/api/place/details/json?{urlencode(params)}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if "error_message" not in response.text:
            return APITest(
                name="Place Details API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$17 per 1000 requests",
            )
        else:
            return APITest(
                name="Place Details API",
                is_vulnerable=False,
                reason=_error_message(response),
                cost="$17 per 1000 requests",
            )
    except Exception as e:
        return APITest(
            name="Place Details API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
            cost="$17 per 1000 requests",
        )


@app.get("/api/test/roads/speedlimit", response_model=APITest)
def test_speedlimit(api_key: str = Query(..., description="Google Maps API Key"),
                   latitude: float = Query(12.9716),
                   longitude: float = Query(77.5946)):
    """Test Speed Limits API"""
    url = f"https://roads.googleapis.com/v1/speedLimits?path={latitude},{longitude}&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if response.status_code == 200 and "error" not in response.text:
            return APITest(
                name="Speed Limits API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="$10 per 1000 requests",
            )
        else:
            return APITest(
                name="Speed Limits API",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
                cost="$10 per 1000 requests",
            )
    except Exception as e:
        return APITest(
            name="Speed Limits API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
            cost="$10 per 1000 requests",
        )


# @app.get("/api/test/places/photo", response_model=APITest)
# def test_places_photo(api_key: str = Query(..., description="Google Maps API Key"),
#                      photo_reference: str = Query("CmRaAAAAzqtQzNDPIFI-E0KwXo9lCf-58F8eBLqDx-cYdYPEOr1iJTZLqIRqfqMb0M8lSm-gXjkJL8HVfZrOqPR0UR7U_-qeUy-B1fEFT1nG0YmC3nXvJCx4vYu6H-20Cxx2h5fh")):
#     """Test Places Photo API"""
#     params = {"photo_reference": photo_reference, "maxwidth": 400, "key": api_key}
#     url = f"https://maps.googleapis.com/maps/api/place/photo?{urlencode(params)}"
#     try:
#         response = requests.get(url, **_REQUEST_KWARGS)
#         if response.status_code == 200:
#             return APITest(
#                 name="Places Photo API",
#                 is_vulnerable=True,
#                 reason="API key accepted - photo accessible",
#                 poc_url=url,
#                 cost="$7 per 1000 requests",
#             )
#         else:
#             return APITest(
#                 name="Places Photo API",
#                 is_vulnerable=False,
#                 reason=_error_message(response),
#                 cost="$7 per 1000 requests",
#             )
#     except Exception as e:
#         return APITest(
#             name="Places Photo API",
#             is_vulnerable=False,
#             reason=f"Request failed: {str(e)}",
#             cost="$7 per 1000 requests",
#         )


@app.get("/api/test/routes/computeroutematrix", response_model=APITest)
def test_routematrix(api_key: str,
                    origin_lat: float = 12.9716,
                    origin_lng: float = 77.5946,
                    dest_lat: float = 12.9352,
                    dest_lng: float = 77.6245):
    """Test Routes API - computeRouteMatrix"""
    url = f"https://routes.googleapis.com/directions/v2:computeRouteMatrix?key={api_key}"
    try:
        payload = {
            "origins": [{"location": {"latLng": {"latitude": origin_lat, "longitude": origin_lng}}}],
            "destinations": [{"location": {"latLng": {"latitude": dest_lat, "longitude": dest_lng}}}],
        }
        response = requests.post(
            url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            **_REQUEST_KWARGS,
        )
        if response.status_code == 200 and "error" not in response.text:
            return APITest(
                name="Routes API (computeRouteMatrix)",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="Paid per element",
            )
        else:
            return APITest(
                name="Routes API (computeRouteMatrix)",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
                cost="Paid per element",
            )
    except Exception as e:
        return APITest(
            name="Routes API (computeRouteMatrix)",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
            cost="Paid per element",
        )


@app.get("/api/test/aerialview", response_model=APITest)
def test_aerialview(api_key: str = Query(..., description="Google Maps API Key"),
                   latitude: float = Query(12.9716),
                   longitude: float = Query(77.5946)):
    """Test Aerial View API"""
    url = f"https://aerialview.googleapis.com/v1/videos:lookupVideo?location.latitude={latitude}&location.longitude={longitude}&key={api_key}"
    try:
        response = requests.get(url, **_REQUEST_KWARGS)
        if response.status_code == 200 and "error" not in response.text:
            return APITest(
                name="Aerial View API",
                is_vulnerable=True,
                reason="API key accepted",
                poc_url=url,
                cost="Paid per request",
            )
        else:
            return APITest(
                name="Aerial View API",
                is_vulnerable=False,
                reason=_error_message(response, ("error",)),
                cost="Paid per request",
            )
    except Exception as e:
        return APITest(
            name="Aerial View API",
            is_vulnerable=False,
            reason=f"Request failed: {str(e)}",
            cost="Paid per request",
        )


@app.get("/api/discovery", response_model=DiscoveryResponse)
def discovery(api_key: str = Query(..., description="Google Maps API Key")):
    """
    Sophisticated endpoint that tests ALL APIs and returns which are exploitable.
    This endpoint scans the API key across all major Google Maps/GCP APIs.
    """
    test_functions = [
        test_staticmap,
        test_streetview,
        test_directions,
        test_geocode,
        test_distancematrix,
        test_places_findplacefromtext,
        test_places_autocomplete,
        test_elevation,
        test_timezone,
        test_roads_nearestroads,
        test_places_nearbysearch,
        test_places_textsearch,
        test_geolocation,
        test_addressvalidation,
        test_airquality,
        test_routes_computeroutes,
        test_gemini_files,
        test_placedetails,
        test_speedlimit,
        # test_places_photo,
        test_routematrix,
        test_aerialview,
    ]

    vulnerable_apis = []
    safe_apis = []

    for test_func in test_functions:
        try:
            result = test_func(api_key=api_key)
            if result.is_vulnerable:
                vulnerable_apis.append(result)
            else:
                safe_apis.append(result)
        except Exception:
            pass

    return DiscoveryResponse(
        total_tested=len(test_functions),
        vulnerable_count=len(vulnerable_apis),
        vulnerable_apis=vulnerable_apis,
        safe_apis=safe_apis,
    )


@app.get("/health")
def health():
    return {"status": "ok", "message": "Google Maps API Scanner is running"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3333)
