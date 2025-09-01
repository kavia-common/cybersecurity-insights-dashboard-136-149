from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
import datetime

# ----------------------------------------------------------------------------
# FastAPI App Setup
# ----------------------------------------------------------------------------

app = FastAPI(
    title="Cybersecurity Insights AI Backend",
    description="Backend API for the Cybersecurity Advanced AI Dashboard. Provides endpoints for analytics, threat detection, notifications, authentication, dashboard data, widgets, settings, and real-time capabilities.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Authentication", "description": "User registration and authentication"},
        {"name": "Analytics", "description": "Endpoints for real-time security analytics and dashboard data"},
        {"name": "ThreatDetection", "description": "AI-driven threat detection queries/results"},
        {"name": "Notifications", "description": "Incident and event alert notification center"},
        {"name": "Widgets", "description": "Dashboard widget data, charts, graphs, and heatmaps"},
        {"name": "Settings", "description": "User and dashboard preferences"},
        {"name": "Search", "description": "Search and filter analytics/events"},
        {"name": "Websockets", "description": "Real-time updates using WebSocket"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------------------
# Mock "Database"/State
# ----------------------------------------------------------------------------

FAKE_USERS_DB = {
    # Password is 'password' -> 'fakehashedpassword'
    "admin@example.com": {
        "id": "user1",
        "email": "admin@example.com",
        "hashed_password": "fakehashedpassword",  # should be fakehashed + password
        "full_name": "Admin User",
        "is_active": True,
    }
}

# In-memory cache for notifications, analytics, etc.
NOTIFICATIONS = []
THREAT_EVENTS = []
ANALYTICS_DATA = []

# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------

# -------------------- AUTH --------------------
class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserLogin(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    full_name: Optional[str] = None
    is_active: bool = True

class Token(BaseModel):
    access_token: str
    token_type: str

# ------------------- ANALYTICS -----------------
class AnalyticsQuery(BaseModel):
    timeframe: str = Field(..., description="Time window for analytics (e.g., '24h', '7d')")
    filters: Optional[Dict[str, Any]] = Field(None, description="Custom filters for analytics data")

class AnalyticsDataPoint(BaseModel):
    timestamp: datetime.datetime
    metric: str
    value: float

class AnalyticsResponse(BaseModel):
    data: List[AnalyticsDataPoint]

# ------------------- THREATS ------------------
class ThreatQuery(BaseModel):
    timeframe: str = Field(..., description="Time window for threat search")
    severity: Optional[str] = Field(None, description="Severity level filter (e.g., high, medium, low)")

class ThreatEvent(BaseModel):
    id: str
    timestamp: datetime.datetime
    type: str
    description: str
    severity: str
    ai_score: float

class ThreatDetectionResponse(BaseModel):
    events: List[ThreatEvent]

# ------------------- NOTIFICATIONS -------------
class Notification(BaseModel):
    id: str
    timestamp: datetime.datetime
    message: str
    severity: str
    read: bool = False

class NotificationResponse(BaseModel):
    notifications: List[Notification]

# ------------------- WIDGETS & DATA ------------
class WidgetDataRequest(BaseModel):
    widget_type: str
    params: Optional[Dict[str, Any]] = None

class WidgetDataResponse(BaseModel):
    widget_id: str
    data: Dict[str, Any]

# ------------------- SETTINGS ------------------
class SettingsUpdate(BaseModel):
    theme: Optional[str] = Field(None, description="UI theme, e.g., 'light' or 'dark'")
    notifications_enabled: Optional[bool] = True
    preferences: Optional[Dict[str, Any]] = None

class UserSettings(BaseModel):
    theme: str
    notifications_enabled: bool
    preferences: Dict[str, Any] = {}

# ------------------- SEARCH/FILTER -------------
class SearchQuery(BaseModel):
    query: str
    types: Optional[List[str]] = Field(None, description="Which data types (threats, notifications, analytics) to search in")
    filters: Optional[Dict[str, Any]] = None

class SearchResult(BaseModel):
    result_type: str
    content: Dict[str, Any]

class SearchResponse(BaseModel):
    results: List[SearchResult]

# ----------------------------------------------------------------------------
# UTILS - (Mock) simple security for demo
# ----------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def fake_hash_password(password: str) -> str:
    return "fakehashed" + password

def fake_decode_token(token: str):
    # Simple fake logic for demo
    for email, user in FAKE_USERS_DB.items():
        if token == f"token-{email}":
            return UserResponse(**user)
    return None

# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme)) -> UserResponse:
    """Gets the current user from the access token (mock implementation)."""
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    return user

# ----------------------------------------------------------------------------
# ROUTES
# ----------------------------------------------------------------------------

# -------------------- HEALTH ------------------------
@app.get("/", tags=["Analytics"])
def health_check():
    """Health check endpoint for service."""
    return {"message": "Healthy"}


# --------------------- AUTHENTICATION ---------------------

@app.post("/auth/register", tags=["Authentication"], response_model=UserResponse, summary="Register new user")
# PUBLIC_INTERFACE
def register_user(user: UserCreate):
    """Register a new user account."""
    if user.email in FAKE_USERS_DB:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = {
        "id": str(uuid.uuid4()),
        "email": user.email,
        "hashed_password": fake_hash_password(user.password),
        "full_name": "",
        "is_active": True,
    }
    FAKE_USERS_DB[user.email] = new_user
    return UserResponse(**new_user)

@app.post("/auth/token", tags=["Authentication"], response_model=Token, summary="User login for access token")
# PUBLIC_INTERFACE
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login to obtain an access token."""
    user_dict = FAKE_USERS_DB.get(form_data.username)
    if not user_dict or user_dict["hashed_password"] != fake_hash_password(form_data.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = f"token-{user_dict['email']}"
    return Token(access_token=access_token, token_type="bearer")


@app.get("/auth/me", tags=["Authentication"], response_model=UserResponse, summary="Get current user")
# PUBLIC_INTERFACE
def get_me(current_user: UserResponse = Depends(get_current_user)):
    """Return current authenticated user."""
    return current_user


# -------------------- ANALYTICS ------------------------

@app.post("/analytics/query", tags=["Analytics"], response_model=AnalyticsResponse, summary="Query real-time analytics")
# PUBLIC_INTERFACE
def query_analytics(payload: AnalyticsQuery, current_user: UserResponse = Depends(get_current_user)):
    """Get real-time analytics data based on query/filter parameters."""
    # For demonstration, generate some fake data
    now = datetime.datetime.utcnow()
    data = [
        AnalyticsDataPoint(
            timestamp=now - datetime.timedelta(minutes=5 * i),
            metric="intrusions_detected",
            value=float(i * 3)
        )
        for i in range(24)
    ]
    return AnalyticsResponse(data=data)


# -------------------- AI-DRIVEN THREAT DETECTION ------------------------

@app.post("/threats/query", tags=["ThreatDetection"], response_model=ThreatDetectionResponse, summary="Query AI-driven threat detections")
# PUBLIC_INTERFACE
def query_threats(payload: ThreatQuery, current_user: UserResponse = Depends(get_current_user)):
    """Obtain threat events detected by the AI model."""
    now = datetime.datetime.utcnow()
    events = [
        ThreatEvent(
            id=str(uuid.uuid4()),
            timestamp=now - datetime.timedelta(hours=i),
            type="Malware" if i % 2 == 0 else "Phishing",
            description="Sample threat event detected by AI.",
            severity="high" if i % 2 == 0 else "medium",
            ai_score=0.95 - 0.02 * i
        )
        for i in range(10)
    ]
    return ThreatDetectionResponse(events=events)


# -------------------- INCIDENT NOTIFICATION CENTER ------------------------

@app.get("/notifications", tags=["Notifications"], response_model=NotificationResponse, summary="Get notifications/incident alerts")
# PUBLIC_INTERFACE
def list_notifications(current_user: UserResponse = Depends(get_current_user)):
    """Get the list of incident notifications (latest first)."""
    # Return the notifications (mocked)
    return NotificationResponse(notifications=NOTIFICATIONS[-20:][::-1])


@app.post("/notifications", tags=["Notifications"], response_model=Notification, summary="Create a new notification")
# PUBLIC_INTERFACE
def create_notification(notification: Notification, current_user: UserResponse = Depends(get_current_user)):
    """Manually create/add a new notification (for demo/testing)."""
    NOTIFICATIONS.append(notification)
    return notification


@app.post("/notifications/mark_read", tags=["Notifications"], summary="Mark notifications as read")
# PUBLIC_INTERFACE
def mark_notifications_read(ids: List[str], current_user: UserResponse = Depends(get_current_user)):
    """Mark selected notifications as read."""
    updated = 0
    for n in NOTIFICATIONS:
        if n.id in ids:
            n.read = True
            updated += 1
    return {"updated": updated}


# -------------------- DASHBOARD WIDGETS & DATA ------------------------

@app.post("/widgets/data", tags=["Widgets"], response_model=WidgetDataResponse, summary="Get data for a dashboard widget")
# PUBLIC_INTERFACE
def widget_data(request: WidgetDataRequest, current_user: UserResponse = Depends(get_current_user)):
    """Endpoint to obtain data for a dashboard widget."""
    # Placeholder: return example data for known widget types
    if request.widget_type == "alerts_heatmap":
        data = {
            "regions": ["NA", "EMEA", "APAC"],
            "alert_counts": [12, 32, 13]
        }
    elif request.widget_type == "incidents_by_type":
        data = {
            "Malware": 18,
            "Phishing": 12,
            "Ransomware": 4
        }
    else:
        data = {"info": "Widget type not implemented."}
    return WidgetDataResponse(widget_id=str(uuid.uuid4()), data=data)


# -------------------- SETTINGS & PREFERENCES ------------------------

@app.get("/settings", tags=["Settings"], response_model=UserSettings, summary="Get user/dashboard settings")
# PUBLIC_INTERFACE
def get_settings(current_user: UserResponse = Depends(get_current_user)):
    """Get current settings/preferences for the user."""
    # Return mock settings for now
    return UserSettings(
        theme="light",
        notifications_enabled=True,
        preferences={}
    )

@app.post("/settings", tags=["Settings"], response_model=UserSettings, summary="Update settings/preferences")
# PUBLIC_INTERFACE
def update_settings(settings: SettingsUpdate, current_user: UserResponse = Depends(get_current_user)):
    """Update settings/preferences for the user (mock)."""
    # Save/return as if updated
    updated = UserSettings(
        theme=settings.theme or "light",
        notifications_enabled=settings.notifications_enabled if settings.notifications_enabled is not None else True,
        preferences=settings.preferences or {}
    )
    return updated


# -------------------- SEARCH & FILTER ------------------------

@app.post("/search", tags=["Search"], response_model=SearchResponse, summary="Search and filter dashboard data")
# PUBLIC_INTERFACE
def search_items(query: SearchQuery, current_user: UserResponse = Depends(get_current_user)):
    """Search across analytics, threats, or notifications."""
    results = []
    q = query.query.lower()
    if not query.types or "threats" in query.types:
        for event in THREAT_EVENTS:
            if q in event.description.lower():
                results.append(SearchResult(result_type="threat", content=event.dict()))
    if not query.types or "notifications" in query.types:
        for notif in NOTIFICATIONS:
            if q in notif.message.lower():
                results.append(SearchResult(result_type="notification", content=notif.dict()))
    # Analytics omitted (mock)
    return SearchResponse(results=results)


# -------------------- REAL-TIME: WebSocket for Live Notifications ------------------------

# For demo: send new notifications over websocket

# Keep a set of connected websocket clients
LIVE_NOTIFICATION_CONNECTIONS = set()

@app.websocket("/ws/notifications")
# PUBLIC_INTERFACE
async def websocket_notifications_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for receiving real-time incident notifications.

    Usage Notes:
    - Connect as an authenticated user and receive real-time incident alerts.
    - No authentication is enforced in the mock; production should check token.
    """
    await websocket.accept()
    LIVE_NOTIFICATION_CONNECTIONS.add(websocket)
    try:
        while True:
            _ = await websocket.receive_text()  # simply keep connection alive
    except WebSocketDisconnect:
        LIVE_NOTIFICATION_CONNECTIONS.remove(websocket)

@app.post("/notifications/push", tags=["Notifications"], summary="Push a new notification to WebSocket clients (demo)")
# PUBLIC_INTERFACE
async def push_notification_to_ws(notification: Notification, current_user: UserResponse = Depends(get_current_user)):
    """Push a notification to all connected websocket clients (demo/POC)."""
    NOTIFICATIONS.append(notification)
    for ws in LIVE_NOTIFICATION_CONNECTIONS.copy():
        try:
            await ws.send_json(notification.dict())
        except Exception:
            LIVE_NOTIFICATION_CONNECTIONS.discard(ws)
    return {"delivered": True, "id": notification.id}


# -------------------- API DOCS HELP FOR REAL-TIME/WS ------------------------

@app.get("/help/websocket", tags=["Websockets"], summary="Websocket API usage information")
def websocket_help():
    """
    Information on WebSocket endpoints for real-time updates:
    - `/ws/notifications` : Real-time incident alert notifications.
    Connect using a websocket protocol (wss://...).
    """
    return {
        "websocket_endpoints": [
            {
                "url": "/ws/notifications",
                "description": "Live streaming of incident/alert notifications in real time."
            }
        ]
    }

# END OF FILE

