import json
import os
import traceback

import google.oauth2.credentials
import google_auth_oauthlib.flow
import requests as http_requests
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build

# ── Allow plain HTTP on localhost (local dev only) ───────────────────────────
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# ── Config ───────────────────────────────────────────────────────────────────
CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = [
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.events",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]
REDIRECT_URI = "http://localhost:8080/callback"
TOKENS_DIR = "tokens"

_flows: dict[str, google_auth_oauthlib.flow.Flow] = {}

app = FastAPI(title="Google Calendar OAuth Server")
os.makedirs(TOKENS_DIR, exist_ok=True)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _token_path(email: str) -> str:
    safe_name = email.replace("@", "_at_").replace(".", "_")
    return os.path.join(TOKENS_DIR, f"{safe_name}.json")


def _save_tokens(email: str, creds: google.oauth2.credentials.Credentials) -> None:
    data = {
        "email":         email,
        "access_token":  creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri":     creds.token_uri,
        "client_id":     creds.client_id,
        "client_secret": creds.client_secret,
        "scopes":        list(creds.scopes) if creds.scopes else [],
        "expiry":        creds.expiry.isoformat() if creds.expiry else None,
    }
    with open(_token_path(email), "w") as f:
        json.dump(data, f, indent=4)


def _load_credentials(email: str) -> google.oauth2.credentials.Credentials | None:
    path = _token_path(email)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    creds = google.oauth2.credentials.Credentials(
        token=data["access_token"],
        refresh_token=data["refresh_token"],
        token_uri=data["token_uri"],
        client_id=data["client_id"],
        client_secret=data["client_secret"],
        scopes=data["scopes"],
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())
        _save_tokens(email, creds)
    return creds


def _get_authenticated_users() -> list[str]:
    users = []
    for fname in os.listdir(TOKENS_DIR):
        if fname.endswith(".json"):
            with open(os.path.join(TOKENS_DIR, fname)) as f:
                try:
                    email = json.load(f).get("email")
                    if email:
                        users.append(email)
                except Exception:
                    pass
    return users


def _get_user_email(access_token: str) -> str | None:
    resp = http_requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if resp.ok:
        return resp.json().get("email")
    return None


# ── Shared CSS ───────────────────────────────────────────────────────────────
BASE_CSS = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Segoe UI', system-ui, sans-serif;
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        padding: 24px;
    }
    .card {
        background: rgba(255,255,255,0.07);
        backdrop-filter: blur(14px);
        border: 1px solid rgba(255,255,255,0.13);
        border-radius: 24px;
        padding: 44px 52px;
        width: 100%;
        box-shadow: 0 28px 64px rgba(0,0,0,0.45);
    }
    h1 { font-size: 1.8rem; font-weight: 700; margin-bottom: 6px; }
    .sub { color: rgba(255,255,255,.55); font-size: .95rem; margin-bottom: 32px; }
    a.btn, button.btn {
        display: inline-block;
        background: linear-gradient(90deg, #4285f4, #34a853);
        color: #fff;
        text-decoration: none;
        padding: 13px 32px;
        border-radius: 50px;
        font-weight: 600;
        font-size: .95rem;
        border: none;
        cursor: pointer;
        transition: opacity .2s, transform .15s;
        box-shadow: 0 4px 20px rgba(66,133,244,.45);
    }
    a.btn:hover, button.btn:hover { opacity: .88; transform: translateY(-2px); }
    a.btn-outline {
        display: inline-block;
        border: 1px solid rgba(255,255,255,.25);
        color: rgba(255,255,255,.75);
        text-decoration: none;
        padding: 10px 24px;
        border-radius: 50px;
        font-size: .85rem;
        transition: background .2s;
    }
    a.btn-outline:hover { background: rgba(255,255,255,.08); }
"""


# ─────────────────────────────────────────────────────────────────────────────
# Root – landing page
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root():
    users = _get_authenticated_users()

    user_options_html = "".join(
        f'<option value="{u}">{u}</option>' for u in users
    )

    user_list_html = ""
    if users:
        items = "".join(f"<li>{u}</li>" for u in users)
        user_list_html = f"""
        <div class="user-list">
            <div class="ul-label">Authenticated accounts</div>
            <ul>{items}</ul>
        </div>"""

    create_section = ""
    if users:
        create_section = """
        <div class="divider"></div>
        <a class="btn" href="/create-event" id="create-event-btn" style="background:linear-gradient(90deg,#9333ea,#ec4899);">
            📅 &nbsp;Create Calendar Event
        </a>"""

    html = f"""
    <!doctype html><html lang="en">
    <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Google Calendar Auth</title>
        <style>
            {BASE_CSS}
            .card {{ max-width: 500px; text-align: center; }}
            .logo {{ font-size: 54px; margin-bottom: 18px; }}
            .divider {{ height: 1px; background: rgba(255,255,255,.1); margin: 28px 0; }}
            .user-list {{ background: rgba(0,0,0,.25); border-radius: 14px; padding: 14px 20px;
                          text-align: left; margin-top: 24px; }}
            .ul-label {{ font-size: .72rem; text-transform: uppercase; letter-spacing: .08em;
                         color: rgba(255,255,255,.4); margin-bottom: 8px; }}
            .user-list ul {{ list-style: none; padding: 0; }}
            .user-list li {{ font-size: .85rem; color: #a5f3fc; padding: 3px 0; }}
            .user-list li::before {{ content: "✓ "; color: #4ade80; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="logo">📅</div>
            <h1>Calendar API Auth</h1>
            <p class="sub">Authorise access to Google Calendar — each user's credentials are stored separately.</p>
            <a class="btn" href="/login" id="login-btn">Sign in with Google</a>
            {user_list_html}
            {create_section}
        </div>
    </body></html>
    """
    return HTMLResponse(content=html)


# ─────────────────────────────────────────────────────────────────────────────
# /login
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/login")
async def login():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI,
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline", prompt="consent",
    )
    _flows[state] = flow
    return RedirectResponse(authorization_url)


# ─────────────────────────────────────────────────────────────────────────────
# /callback
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/callback")
async def callback(request: Request):
    state = request.query_params.get("state", "")
    error = request.query_params.get("error", "")

    if error:
        return JSONResponse(status_code=400,
                            content={"error": "Access denied", "details": error})
    if state not in _flows:
        return JSONResponse(status_code=403,
                            content={"error": "Invalid state. Start again via /login"})

    flow = _flows.pop(state)
    try:
        flow.fetch_token(authorization_response=str(request.url))
    except Exception as exc:
        return JSONResponse(status_code=500,
                            content={"error": "Token exchange failed", "details": str(exc),
                                     "traceback": traceback.format_exc()})

    creds = flow.credentials
    email = _get_user_email(creds.token) or "unknown_user"
    _save_tokens(email, creds)

    access_token  = creds.token or "N/A"
    refresh_token = creds.refresh_token or "N/A – already issued previously"
    expiry        = creds.expiry.isoformat() if creds.expiry else "N/A"
    safe_fname    = email.replace("@", "_at_").replace(".", "_") + ".json"

    html = f"""
    <!doctype html><html lang="en">
    <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Authenticated</title>
        <style>
            {BASE_CSS}
            .card {{ max-width: 660px; }}
            .badge {{ font-size: 46px; margin-bottom: 10px; }}
            h1 {{ color: #4ade80; }}
            .email-tag {{ color: #a5f3fc; font-size: .9rem; margin-bottom: 22px; }}
            .token-box {{ background: rgba(0,0,0,.3); border: 1px solid rgba(255,255,255,.1);
                          border-radius: 12px; padding: 14px 18px; margin-bottom: 12px; word-break: break-all; }}
            .label {{ font-size: .7rem; text-transform: uppercase; letter-spacing: .08em;
                      color: rgba(255,255,255,.4); margin-bottom: 5px; }}
            .value {{ font-size: .82rem; color: #a5f3fc; font-family: monospace; line-height: 1.6; }}
            .expiry {{ font-size: .75rem; color: #fbbf24; margin-top: 4px; }}
            .note {{ font-size: .78rem; color: rgba(255,255,255,.35); margin-top: 18px; }}
            .actions {{ display: flex; gap: 12px; margin-top: 24px; flex-wrap: wrap; }}
            code {{ background: rgba(255,255,255,.1); border-radius: 4px; padding: 1px 6px; font-size:.85em; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="badge">✅</div>
            <h1>Authentication Successful!</h1>
            <div class="email-tag">Signed in as <strong>{email}</strong></div>
            <p class="sub">Saved to <code>tokens/{safe_fname}</code></p>

            <div class="token-box">
                <div class="label">Access Token</div>
                <div class="value">{access_token}</div>
                <div class="expiry">⏱ Expires: {expiry} &nbsp;(auto-refreshed on next API call)</div>
            </div>
            <div class="token-box">
                <div class="label">Refresh Token &nbsp;(long-lived)</div>
                <div class="value">{refresh_token}</div>
            </div>

            <div class="note">⚠️ Keep tokens secret.</div>
            <div class="actions">
                <a class="btn" href="/create-event"
                   style="background:linear-gradient(90deg,#9333ea,#ec4899);">📅 Create Event</a>
                <a class="btn-outline" href="/">← Home</a>
            </div>
        </div>
    </body></html>
    """
    return HTMLResponse(content=html)


# ─────────────────────────────────────────────────────────────────────────────
# GET /create-event – HTML form
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/create-event", response_class=HTMLResponse)
async def create_event_form():
    users = _get_authenticated_users()
    if not users:
        return HTMLResponse(
            content="""<html><body style="font-family:sans-serif;padding:40px;color:#fff;
            background:#1a1a2e;"><h2>No authenticated users found.</h2>
            <p>Please <a href="/login" style="color:#4285f4;">sign in first</a>.</p></body></html>""",
            status_code=403,
        )

    user_options = "".join(f'<option value="{u}">{u}</option>' for u in users)

    html = f"""
    <!doctype html><html lang="en">
    <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Create Calendar Event</title>
        <style>
            {BASE_CSS}
            .card {{ max-width: 680px; }}
            h1 {{ font-size: 1.6rem; }}
            .form-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-top: 28px; }}
            .form-grid .full {{ grid-column: 1 / -1; }}
            label {{ display: block; font-size: .75rem; text-transform: uppercase;
                     letter-spacing: .07em; color: rgba(255,255,255,.45); margin-bottom: 6px; }}
            input, select, textarea {{
                width: 100%;
                background: rgba(255,255,255,.07);
                border: 1px solid rgba(255,255,255,.15);
                border-radius: 10px;
                color: #fff;
                padding: 11px 14px;
                font-size: .92rem;
                outline: none;
                transition: border-color .2s;
                font-family: inherit;
            }}
            input:focus, select:focus, textarea:focus {{
                border-color: rgba(66,133,244,.7);
                background: rgba(255,255,255,.1);
            }}
            textarea {{ resize: vertical; min-height: 90px; }}
            select option {{ background: #302b63; }}
            .hint {{ font-size: .74rem; color: rgba(255,255,255,.35); margin-top: 5px; }}
            .actions {{ display: flex; gap: 14px; margin-top: 30px; align-items: center; }}
            #status {{ display: none; margin-top: 20px; padding: 16px 20px;
                       border-radius: 12px; font-size: .9rem; }}
            #status.success {{ background: rgba(74,222,128,.12); border: 1px solid rgba(74,222,128,.3);
                               color: #4ade80; }}
            #status.error   {{ background: rgba(248,113,113,.12); border: 1px solid rgba(248,113,113,.3);
                               color: #f87171; }}
            .spinner {{ display: none; width: 20px; height: 20px; border: 3px solid rgba(255,255,255,.2);
                        border-top-color: #fff; border-radius: 50%; animation: spin .7s linear infinite; }}
            @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        </style>
    </head>
    <body>
        <div class="card">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;">
                <span style="font-size:36px;">📅</span>
                <h1>Create Calendar Event</h1>
            </div>
            <p class="sub">Fill in the details below — an invite email will be sent to all attendees automatically.</p>

            <form id="event-form">
                <div class="form-grid">

                    <div class="full">
                        <label>Organiser (your authenticated account)</label>
                        <select name="organizer_email" id="organizer_email" required>
                            {user_options}
                        </select>
                    </div>

                    <div class="full">
                        <label>Event Title *</label>
                        <input type="text" name="title" id="title"
                               placeholder="e.g. Q2 Planning Meeting" required />
                    </div>

                    <div class="full">
                        <label>Description</label>
                        <textarea name="description" id="description"
                                  placeholder="Agenda, notes or any details…"></textarea>
                    </div>

                    <div>
                        <label>Start Date & Time *</label>
                        <input type="datetime-local" name="start_datetime" id="start_datetime" required />
                    </div>

                    <div>
                        <label>End Date & Time *</label>
                        <input type="datetime-local" name="end_datetime" id="end_datetime" required />
                    </div>

                    <div class="full">
                        <label>Timezone</label>
                        <select name="timezone" id="timezone">
                            <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
                            <option value="UTC">UTC</option>
                            <option value="America/New_York">America/New_York (EST)</option>
                            <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
                            <option value="Europe/London">Europe/London (GMT)</option>
                            <option value="Europe/Berlin">Europe/Berlin (CET)</option>
                            <option value="Asia/Singapore">Asia/Singapore (SGT)</option>
                            <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
                        </select>
                    </div>

                    <div class="full">
                        <label>Attendee Emails *</label>
                        <input type="text" name="attendees" id="attendees"
                               placeholder="alice@example.com, bob@example.com" required />
                        <div class="hint">Separate multiple emails with commas. Each will receive a Google Calendar invite.</div>
                    </div>

                </div>

                <div class="actions">
                    <button type="submit" class="btn" id="submit-btn">
                        🚀 &nbsp;Create Event & Send Invites
                    </button>
                    <div class="spinner" id="spinner"></div>
                    <a class="btn-outline" href="/">← Home</a>
                </div>
            </form>

            <div id="status"></div>
        </div>

        <script>
            // Pre-fill datetime to now + 1 hour
            const now = new Date();
            const pad = n => String(n).padStart(2, '0');
            const fmt = d => `${{d.getFullYear()}}-${{pad(d.getMonth()+1)}}-${{pad(d.getDate())}}T${{pad(d.getHours())}}:${{pad(d.getMinutes())}}`;
            const start = new Date(now.getTime() + 60*60*1000);
            const end   = new Date(now.getTime() + 2*60*60*1000);
            document.getElementById('start_datetime').value = fmt(start);
            document.getElementById('end_datetime').value   = fmt(end);

            document.getElementById('event-form').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const btn     = document.getElementById('submit-btn');
                const spinner = document.getElementById('spinner');
                const status  = document.getElementById('status');

                btn.disabled  = true;
                spinner.style.display = 'block';
                status.style.display  = 'none';

                const body = new URLSearchParams(new FormData(e.target));

                try {{
                    const res = await fetch('/create-event', {{
                        method: 'POST',
                        body: body,
                        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                    }});
                    const data = await res.json();

                    status.style.display = 'block';
                    if (res.ok) {{
                        status.className = 'success';
                        status.innerHTML = `✅ <strong>Event created!</strong><br>
                            🔗 <a href="${{data.event_link}}" target="_blank"
                               style="color:#a5f3fc;">Open in Google Calendar</a><br>
                            📧 Invite emails sent to all attendees.`;
                    }} else {{
                        status.className = 'error';
                        status.innerHTML = `❌ <strong>Error:</strong> ${{data.error || JSON.stringify(data)}}`;
                    }}
                }} catch (err) {{
                    status.style.display = 'block';
                    status.className = 'error';
                    status.innerHTML = `❌ <strong>Network error:</strong> ${{err.message}}`;
                }} finally {{
                    btn.disabled = false;
                    spinner.style.display = 'none';
                }}
            }});
        </script>
    </body></html>
    """
    return HTMLResponse(content=html)


# ─────────────────────────────────────────────────────────────────────────────
# POST /create-event – create the event via Google Calendar API
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/create-event")
async def create_event(
    organizer_email: str = Form(...),
    title:           str = Form(...),
    description:     str = Form(""),
    start_datetime:  str = Form(...),   # "YYYY-MM-DDTHH:MM"
    end_datetime:    str = Form(...),
    timezone:        str = Form("Asia/Kolkata"),
    attendees:       str = Form(...),   # comma-separated emails
):
    # Load credentials for the organiser
    creds = _load_credentials(organizer_email)
    if creds is None:
        return JSONResponse(
            status_code=404,
            content={"error": f"No credentials found for {organizer_email}. Please authenticate first."},
        )

    # Parse attendee list
    attendee_emails = [e.strip() for e in attendees.split(",") if e.strip()]
    if not attendee_emails:
        return JSONResponse(status_code=400, content={"error": "At least one attendee email is required."})

    # Build event payload
    event_body = {
        "summary":     title,
        "description": description,
        "start": {
            "dateTime": start_datetime + ":00",   # append seconds
            "timeZone": timezone,
        },
        "end": {
            "dateTime": end_datetime + ":00",
            "timeZone": timezone,
        },
        "attendees": [{"email": e} for e in attendee_emails],
        "reminders": {
            "useDefault": False,
            "overrides": [
                {"method": "email",  "minutes": 24 * 60},  # 1 day before
                {"method": "popup",  "minutes": 30},
            ],
        },
    }

    try:
        service = build("calendar", "v3", credentials=creds)
        created = service.events().insert(
            calendarId="primary",
            body=event_body,
            sendUpdates="all",      # ← Google sends email invites to all attendees
        ).execute()
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"error": str(exc), "traceback": traceback.format_exc()},
        )

    return JSONResponse(content={
        "message":    "Event created successfully",
        "event_id":   created.get("id"),
        "event_link": created.get("htmlLink"),
        "title":      created.get("summary"),
        "start":      created["start"].get("dateTime"),
        "end":        created["end"].get("dateTime"),
        "attendees":  attendee_emails,
    })


# ─────────────────────────────────────────────────────────────────────────────
# /tokens – list all authenticated users
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/tokens")
async def list_tokens():
    users = []
    for fname in os.listdir(TOKENS_DIR):
        if fname.endswith(".json"):
            path = os.path.join(TOKENS_DIR, fname)
            with open(path) as f:
                try:
                    data = json.load(f)
                    users.append({
                        "email":      data.get("email"),
                        "expiry":     data.get("expiry"),
                        "scopes":     data.get("scopes"),
                        "token_file": fname,
                    })
                except Exception:
                    pass
    return JSONResponse(content={"authenticated_users": users})


# ─────────────────────────────────────────────────────────────────────────────
# /tokens/{email} – get valid (auto-refreshed) token for one user
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/tokens/{email:path}")
async def get_user_token(email: str):
    creds = _load_credentials(email)
    if creds is None:
        return JSONResponse(
            status_code=404,
            content={"error": f"No tokens found for {email}. Authenticate via /login"},
        )
    path = _token_path(email)
    with open(path) as f:
        data = json.load(f)
    return JSONResponse(content={
        "email":         email,
        "access_token":  data["access_token"],
        "refresh_token": data["refresh_token"],
        "expiry":        data["expiry"],
        "scopes":        data["scopes"],
    })


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="localhost", port=8080, reload=True)
