"""
Better Impact — HR Induction Completed Notification
====================================================
Polls the Better Impact API every 30 minutes (via GitHub Actions cron).
When 'Immediate' fields change (HR Induction Date, Registration Form), sending an immediate notification.
A Daily Digest of all other changes and stalled workflows is sent at 8:00 AM (Australia/Perth).

State is stored in state.json and committed back to the repo after each run,
so the previous values are remembered between runs.

Required GitHub Actions secrets:
  BI_API_USERNAME   — Better Impact API key username
  BI_API_PASSWORD   — Better Impact API key password
  SMTP_HOST         — e.g. smtp.office365.com
  SMTP_PORT         — e.g. 587
  SMTP_USERNAME     — sending email address
  SMTP_PASSWORD     — sending email password
  NOTIFY_EMAIL      — supervisor's email address
  STATE_PASSWORD    — password used to encrypt state.json and dashboard.json

Optional:
  BI_ORG_ID         — your Better Impact organisation ID (if required by your account)
"""

import os
import json
import base64
import smtplib
import requests
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ── Configuration ─────────────────────────────────────────────────────────────

# Name of the custom field exactly as it appears in Better Impact
HR_FIELD_NAME = "HR Induction Date"

# Site Induction field — set to None to disable monitoring
SITE_FIELD_NAME = "Site Induction Date"

# Supervisor Interview Outcome (Drop Down) — set to None to disable monitoring
SUPERVISOR_FIELD_NAME = "Supervisor Interview Outcome"

# Registration Form signature (Signed Document) — set to None to disable monitoring
REGISTRATION_FIELD_NAME = "Registration Form - Sign"

# Fields that trigger an immediate email when changed from empty
IMMEDIATE_FIELDS = {REGISTRATION_FIELD_NAME, HR_FIELD_NAME, SITE_FIELD_NAME, SUPERVISOR_FIELD_NAME}

# Fields that indicate a form submission (shown separately in the email)
FORM_SUBMISSION_FIELDS = {REGISTRATION_FIELD_NAME}

# Better Impact API base URL
API_BASE = "https://api.betterimpact.com/v1"

# State file path — committed back to repo to persist between runs
STATE_FILE = "state.json"

# Timezone for daily digest scheduling and timestamps
TZ = ZoneInfo("Australia/Perth")

# ── Encryption & Decryption ───────────────────────────────────────────────────

def get_encryption_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_data(data_dict, password: str):
    data_bytes = json.dumps(data_dict).encode('utf-8')
    salt = os.urandom(16)
    key = get_encryption_key(password, salt)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data_bytes) + encryptor.finalize()
    
    return {
        "encrypted": True,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(encryptor.tag).decode('utf-8')
    }

def decrypt_data(encrypted_payload, password: str):
    try:
        salt = base64.b64decode(encrypted_payload["salt"])
        iv = base64.b64decode(encrypted_payload["iv"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
        tag = base64.b64decode(encrypted_payload["tag"])
        
        key = get_encryption_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        print(f"Decryption failed. Please check your STATE_PASSWORD! Error: {e}")
        return None

# ── Dashboard Utilities ───────────────────────────────────────────────────────

def anonymize_name(full_name):
    """Obscure last name for privacy on public dashboards."""
    if not full_name:
        return "Unknown"
    parts = full_name.split()
    if len(parts) > 1:
        return f"{parts[0]} {parts[-1][0]}."
    return full_name

def update_dashboard_json(state, now, api_ok, email_ok):
    new_apps = []
    awaiting_hr = []
    awaiting_site = []
    
    users = state.get("users", {})
    for _, info in users.items():
        name = info.get("name", "Unknown")
        fields = info.get("fields", {})
        reg = fields.get(REGISTRATION_FIELD_NAME, {}).get("value")
        outcome = fields.get(SUPERVISOR_FIELD_NAME, {}).get("value")
        hr = fields.get(HR_FIELD_NAME, {}).get("value")
        site = fields.get(SITE_FIELD_NAME, {}).get("value")
        
        if reg and not outcome:
            new_apps.append(name)
        if outcome == "Passed" and not hr:
            awaiting_hr.append(name)
        if hr and not site:
            awaiting_site.append(name)
            
    dash_data = {
        "workflow_status": {
            "new_applications": new_apps,
            "awaiting_hr_induction": awaiting_hr,
            "awaiting_site_induction": awaiting_site
        },
        "recent_activity": state.get("dashboard_activity", {"field_changes": [], "form_submissions": []}),
        "system_health": {
            "last_poll_time": now.isoformat(),
            "api_status_ok": api_ok,
            "email_status_ok": email_ok
        }
    }
    
    docs_dir = os.path.join(os.path.dirname(__file__), "docs")
    os.makedirs(docs_dir, exist_ok=True)
    
    password = os.environ.get("STATE_PASSWORD")
    if password:
        final_payload = encrypt_data(dash_data, password)
    else:
        final_payload = dash_data

    with open(os.path.join(docs_dir, "dashboard.json"), "w") as f:
        json.dump(final_payload, f, indent=2)
    print("Dashboard JSON updated.")

# ── API ───────────────────────────────────────────────────────────────────────

def get_volunteers():
    """Fetch all volunteer profiles with custom fields from Better Impact."""
    username = os.environ["BI_API_USERNAME"]
    password = os.environ["BI_API_PASSWORD"]

    url = f"{API_BASE}/organization/users/"
    params = {
        "modules": "volunteer",   
        "page_size": 200,
        "page_number": 0,         
    }

    all_users = []

    while True:
        response = requests.get(url, auth=(username, password), params=params)
        response.raise_for_status()
        data = response.json()

        users = data.get("users", [])
        all_users.extend(users)

        header = data.get("header", {})
        if not header.get("has_next_page", False):
            break

        params["page_number"] += 1

    print(f"Fetched {len(all_users)} volunteer profiles")
    return all_users


def extract_custom_field(user, field_name):
    """
    Extract a custom field value from a volunteer profile.
    Per API docs, custom fields have: custom_field_name, value, type, etc.
    """
    if not field_name:
        return ""
    custom_fields = user.get("custom_fields", [])
    for field in custom_fields:
        name = field.get("custom_field_name", "").strip().lower()
        if name == field_name.strip().lower():
            return field.get("value") or ""

    return ""

# ── State ─────────────────────────────────────────────────────────────────────

def load_state():
    """Load the previous state snapshot from state.json."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            data = json.load(f)
            
            # Check if state is encrypted
            if data.get("encrypted"):
                password = os.environ.get("STATE_PASSWORD")
                if not password:
                    print("ERROR: STATE_PASSWORD not set, but state is encrypted. Cannot continue.")
                    exit(1)
                decrypted_data = decrypt_data(data, password)
                if not decrypted_data:
                    exit(1)
                data = decrypted_data
            
            # Migrate old format if necessary
            if "users" not in data:
                print("Migrating old state format to new format with timestamps.")
                new_state = {
                    "users": {},
                    "digest_queue": [],
                    "last_digest_date": "",
                    "dashboard_activity": {"field_changes": [], "form_submissions": []}
                }
                now_str = datetime.now(TZ).isoformat()
                for user_id, info in data.items():
                    if not isinstance(info, dict) or "fields" not in info:
                        continue
                    new_fields = {}
                    for fname, fval in info.get("fields", {}).items():
                        new_fields[fname] = {
                            "value": fval,
                            "updated_at": now_str
                        }
                    new_state["users"][user_id] = {
                        "name": info.get("name", ""),
                        "fields": new_fields
                    }
                return new_state
            return data
            
    return {"users": {}, "digest_queue": [], "last_digest_date": "", "dashboard_activity": {"field_changes": [], "form_submissions": []}}


def save_state(state):
    """Save the current state snapshot to state.json."""
    password = os.environ.get("STATE_PASSWORD")
    if password:
        final_payload = encrypt_data(state, password)
    else:
        final_payload = state
        
    with open(STATE_FILE, "w") as f:
        json.dump(final_payload, f, indent=2)
    print(f"State saved: {len(state.get('users', {}))} volunteers tracked")

# ── Email ─────────────────────────────────────────────────────────────────────

def get_smtp_config():
    return {
        "smtp_host": os.environ["SMTP_HOST"],
        "smtp_port": int(os.environ["SMTP_PORT"]),
        "smtp_username": os.environ["SMTP_USERNAME"],
        "smtp_password": os.environ["SMTP_PASSWORD"],
        "notify_email": os.environ["NOTIFY_EMAIL"],
    }

def send_email(subject, body):
    config = get_smtp_config()
    msg = MIMEMultipart()
    msg["From"]    = "City of Kwinana Volunteer Centre <malachymcgrath286@gmail.com>"
    msg["To"]      = config["notify_email"]
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(config["smtp_host"], config["smtp_port"]) as server:
            server.starttls()
            server.login(config["smtp_username"], config["smtp_password"])
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send notification: {e}")
        raise

def send_immediate_notification(changes):
    """Send immediate email for critical changes."""
    form_submissions = []
    induction_updates = []
    for change in changes:
        volunteer_name = change["volunteer_name"]
        field_name = change["field_name"]
        old_val = change["previous_value"] if change.get("previous_value") else "(empty)"
        new_val = change["new_value"]
        
        if field_name in FORM_SUBMISSION_FIELDS:
            form_submissions.append(f"<li><strong>{volunteer_name}</strong> submitted {field_name}<br><em>(Changed from '{old_val}' to '{new_val}')</em></li>")
        else:
            induction_updates.append(f"<li><strong>{volunteer_name}</strong><br>Field: {field_name}<br>Changed: <em>'{old_val}'</em> &rarr; <em>'{new_val}'</em></li>")

    parts = []
    if form_submissions:
        parts.append(f"{len(form_submissions)} form submission(s)")
    if induction_updates:
        parts.append(f"{len(induction_updates)} induction update(s)")
    subject = f"Better Impact Notification — {' & '.join(parts)}"

    body = "<p>Hi,</p><p>This is an automated notification from the City of Kwinana Volunteer Centre.</p>"

    if form_submissions:
        body += "<h3>Form Submissions</h3><ul>" + "".join(form_submissions) + "</ul>"
    if induction_updates:
        body += "<h3>Induction Updates</h3><ul>" + "".join(induction_updates) + "</ul>"

    body += (
        f"<p>Recorded: {datetime.now(TZ).strftime('%d/%m/%Y %H:%M')}</p>"
        f"<p>You can view volunteer profiles by logging into Better Impact.</p><hr>"
        f"<p><small>Automatically sent by the Volunteer Centre monitoring script.</small></p>"
    )

    send_email(subject, body)
    print(f"Immediate notification sent — {len(changes)} change(s)")

def send_daily_digest(digest_queue, stalled_workflows):
    """Send summary digest of all non-critical changes and stalled workflows."""
    subject = "Better Impact — Daily Digest & Stalled Workflows"
    
    body = "<p>Hi,</p><p>Here is your daily summary of volunteer profile changes and stalled workflows.</p>"

    body += "<h3>Stalled Workflows (Action Required)</h3>"
    if stalled_workflows:
        body += "<ul>"
        for wf in stalled_workflows:
            body += f"<li><strong>{wf['name']}</strong> ({wf['type']})<br>Details: {wf['reason']}</li>"
        body += "</ul>"
    else:
        body += "<p>No stalled workflows found.</p>"

    body += "<h3>Changes in Last 24 Hours</h3>"
    if digest_queue:
        body += "<ul>"
        for change in digest_queue:
            old_val = change['previous_value'] if change.get('previous_value') else "(empty)"
            new_val = change['new_value']
            body += f"<li><strong>{change['volunteer_name']}</strong><br>{change['field_name']}: <em>'{old_val}'</em> &rarr; <em>'{new_val}'</em></li>"
        body += "</ul>"
    else:
        body += "<p>No non-critical changes in the last 24 hours.</p>"

    body += (
        f"<p>Generated: {datetime.now(TZ).strftime('%d/%m/%Y %H:%M')}</p>"
        f"<p>You can view volunteer profiles by logging into Better Impact.</p><hr>"
        f"<p><small>Automatically sent by the Volunteer Centre monitoring script.</small></p>"
    )

    send_email(subject, body)
    print(f"Daily digest sent — {len(digest_queue)} changes, {len(stalled_workflows)} stalled workflows")

# ── Stalled Workflows ─────────────────────────────────────────────────────────

def check_stalled_workflows(users_state, now, true_names_map=None):
    """
    Check for:
    1. Application Stalled: V1 submitted (>5 days ago), but no Interview Outcome.
    2. Accepted but Induction Incomplete: Supervisor Outcome is 'Passed' (>7 days ago), but no HR Induction Date.
    """
    stalled = []
    
    for user_id, info in users_state.items():
        base_name = info.get("name", "Unknown")
        name = true_names_map.get(user_id, base_name) if true_names_map else base_name
        fields = info.get("fields", {})
        
        reg_form = fields.get(REGISTRATION_FIELD_NAME, {})
        outcome = fields.get(SUPERVISOR_FIELD_NAME, {})
        hr_ind = fields.get(HR_FIELD_NAME, {})

        # 1. Application Stalled
        if reg_form.get("value") and not outcome.get("value"):
            try:
                update_time = datetime.fromisoformat(reg_form.get("updated_at"))
                if (now - update_time).days >= 5:
                    stalled.append({
                        "name": name,
                        "type": "Application Stalled",
                        "reason": f"Registration form submitted {(now - update_time).days} days ago, but no Interview Outcome."
                    })
            except (ValueError, TypeError):
                pass
                
        # 2. Accepted but Induction Incomplete
        if outcome.get("value") == "Passed" and not hr_ind.get("value"):
            try:
                update_time = datetime.fromisoformat(outcome.get("updated_at"))
                if (now - update_time).days >= 7:
                    stalled.append({
                        "name": name,
                        "type": "Induction Incomplete",
                        "reason": f"Interview passed {(now - update_time).days} days ago, but HR Induction Date is blank."
                    })
            except (ValueError, TypeError):
                pass
                
    return stalled

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    now = datetime.now(TZ)
    print(f"Poll started at {now.strftime('%d/%m/%Y %H:%M')}")

    fields_to_monitor = [f for f in [HR_FIELD_NAME, SITE_FIELD_NAME, SUPERVISOR_FIELD_NAME, REGISTRATION_FIELD_NAME] if f]

    state = load_state()
    if "dashboard_activity" not in state:
        state["dashboard_activity"] = {"field_changes": [], "form_submissions": []}

    previous_users = state.get("users", {})
    digest_queue = state.get("digest_queue", [])
    
    current_users = {}
    immediate_changes = []

    api_ok = True
    email_ok = True
    
    try:
        volunteers = get_volunteers()
    except Exception as e:
        print(f"Failed to fetch volunteers: {e}")
        api_ok = False
        volunteers = []

    if not api_ok:
        print("API offline: Preserving state to prevent data wipe.")
        update_dashboard_json(state, now, api_ok, email_ok)
        exit(1)

    for user in volunteers:
        if not isinstance(user, dict):
            continue
        user_id   = str(user.get("user_id", ""))
        raw_name = (
            f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
            or user.get("name", f"Volunteer {user_id}")
        )
        anon_name = anonymize_name(raw_name)

        if not user_id:
            continue

        current_users[user_id] = {"name": anon_name, "fields": {}}

        for field_name in fields_to_monitor:
            current_value = extract_custom_field(user, field_name)
            
            prev_field_data = previous_users.get(user_id, {}).get("fields", {}).get(field_name, {})
            # Handle if previous was somehow string
            previous_value = prev_field_data.get("value", "") if isinstance(prev_field_data, dict) else prev_field_data
            previous_updated_at = prev_field_data.get("updated_at", now.isoformat()) if isinstance(prev_field_data, dict) else now.isoformat()

            if current_value != previous_value:
                # Value changed
                new_updated_at = now.isoformat()
                
                # We only alert on changes TO a value (not to blank) for most things, or any change?
                # The user previously wanted "notify on any value change rather than only initial submissions".
                if current_value:
                    print(f"Change detected: {raw_name} — {field_name}: '{previous_value}' → '{current_value}'")
                    change_dict = {
                        "user_id": user_id,
                        "volunteer_name": anon_name,
                        "field_name": field_name,
                        "previous_value": previous_value,
                        "new_value": current_value,
                        "timestamp": new_updated_at
                    }
                    
                    # Store stripped/anonymized version for dashboard
                    public_change = {
                        "volunteer_name": anon_name,
                        "field_name": field_name,
                        "old_value": previous_value if previous_value else "(empty)",
                        "new_value": current_value,
                        "timestamp": new_updated_at
                    }
                    
                    if field_name in FORM_SUBMISSION_FIELDS:
                        state["dashboard_activity"]["form_submissions"].insert(0, public_change)
                        state["dashboard_activity"]["form_submissions"] = state["dashboard_activity"]["form_submissions"][:5] # Keep max 5
                    else:
                        state["dashboard_activity"]["field_changes"].insert(0, public_change)
                        state["dashboard_activity"]["field_changes"] = state["dashboard_activity"]["field_changes"][:5]
                    
                    if field_name in IMMEDIATE_FIELDS and (not previous_value):
                        immediate_changes.append({
                            **change_dict,
                            "volunteer_name": raw_name # Only use true name in volatile email queue
                        })
                    else:
                        digest_queue.append(change_dict)
            else:
                new_updated_at = previous_updated_at

            current_users[user_id]["fields"][field_name] = {
                "value": current_value,
                "updated_at": new_updated_at
            }

    state["users"] = current_users

    # 1. Send Immediate Notifications
    if immediate_changes:
        try:
            send_immediate_notification(immediate_changes)
        except Exception as e:
            print(f"Failed sending immediate email: {e}")
            email_ok = False

    # 2. Check for Daily Digest
    today_str = now.strftime('%Y-%m-%d')
    # Run daily digest if it's 8 AM or later AND we haven't sent it today yet.
    if now.hour >= 8 and state.get("last_digest_date") != today_str:
        print("Evaluating stalled workflows and sending Daily Digest.")
        
        # Hydrate true names mapping for digests
        true_names_map = {}
        for v in volunteers:
            uid = str(v.get("user_id", ""))
            fname = f"{v.get('first_name', '')} {v.get('last_name', '')}".strip() or v.get("name", "Unknown")
            true_names_map[uid] = fname
            
        stalled_workflows = check_stalled_workflows(current_users, now, true_names_map)
        
        # Inject true names back into digest queue items
        for item in digest_queue:
            uid = item.get("user_id")
            if uid and uid in true_names_map:
                item["volunteer_name"] = true_names_map[uid]
        
        # Only send if there's actually something to report
        if digest_queue or stalled_workflows:
            try:
                send_daily_digest(digest_queue, stalled_workflows)
            except Exception as e:
                print(f"Failed sending daily digest email: {e}")
                email_ok = False
        else:
            print("No non-critical changes and no stalled workflows. Skipping digest email.")
            
        # Update digest state
        state["last_digest_date"] = today_str
        state["digest_queue"] = []
    else:
        # Save accumulated digests
        state["digest_queue"] = digest_queue

    # Save state
    save_state(state)
    
    # Update HTML static payload
    update_dashboard_json(state, now, api_ok, email_ok)
    
    if not api_ok:
        # Fail the workflow so Github Actions knows
        exit(1)


if __name__ == "__main__":
    main()