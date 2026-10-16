import json
import os
import sqlite3
from datetime import datetime, timezone

import pandas as pd
import streamlit as st
import altair as alt

st.set_page_config(
    page_title="SentinelX Security Simulator",
    page_icon="🛡️",
    layout="wide"
)


# ==============================
# SENTINELX DARK CYBERSECURITY THEME
# ==============================

st.markdown("""
<style>
    /* Main application background */
    .stApp {
        background-color: #0b1120;
        color: #e2e8f0;
    }

    /* Main content spacing */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1400px;
    }

    /* Main headings */
    h1, h2, h3 {
        color: #55e6a5 !important;
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: #141f33;
        border: 1px solid #263650;
        padding: 18px;
        border-radius: 12px;
    }

    [data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
    }

    [data-testid="stMetricValue"] {
        color: #55e6a5 !important;
    }

    /* Buttons */
    .stButton > button {
        background-color: #123b32;
        color: #55e6a5;
        border: 1px solid #287a60;
        border-radius: 8px;
        font-weight: 600;
        transition: 0.2s;
    }

    .stButton > button:hover {
        background-color: #1b5947;
        border-color: #55e6a5;
        color: white;
    }

    /* Input fields */
    div[data-baseweb="select"] > div,
    div[data-baseweb="input"] > div {
        background-color: #141f33;
        border-color: #34445e;
    }

    /* Expanders and data tables */
    [data-testid="stExpander"] {
        background-color: #111c2e;
        border: 1px solid #263650;
        border-radius: 10px;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #263650;
        border-radius: 10px;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #080e1a;
        border-right: 1px solid #263650;
    }

    /* Divider */
    hr {
        border-color: #263650;
    }

    
    
    /* JSON message editor - dark theme fix */
    [data-testid="stTextArea"] textarea,
    [data-testid="stTextArea"] textarea:focus {
        background: #111827 !important;
        color: #00e5ff !important;
        -webkit-text-fill-color: #00e5ff !important;
        border: 1px solid #00bcd4 !important;
        border-radius: 10px !important;
        caret-color: #00e5ff !important;
        opacity: 1 !important;
    }

    [data-testid="stTextArea"] > div,
    [data-testid="stTextArea"] > div > div {
        background: #111827 !important;
        border-color: #00bcd4 !important;
    }

    [data-testid="stTextArea"] label {
        color: #94a3b8 !important;
    }


    textarea:focus {
        border: 1px solid #55e6a5 !important;
        box-shadow: 0 0 8px rgba(0, 229, 255, 0.25) !important;
    }

</style>
""", unsafe_allow_html=True)

st.title("🛡️ SentinelX")
st.subheader("Secure Telemetry & Command Validation Simulator")
st.caption("A defensive simulator using synthetic messages only.")

ALLOWED_COMMANDS = {"STATUS", "PING", "RESTART"}
MAX_AGE_SECONDS = 300

# ==============================
# SQLITE EVENT STORAGE
# ==============================
DB_PATH = "sentinelx_events.db"


def init_database():
    """Create the local event table if it does not already exist."""
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                device TEXT,
                command TEXT,
                status TEXT,
                reason TEXT,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'LOW'
            )
            """
        )


def save_event_to_database(event):
    """Save one event while remaining compatible with older event records."""
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT INTO events
                (time, device, command, status, reason, risk_score, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("Time", ""),
                event.get("Device", "Unknown"),
                event.get("Command", "Unknown"),
                event.get("Status", "REJECTED"),
                event.get("Reason", ""),
                event.get("Risk Score", 0),
                event.get("Risk Level", "LOW"),
            ),
        )


def load_events_from_database():
    """Load saved events in newest-first order for the dashboard."""
    with sqlite3.connect(DB_PATH) as connection:
        rows = connection.execute(
            """
            SELECT time, device, command, status, reason, risk_score, risk_level
            FROM events
            ORDER BY id DESC
            """
        ).fetchall()

    return [
        {
            "Time": row[0],
            "Device": row[1],
            "Command": row[2],
            "Status": row[3],
            "Reason": row[4],
            "Risk Score": row[5],
            "Risk Level": row[6],
        }
        for row in rows
    ]


def clear_database_events():
    """Remove all saved event records."""
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("DELETE FROM events")


# Create the database/table when the app starts.
init_database()


def validate_message(raw_message):
    try:
        message = json.loads(raw_message)
    except (json.JSONDecodeError, TypeError):
        return False, ["Invalid JSON format."], None

    if not isinstance(message, dict):
        return False, ["Message must be a JSON object."], None

    errors = []
    required = ["device_id", "command", "timestamp", "sequence"]

    for field in required:
        if field not in message:
            errors.append(f"Missing required field: {field}")

    if errors:
        return False, errors, message

    if not isinstance(message["device_id"], str) or not message["device_id"].strip():
        errors.append("device_id must be a non-empty string.")

    if not isinstance(message["command"], str):
        errors.append("command must be a string.")
    elif message["command"] not in ALLOWED_COMMANDS:
        errors.append("Unsupported command.")

    sequence = message["sequence"]
    if type(sequence) is not int or sequence < 1:
        errors.append("sequence must be a positive integer.")

    timestamp = message["timestamp"]

    if not isinstance(timestamp, str):
        errors.append("timestamp must be an ISO 8601 string.")
    else:
        try:
            parsed = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                errors.append("Timestamp must include a timezone.")
            else:
                age = (
                    datetime.now(timezone.utc)
                    - parsed.astimezone(timezone.utc)
                ).total_seconds()

                if age > MAX_AGE_SECONDS:
                    errors.append("Message timestamp has expired.")
                elif age < -30:
                    errors.append("Timestamp is too far in the future.")

        except ValueError:
            errors.append("Invalid timestamp format.")

    return len(errors) == 0, errors, message


if "history" not in st.session_state:
    st.session_state.history = load_events_from_database()

if "sequences" not in st.session_state:
    st.session_state.sequences = {}


def record_message(raw_message):
    accepted, errors, message = validate_message(raw_message)

    device = "Unknown"
    command = "Unknown"

    if isinstance(message, dict):
        device = str(message.get("device_id", "Unknown"))
        command = str(message.get("command", "Unknown"))

        if accepted:
            sequence_key = device
            sequence = message["sequence"]
            last_sequence = st.session_state.sequences.get(sequence_key, 0)

            if sequence <= last_sequence:
                accepted = False
                errors.append(
                    "Duplicate or out-of-order sequence number for this device."
                )
            else:
                st.session_state.sequences[sequence_key] = sequence

    # Simple, explainable risk score for this simulated event.
    # This is a demo heuristic, not a real-world security guarantee.
    if accepted:
        risk_score = 0
    else:
        error_text = " ".join(errors).lower()
        if "duplicate or out-of-order" in error_text:
            risk_score = 80
        elif "unsupported command" in error_text:
            risk_score = 70
        elif "invalid json" in error_text or "missing required field" in error_text:
            risk_score = 60
        elif "timestamp" in error_text or "expired" in error_text:
            risk_score = 50
        else:
            risk_score = 40

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    result = {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Device": device,
        "Command": command,
        "Status": "ACCEPTED" if accepted else "REJECTED",
        "Reason": "All checks passed" if accepted else "; ".join(errors),
        "Risk Score": risk_score,
        "Risk Level": risk_level
    }

    # Keep the dashboard updated and persist the event to SQLite.
    st.session_state.history.insert(0, result)
    save_event_to_database(result)
    return accepted, errors, result


now = datetime.now(timezone.utc).isoformat(timespec="seconds")

valid_example = {
    "device_id": "DEVICE-001",
    "command": "STATUS",
    "timestamp": now,
    "sequence": 1
}

test_cases = {
    "Valid message": valid_example,
    "Unsupported command": {
        "device_id": "DEVICE-002",
        "command": "DELETE_ALL",
        "timestamp": now,
        "sequence": 1
    },
    "Missing device ID": {
        "command": "PING",
        "timestamp": now,
        "sequence": 1
    },
    "Invalid sequence": {
        "device_id": "DEVICE-004",
        "command": "RESTART",
        "timestamp": now,
        "sequence": -1
    },
    "Expired timestamp": {
        "device_id": "DEVICE-005",
        "command": "PING",
        "timestamp": "2020-01-01T00:00:00+00:00",
        "sequence": 1
    }
}

st.markdown("## 1. Message validator")

choice = st.selectbox(
    "Choose a test case",
    ["Custom message"] + list(test_cases.keys())
)

if choice == "Custom message":
    default_text = json.dumps(valid_example, indent=2)
else:
    default_text = json.dumps(test_cases[choice], indent=2)

raw_message = st.text_area(
    "JSON message",
    value=default_text,
    height=220
)

if st.button("🔍 Validate Message", type="primary"):
    accepted, errors, result = record_message(raw_message)

    if accepted:
        st.success("ACCEPTED — all validation checks passed.")
    else:
        st.error("REJECTED — validation failed.")
        for error in errors:
            st.write(f"• {error}")

    st.json(result)

st.markdown("---")
st.markdown("## 2. Security test simulator")

if st.button("▶ Run all test cases"):
    for name, message in test_cases.items():
        # Generate a fresh timestamp for the valid test.
        if name == "Valid message":
            message = dict(message)
            message["timestamp"] = datetime.now(
                timezone.utc
            ).isoformat(timespec="seconds")

        accepted, errors, result = record_message(
            json.dumps(message)
        )

    st.success("Simulation finished. Review the results below.")

# ==========================================
# 3. LIVE DEMO MODE (SYNTHETIC MESSAGES ONLY)
# ==========================================
st.markdown("---")
st.markdown("## 3. Live Demo Mode")
st.write(
    "Run a guided scenario to demonstrate how SentinelX validates synthetic "
    "messages. Every scenario uses the same validation, risk-scoring, event "
    "history, and SQLite-saving functions as the message validator."
)
st.info(
    "Demo scenarios use simulated data only. No commands are sent to or "
    "executed on real devices."
)

if "demo_results" not in st.session_state:
    st.session_state.demo_results = []

scenario_descriptions = {
    "Normal Operation": "Three valid simulated messages should be accepted.",
    "Invalid Command": "An unsupported command should be rejected and assigned a risk score.",
    "Sequence Error": "A repeated sequence number for the same simulated device should be rejected."
}

selected_scenario = st.selectbox(
    "Choose a demo scenario",
    list(scenario_descriptions.keys()),
    key="live_demo_scenario"
)
st.caption(scenario_descriptions[selected_scenario])

if st.button("▶ Run Selected Demo Scenario", type="primary", key="run_live_demo"):
    # Unique IDs keep repeated demo runs independent from earlier sequence state.
    run_id = datetime.now(timezone.utc).strftime("%H%M%S%f")
    demo_messages = []
    fresh_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if selected_scenario == "Normal Operation":
        for index, command in enumerate(["STATUS", "PING", "RESTART"], start=1):
            demo_messages.append({
                "device_id": f"DEMO-{run_id}-{index}",
                "command": command,
                "timestamp": fresh_timestamp,
                "sequence": 1
            })
    elif selected_scenario == "Invalid Command":
        demo_messages.append({
            "device_id": f"DEMO-{run_id}-INVALID",
            "command": "DELETE_ALL",
            "timestamp": fresh_timestamp,
            "sequence": 1
        })
    else:
        sequence_device = f"DEMO-{run_id}-SEQUENCE"
        demo_messages.extend([
            {
                "device_id": sequence_device,
                "command": "STATUS",
                "timestamp": fresh_timestamp,
                "sequence": 1
            },
            {
                "device_id": sequence_device,
                "command": "PING",
                "timestamp": fresh_timestamp,
                "sequence": 1
            }
        ])

    scenario_results = []
    for demo_message in demo_messages:
        accepted, errors, event = record_message(json.dumps(demo_message))
        scenario_results.append(event)

    st.session_state.demo_results = scenario_results
    st.session_state.demo_results_scenario = selected_scenario

if st.session_state.demo_results:
    st.markdown("### Latest Demo Results")
    previous_scenario = st.session_state.get("demo_results_scenario", "Demo")
    st.caption(f"Scenario: {previous_scenario}")
    demo_df = pd.DataFrame(st.session_state.demo_results)
    demo_accepted = int((demo_df["Status"] == "ACCEPTED").sum())
    demo_rejected = int((demo_df["Status"] == "REJECTED").sum())
    demo_col1, demo_col2, demo_col3 = st.columns(3)
    demo_col1.metric("Messages in Scenario", len(demo_df))
    demo_col2.metric("Accepted", demo_accepted)
    demo_col3.metric("Rejected", demo_rejected)
    st.dataframe(demo_df, use_container_width=True, hide_index=True)

history = st.session_state.history
accepted_count = sum(
    row["Status"] == "ACCEPTED" for row in history
)
rejected_count = len(history) - accepted_count

st.markdown("## 4. Security dashboard")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Messages", len(history))
col2.metric("Accepted", accepted_count)
col3.metric("Rejected", rejected_count)
high_risk_count = sum(row.get("Risk Score", 0) >= 70 for row in history)
col4.metric("High-Risk Events", high_risk_count)

# ==========================================
# 4. THREAT ANALYSIS OVERVIEW
# ==========================================
st.markdown("---")
st.markdown("## 4. Threat Analysis Overview")
st.caption(
    "This overview summarizes recorded simulation events only. Risk levels are "
    "based on SentinelX's simple demo rules and are not a real-world security verdict."
)

if history:
    threat_df = pd.DataFrame(history).copy()
    if "Risk Score" not in threat_df.columns:
        threat_df["Risk Score"] = 0
    if "Risk Level" not in threat_df.columns:
        threat_df["Risk Level"] = "LOW"
    if "Reason" not in threat_df.columns:
        threat_df["Reason"] = "Unknown"
    if "Status" not in threat_df.columns:
        threat_df["Status"] = "REJECTED"

    threat_df["Risk Score"] = pd.to_numeric(
        threat_df["Risk Score"], errors="coerce"
    ).fillna(0)
    threat_df["Risk Level"] = threat_df["Risk Level"].fillna("LOW").astype(str)
    threat_df["Reason"] = threat_df["Reason"].fillna("Unknown").astype(str)

    average_risk = round(float(threat_df["Risk Score"].mean()), 1)
    high_events = int((threat_df["Risk Score"] >= 70).sum())
    medium_events = int(((threat_df["Risk Score"] >= 40) & (threat_df["Risk Score"] < 70)).sum())
    low_events = int((threat_df["Risk Score"] < 40).sum())
    rejected_events = int((threat_df["Status"] == "REJECTED").sum())
    rejection_percent = round(rejected_events / len(threat_df) * 100, 1) if len(threat_df) else 0

    threat_col1, threat_col2, threat_col3, threat_col4 = st.columns(4)
    threat_col1.metric("Average Demo Risk Score", f"{average_risk}/100")
    threat_col2.metric("High Risk", high_events)
    threat_col3.metric("Medium Risk", medium_events)
    threat_col4.metric("Rejected Events", f"{rejection_percent}%")

    risk_counts = pd.DataFrame({
        "Risk Level": ["HIGH", "MEDIUM", "LOW"],
        "Events": [high_events, medium_events, low_events]
    })
    reason_counts = (
        threat_df[threat_df["Status"] == "REJECTED"]["Reason"]
        .value_counts()
        .head(5)
        .rename_axis("Rejection Reason")
        .reset_index(name="Events")
    )

    threat_chart_col1, threat_chart_col2 = st.columns(2)
    with threat_chart_col1:
        st.markdown("### Risk Level Distribution")
        st.bar_chart(risk_counts.set_index("Risk Level"), height=260)
    with threat_chart_col2:
        st.markdown("### Most Common Rejection Reasons")
        if not reason_counts.empty:
            st.bar_chart(reason_counts.set_index("Rejection Reason"), height=260)
        else:
            st.info("No rejected events have been recorded yet.")

    if high_events:
        st.warning(
            f"Review recommended: {high_events} high-risk simulated event(s) are in the recorded history. "
            "Inspect their reasons in Live Event History; this is a demo heuristic, not proof of an attack."
        )
    else:
        st.success("No high-risk events are currently recorded in the simulation history.")
else:
    st.info("Run a demo scenario or validate a message to populate threat analysis.")

# ==========================================
# 5. INCIDENT INVESTIGATION WORKSPACE
# ==========================================
st.markdown("---")
st.markdown("## 5. Incident Investigation Workspace")
st.caption(
    "Incidents here are grouped from rejected events in the local simulation. "
    "They are review aids, not confirmed real-world attacks."
)

if "reviewed_incidents" not in st.session_state:
    st.session_state.reviewed_incidents = set()

if history:
    incident_df = pd.DataFrame(history).copy()
    for column, default in [("Device", "Unknown"), ("Command", "Unknown"),
                             ("Status", "REJECTED"), ("Reason", "Unknown"),
                             ("Risk Score", 0), ("Risk Level", "LOW"), ("Time", "Unknown")]:
        if column not in incident_df.columns:
            incident_df[column] = default

    incident_df["Risk Score"] = pd.to_numeric(incident_df["Risk Score"], errors="coerce").fillna(0)
    rejected_incidents = incident_df[incident_df["Status"] == "REJECTED"].copy()

    if rejected_incidents.empty:
        st.success("No rejected events to investigate yet. Run a simulated scenario to create investigation records.")
    else:
        # A review group is based on device plus rejection reason. This is a simple demo grouping rule.
        rejected_incidents["Incident Group"] = (
            rejected_incidents["Device"].fillna("Unknown").astype(str)
            + " | " + rejected_incidents["Reason"].fillna("Unknown").astype(str)
        )
        incident_summary = (
            rejected_incidents.groupby("Incident Group")
            .agg(
                Device=("Device", "first"),
                Reason=("Reason", "first"),
                Events=("Status", "size"),
                Highest_Risk=("Risk Score", "max"),
                Latest_Event=("Time", "first"),
            )
            .reset_index()
            .rename(columns={"Highest_Risk": "Highest Risk Score", "Latest_Event": "Latest Event"})
            .sort_values(["Highest Risk Score", "Events"], ascending=[False, False])
        )
        incident_summary["Review Status"] = incident_summary["Incident Group"].apply(
            lambda key: "Reviewed" if key in st.session_state.reviewed_incidents else "Needs review"
        )
        incident_col1, incident_col2, incident_col3 = st.columns(3)
        incident_col1.metric("Incident Groups", len(incident_summary))
        incident_col2.metric("Needs Review", int((incident_summary["Review Status"] == "Needs review").sum()))
        incident_col3.metric("Reviewed", int((incident_summary["Review Status"] == "Reviewed").sum()))
        st.dataframe(incident_summary, use_container_width=True, hide_index=True)

        selected_incident = st.selectbox(
            "Select an incident group",
            incident_summary["Incident Group"].tolist(),
            key="incident_investigation_selection",
        )
        selected_incident_row = incident_summary[incident_summary["Incident Group"] == selected_incident].iloc[0]
        st.markdown("### Investigation Details")
        detail_col1, detail_col2, detail_col3 = st.columns(3)
        detail_col1.metric("Device", str(selected_incident_row["Device"]))
        detail_col2.metric("Events in Group", int(selected_incident_row["Events"]))
        detail_col3.metric("Highest Risk Score", int(selected_incident_row["Highest Risk Score"]))
        st.write("**Observed reason:** " + str(selected_incident_row["Reason"]))

        reason_text = str(selected_incident_row["Reason"]).lower()
        if "sequence" in reason_text or "out-of-order" in reason_text:
            recommendation = "Review the device's simulated sequence values and confirm messages arrive in the expected order."
        elif "unsupported command" in reason_text:
            recommendation = "Check the command against the documented allowlist; keep unsupported commands rejected."
        elif "timestamp" in reason_text or "expired" in reason_text:
            recommendation = "Check the timestamp format, timezone, and allowed message age in this simulation."
        elif "json" in reason_text or "required field" in reason_text:
            recommendation = "Check the message structure and ensure all required fields are present and correctly typed."
        else:
            recommendation = "Review the event details and validation reason, then rerun a controlled synthetic test."
        st.info("**Suggested defensive review:** " + recommendation)

        review_col1, review_col2 = st.columns(2)
        with review_col1:
            if selected_incident in st.session_state.reviewed_incidents:
                st.success("This group is marked reviewed for this session.")
            elif st.button("Mark incident as reviewed", key="mark_incident_reviewed"):
                st.session_state.reviewed_incidents.add(selected_incident)
                st.rerun()
        with review_col2:
            if selected_incident in st.session_state.reviewed_incidents:
                if st.button("Reopen for review", key="reopen_incident_review"):
                    st.session_state.reviewed_incidents.discard(selected_incident)
                    st.rerun()

        st.markdown("### Events in This Group")
        st.dataframe(
            rejected_incidents[rejected_incidents["Incident Group"] == selected_incident]
            [["Time", "Device", "Command", "Status", "Reason", "Risk Score", "Risk Level"]],
            use_container_width=True,
            hide_index=True,
        )
        st.caption("Review markers last for the current app session only. Event history remains stored in the existing SQLite database.")
else:
    st.info("No events recorded yet. Run a demo scenario to populate the investigation workspace.")

# ==========================================
# 5. DEVICE MONITORING PANEL
# ==========================================

st.markdown("## 5. Device Monitoring")

if history:
    device_df = pd.DataFrame(history).copy()

    # Support older saved events that may not contain risk fields.
    if "Risk Score" not in device_df.columns:
        device_df["Risk Score"] = 0
    if "Risk Level" not in device_df.columns:
        device_df["Risk Level"] = "LOW"

    device_df["Device"] = device_df["Device"].fillna("Unknown").astype(str)
    device_df["Status"] = device_df["Status"].fillna("REJECTED").astype(str)
    device_df["Risk Score"] = pd.to_numeric(
        device_df["Risk Score"], errors="coerce"
    ).fillna(0)

    device_summary = (
        device_df.groupby("Device")
        .agg(
            Events=("Device", "size"),
            Rejected=("Status", lambda values: (values == "REJECTED").sum()),
            High_Risk=("Risk Score", lambda values: (values >= 70).sum()),
            Latest_Event=("Time", "first"),
        )
        .reset_index()
        .rename(columns={
            "High_Risk": "High-Risk Events",
            "Latest_Event": "Latest Event"
        })
    )

    device_summary["Rejection Rate (%)"] = (
        device_summary["Rejected"] / device_summary["Events"] * 100
    ).round(1)

    device_summary = device_summary.sort_values(
        by=["High-Risk Events", "Rejected", "Events"],
        ascending=[False, False, False]
    )

    device_metric1, device_metric2, device_metric3 = st.columns(3)
    device_metric1.metric("Devices Seen", int(device_summary["Device"].nunique()))
    device_metric2.metric(
        "Devices With Rejections",
        int((device_summary["Rejected"] > 0).sum())
    )
    device_metric3.metric(
        "Devices With High-Risk Events",
        int((device_summary["High-Risk Events"] > 0).sum())
    )

    st.caption(
        "Device status is inferred from simulated event history. "
        "This panel does not connect to or monitor real devices."
    )

    st.markdown("### Device Activity Summary")
    st.dataframe(device_summary, use_container_width=True, hide_index=True)

    selected_device = st.selectbox(
        "Inspect a device",
        ["All Devices"] + sorted(device_summary["Device"].unique().tolist()),
        key="device_monitor_selection"
    )

    if selected_device == "All Devices":
        selected_events = device_df
    else:
        selected_events = device_df[device_df["Device"] == selected_device]

    st.markdown("### Recent Events for Selected Device")
    st.dataframe(
        selected_events[
            ["Time", "Device", "Command", "Status", "Reason", "Risk Score", "Risk Level"]
        ].head(20),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info(
        "No device activity yet. Validate a message or run the test simulator "
        "to populate this panel."
    )

# ==========================================
# 5. SYSTEM HEALTH DASHBOARD
# ==========================================

st.markdown("## 6. System Health")

database_exists = os.path.exists(DB_PATH)
database_size_kb = round(os.path.getsize(DB_PATH) / 1024, 1) if database_exists else 0
acceptance_rate = round((accepted_count / len(history)) * 100, 1) if history else 0
last_event_time = history[0].get("Time", "No events") if history else "No events"

health_col1, health_col2, health_col3, health_col4 = st.columns(4)
health_col1.metric("Database", "Connected" if database_exists else "Not found")
health_col2.metric("Database Size", f"{database_size_kb} KB")
health_col3.metric("Acceptance Rate", f"{acceptance_rate}%")
health_col4.metric("Latest Event", last_event_time)

if not history:
    st.info("No events recorded yet. Run a test case to populate system health metrics.")
else:
    st.caption(
        "Health indicators are based on this local simulation's saved event history. "
        "They do not measure the health of real devices or production infrastructure."
    )

# ==========================================
# 5. SECURITY ANALYTICS
# ==========================================

st.markdown("## 7. Security Analytics")

if history:
    df = pd.DataFrame(history)

    # Accepted vs rejected messages
    status_counts = (
        df["Status"]
        .value_counts()
        .reindex(["ACCEPTED", "REJECTED"], fill_value=0)
    )

    chart_col1, chart_col2 = st.columns(2)

    
    with chart_col1:
        st.markdown("### Accepted vs Rejected")
        st.bar_chart(
            status_counts,
            height=280,
            color="#55e6a5"
        )


    with chart_col2:
        st.markdown("### Rejection Reasons")
        rejected_df = df[df["Status"] == "REJECTED"]

            

        if not rejected_df.empty:
            reason_counts = rejected_df["Reason"].value_counts().head(8)

            st.bar_chart(
                reason_counts,
                height=280,
                color="#ff6b6b"
            )
        else:
            st.info("No rejected messages to chart yet.")

    st.markdown("### Event Timeline")

    timeline_df = df.copy()
    timeline_df["Time"] = pd.to_datetime(
        timeline_df["Time"],
        format="%H:%M:%S",
        errors="coerce"
    )
    timeline_df = timeline_df.dropna(subset=["Time"])


    if not timeline_df.empty:
        timeline_df["Minute"] = timeline_df["Time"].dt.strftime("%H:%M")
        timeline_counts = (
            timeline_df.groupby(["Minute", "Status"])
            .size()
            .unstack(fill_value=0)
            .reindex(columns=["ACCEPTED", "REJECTED"], fill_value=0)
        )
        st.line_chart(timeline_counts, height=280)
    else:
        st.info("Timeline will appear when event timestamps are available.")

    st.markdown("---")

    # ==========================================
    # 7. LIVE EVENT HISTORY
    # ==========================================

    st.markdown("## 8. Live Event History")

    # Advanced event filters
    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:
        status_choice = st.selectbox(
            "Status",
            ["All Events", "Accepted Only", "Rejected Only"],
            key="live_history_status_filter"
        )

    with filter_col2:
        device_options = ["All Devices"] + sorted(
            df["Device"].dropna().astype(str).unique().tolist()
        )
        device_choice = st.selectbox(
            "Device",
            device_options,
            key="live_history_device_filter"
        )

    with filter_col3:
        rejected_reasons = (
            df.loc[df["Status"] == "REJECTED", "Reason"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )
        reason_options = ["All Reasons"] + sorted(rejected_reasons)
        reason_choice = st.selectbox(
            "Rejection reason",
            reason_options,
            key="live_history_reason_filter"
        )

    search_text = st.text_input(
        "Search events",
        placeholder="Search device, command, status, reason, or time..."
    )

    filtered_df = df.copy()

    if status_choice == "Accepted Only":
        filtered_df = filtered_df[filtered_df["Status"] == "ACCEPTED"]
    elif status_choice == "Rejected Only":
        filtered_df = filtered_df[filtered_df["Status"] == "REJECTED"]

    if device_choice != "All Devices":
        filtered_df = filtered_df[filtered_df["Device"].astype(str) == device_choice]

    if reason_choice != "All Reasons":
        filtered_df = filtered_df[filtered_df["Reason"].astype(str) == reason_choice]

    if search_text.strip():
        searchable_columns = ["Time", "Device", "Command", "Status", "Reason"]
        search_mask = filtered_df[searchable_columns].astype(str).apply(
            lambda column: column.str.contains(
                search_text.strip(), case=False, regex=False, na=False
            )
        ).any(axis=1)
        filtered_df = filtered_df[search_mask]

    st.caption(f"Showing {len(filtered_df)} of {len(df)} events.")

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        "📥 Download security report (CSV)",
        data=df.to_csv(index=False),
        file_name="sentinelx_report.csv",
        mime="text/csv"
    )

    if st.button("🧹 Clear event history"):
        st.session_state.history = []
        st.session_state.sequences = {}
        clear_database_events()
        st.rerun()

else:
    st.info(
        "No events yet. Validate a message or run the test simulator "
        "to populate the security dashboard, analytics, and live event history."
    )

st.markdown("---")
st.caption(
    "Scope: local simulation only. Messages are not sent to real devices "
    "and commands are never executed. This demo does not authenticate "
    "senders or verify cryptographic signatures."
)
