import json
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
    st.session_state.history = []

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

    result = {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Device": device,
        "Command": command,
        "Status": "ACCEPTED" if accepted else "REJECTED",
        "Reason": "All checks passed" if accepted else "; ".join(errors)
    }

    st.session_state.history.insert(0, result)
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

history = st.session_state.history
accepted_count = sum(
    row["Status"] == "ACCEPTED" for row in history
)
rejected_count = len(history) - accepted_count

st.markdown("## 3. Security dashboard")

col1, col2, col3 = st.columns(3)
col1.metric("Total Messages", len(history))
col2.metric("Accepted", accepted_count)
col3.metric("Rejected", rejected_count)

# ==========================================
# 4. SECURITY ANALYTICS
# ==========================================

st.markdown("## 4. Security Analytics")

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
    # 5. LIVE EVENT HISTORY
    # ==========================================

    st.markdown("## 5. Live Event History")

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
