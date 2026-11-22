
import os
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
import boto3

from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv(
    "DASHBOARD_API_URL",
    "http://127.0.0.1:5000"
)

# =====================================================
# PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="Cloud Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =====================================================
# DASHBOARD STARTUP EMAIL (ONCE PER STREAMLIT SESSION)
# =====================================================

if "startup_email_sent" not in st.session_state:
    try:
        sns_topic_arn = os.getenv("SNS_TOPIC_ARN")
        aws_region = os.getenv("AWS_REGION", "ap-south-1")

        if not sns_topic_arn:
            st.warning("Startup email not sent: SNS_TOPIC_ARN is missing from .env.")
        else:
            sns = boto3.client("sns", region_name=aws_region)
            sns.publish(
                TopicArn=sns_topic_arn,
                Subject="Cloud Threat Detection Dashboard Started",
                Message=(
                    "Your Cloud Threat Detection System dashboard "
                    "has been opened successfully."
                )
            )
            st.session_state["startup_email_sent"] = True
            st.success("Dashboard startup email sent successfully!")

    except Exception as error:
        st.error(f"Unable to send dashboard startup email: {error}")

# =====================================================
# COLOR THEME
# =====================================================

BG = "#0B1220"
CARD = "#151F30"
BORDER = "#26364B"
TEXT = "#F1F5F9"
MUTED = "#A8B6C8"

SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#EAB308",
    "LOW": "#22C55E"
}

# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>

.stApp {
    background-color: #0B1220;
    color: #F1F5F9;
}

[data-testid="stHeader"] {
    background-color: #0B1220;
}

[data-testid="stSidebar"] {
    background-color: #111B2B;
    border-right: 1px solid #26364B;
}

[data-testid="stSidebar"] * {
    color: #E2E8F0;
}

h1, h2, h3, h4, p, label {
    color: #F1F5F9 !important;
}

[data-testid="stMetric"] {
    background-color: #151F30;
    border: 1px solid #26364B;
    padding: 20px;
    border-radius: 12px;
}

[data-testid="stMetricLabel"] {
    color: #A8B6C8 !important;
}

[data-testid="stMetricValue"] {
    color: #FFFFFF !important;
}

/* Main buttons and form submit buttons */
div.stButton > button,
div[data-testid="stFormSubmitButton"] > button,
[data-testid="stForm"] button[kind="secondaryFormSubmit"],
[data-testid="stForm"] button[kind="primaryFormSubmit"] {
    background-color: #2563EB !important;
    color: #FFFFFF !important;
    border: 1px solid #60A5FA !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
    min-height: 42px !important;
    opacity: 1 !important;
}

div.stButton > button p,
div[data-testid="stFormSubmitButton"] > button p,
[data-testid="stForm"] button p {
    color: #FFFFFF !important;
    font-weight: 700 !important;
}

div.stButton > button:hover,
div[data-testid="stFormSubmitButton"] > button:hover,
[data-testid="stForm"] button:hover {
    background-color: #1D4ED8 !important;
    color: #FFFFFF !important;
    border-color: #93C5FD !important;
}

/* Make investigation notes and text inputs easy to see and edit */
[data-testid="stTextArea"] textarea,
[data-testid="stTextInput"] input {
    background-color: #0F1B2D !important;
    color: #F1F5F9 !important;
    -webkit-text-fill-color: #F1F5F9 !important;
    border: 1px solid #526782 !important;
    border-radius: 8px !important;
    caret-color: #FFFFFF !important;
}

[data-testid="stTextArea"] textarea:focus,
[data-testid="stTextInput"] input:focus {
    border: 2px solid #60A5FA !important;
    outline: none !important;
}

[data-testid="stTextArea"] textarea::placeholder,
[data-testid="stTextInput"] input::placeholder {
    color: #A8B6C8 !important;
    -webkit-text-fill-color: #A8B6C8 !important;
}

hr {
    border-color: #26364B;
}

[data-testid="stDataFrame"] {
    border: 1px solid #26364B;
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)


# =====================================================
# API CONNECTION
# =====================================================

def get_api_data(endpoint):

    try:

        response = requests.get(
            API_URL + endpoint,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:

        st.error(
            f"Backend connection failed: {error}"
        )

        return None


# =====================================================
# AWS FAILED LOGIN MONITORING
# =====================================================

def get_failed_login_records():
    """Read the Lambda failed-login counter table in AWS."""
    table_name = os.getenv("DYNAMODB_TABLE", "FailedLoginAttempts")
    region = os.getenv("DYNAMODB_REGION", "us-east-1")

    try:
        dynamodb = boto3.resource("dynamodb", region_name=region)
        table = dynamodb.Table(table_name)

        records = []
        response = table.scan()
        records.extend(response.get("Items", []))

        while response.get("LastEvaluatedKey"):
            response = table.scan(
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            records.extend(response.get("Items", []))

        return records, None

    except Exception as error:
        return None, str(error)


# =====================================================
# DISPLAY TABLE
# =====================================================

def display_table(dataframe):

    st.dataframe(
        dataframe,
        use_container_width=True,
        hide_index=True
    )


# =====================================================
# PLOTLY CHART THEME
# =====================================================

def apply_chart_theme(figure):

    figure.update_layout(

        template="plotly_dark",

        paper_bgcolor=CARD,

        plot_bgcolor=CARD,

        font=dict(
            color=TEXT,
            family="Arial"
        ),

        title_font=dict(
            color=TEXT,
            size=18
        ),

        margin=dict(
            l=30,
            r=30,
            t=60,
            b=30
        ),

        legend=dict(
            font=dict(color=TEXT)
        )
    )

    return figure


# =====================================================
# SIDEBAR NAVIGATION
# =====================================================

st.sidebar.title("🛡️ SECURITY CENTER")

st.sidebar.caption(
    "Cloud Threat Detection System"
)

st.sidebar.divider()

page = st.sidebar.radio(

    "NAVIGATION",

    [
        "Security Overview",
        "Threat Analysis",
        "Security Alerts",
        "Event Monitoring",
        "AWS Brute Force Monitoring",
        "Incident Management",
        "Reports"
    ]

)

st.sidebar.divider()

if st.sidebar.button(
    "↻ Refresh Dashboard",
    use_container_width=True
):

    st.rerun()

st.sidebar.markdown("---")

st.sidebar.caption(
    "AWS REGION: ap-south-1"
)

st.sidebar.caption(
    "VERSION: 1.0.0"
)


# =====================================================
# MAIN HEADER
# =====================================================

st.title(
    "🛡️ CLOUD THREAT DETECTION CENTER"
)

st.markdown(
    """
    <p style='color:#A8B6C8;'>
    AWS Security Monitoring |
    Threat Intelligence |
    Incident Management
    </p>
    """,
    unsafe_allow_html=True
)

st.divider()


# =====================================================
# FETCH DASHBOARD DATA
# =====================================================

summary = get_api_data(
    "/api/dashboard/summary"
)


if summary is not None:

    total_events = summary.get(
        "total_events", 0
    )

    total_alerts = summary.get(
        "total_alerts", 0
    )

    open_alerts = summary.get(
        "open_alerts", 0
    )

    severity_data = summary.get(
        "severity_distribution", {}
    )

    recent_alerts = summary.get(
        "recent_alerts", []
    )


    # =================================================
    # 1. SECURITY OVERVIEW
    # =================================================

    if page == "Security Overview":

        st.header("Security Overview")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "📡 Total Events",
            total_events
        )

        col2.metric(
            "🚨 Total Alerts",
            total_alerts
        )

        col3.metric(
            "⚠️ Open Alerts",
            open_alerts
        )

        col4.metric(
            "🔴 Critical Alerts",
            severity_data.get("CRITICAL", 0)
        )

        st.divider()

        st.header("Threat Severity Analysis")

        chart_data = pd.DataFrame({

            "Severity": list(SEVERITY_COLORS.keys()),

            "Count": [
                severity_data.get(level, 0)
                for level in SEVERITY_COLORS
            ]

        })

        col1, col2 = st.columns(2)

        # THREAT DISTRIBUTION

        with col1:

            if chart_data["Count"].sum() > 0:

                figure = px.pie(

                    chart_data,

                    names="Severity",

                    values="Count",

                    hole=0.58,

                    color="Severity",

                    color_discrete_map=SEVERITY_COLORS,

                    title="Threat Distribution"

                )

                figure.update_traces(
                    textposition="inside",
                    textinfo="percent+label"
                )

                st.plotly_chart(
                    apply_chart_theme(figure),
                    use_container_width=True
                )

            else:

                st.info(
                    "No alerts available for severity analysis."
                )

        # ALERTS BY SEVERITY

        with col2:

            figure = px.bar(

                chart_data,

                x="Severity",

                y="Count",

                color="Severity",

                color_discrete_map=SEVERITY_COLORS,

                title="Alerts by Severity"

            )

            st.plotly_chart(
                apply_chart_theme(figure),
                use_container_width=True
            )

        st.divider()

        st.header("Recent Security Alerts")

        if recent_alerts:

            recent_df = pd.DataFrame(
                recent_alerts
            )

            display_table(recent_df)

        else:

            st.success(
                "No security alerts available."
            )


    # =================================================
    # 2. THREAT ANALYSIS
    # =================================================

    elif page == "Threat Analysis":

        st.header("Threat Analysis")

        alerts = get_api_data(
            "/api/alerts/"
        )

        if alerts is not None:

            alert_df = pd.DataFrame(alerts)

            if not alert_df.empty:

                col1, col2 = st.columns(2)

                with col1:

                    st.metric(
                        "Detected Threats",
                        len(alert_df)
                    )

                with col2:

                    average_risk = (

                        alert_df["risk_score"].mean()

                        if "risk_score" in alert_df.columns

                        else 0

                    )

                    st.metric(
                        "Average Risk Score",
                        round(average_risk, 2)
                    )

                st.divider()

                st.subheader(
                    "Threat Severity Analysis"
                )

                severity_counts = (

                    alert_df["severity"]

                    .value_counts()

                    .reindex(
                        list(SEVERITY_COLORS.keys()),
                        fill_value=0
                    )

                    .rename_axis("Severity")

                    .reset_index(name="Count")

                )

                figure = px.bar(

                    severity_counts,

                    x="Severity",

                    y="Count",

                    color="Severity",

                    color_discrete_map=SEVERITY_COLORS,

                    title="Threat Count by Severity"

                )

                st.plotly_chart(
                    apply_chart_theme(figure),
                    use_container_width=True
                )

                if "risk_score" in alert_df.columns:

                    figure = px.histogram(

                        alert_df,

                        x="risk_score",

                        nbins=10,

                        title="Risk Score Distribution"

                    )

                    st.plotly_chart(
                        apply_chart_theme(figure),
                        use_container_width=True
                    )

            else:

                st.info(
                    "No threat data available."
                )


    # =================================================
    # 3. SECURITY ALERTS
    # =================================================

    elif page == "Security Alerts":

        st.header("🚨 Security Alerts")

        alerts = get_api_data(
            "/api/alerts/"
        )

        if alerts is not None:

            alert_df = pd.DataFrame(alerts)

            if not alert_df.empty:

                selected_severity = st.selectbox(

                    "Filter by Severity",

                    [
                        "ALL",
                        "CRITICAL",
                        "HIGH",
                        "MEDIUM",
                        "LOW"
                    ]

                )

                if selected_severity != "ALL":

                    alert_df = alert_df[
                        alert_df["severity"]
                        == selected_severity
                    ]

                st.metric(
                    "Matching Alerts",
                    len(alert_df)
                )

                display_table(alert_df)

            else:

                st.success(
                    "No security alerts available."
                )


    # =================================================
    # 4. EVENT MONITORING
    # =================================================

    elif page == "Event Monitoring":

        st.header("📡 Raw CloudTrail Event Monitoring")
        st.caption(
            "Review security events stored in the database, filter records, "
            "and inspect the original event JSON."
        )

        event_response = get_api_data(
            "/api/events/?limit=200"
        )

        if event_response is not None:

            raw_events = event_response.get("events", [])
            total_raw_events = event_response.get("total", len(raw_events))
            returned_events = event_response.get("returned", len(raw_events))

            metric_col1, metric_col2, metric_col3 = st.columns(3)

            metric_col1.metric(
                "Total Stored Events",
                total_raw_events
            )

            metric_col2.metric(
                "Events Loaded",
                returned_events
            )

            unique_sources = len({
                event.get("event_source", "Unknown")
                for event in raw_events
            })

            metric_col3.metric(
                "Event Sources",
                unique_sources
            )

            st.divider()

            if raw_events:

                event_df = pd.DataFrame([
                    {
                        "ID": event.get("id"),
                        "Event Name": event.get("event_name", "Unknown"),
                        "Event Source": event.get("event_source", "Unknown"),
                        "User Identity": event.get("user_identity", "Unknown"),
                        "Source IP": event.get("source_ip", "Unknown"),
                        "Region": event.get("region", "Unknown"),
                        "Resource": event.get("resource_name", "Not specified"),
                        "Status": event.get("event_status", "UNKNOWN"),
                        "Created At": event.get("created_at")
                    }
                    for event in raw_events
                ])

                st.subheader("Filter Events")

                filter_col1, filter_col2, filter_col3 = st.columns(3)

                event_names = sorted({
                    str(event.get("event_name", "Unknown"))
                    for event in raw_events
                })
                statuses = sorted({
                    str(event.get("event_status", "UNKNOWN"))
                    for event in raw_events
                })

                with filter_col1:
                    selected_event_name = st.selectbox(
                        "Event Name",
                        options=["ALL"] + event_names
                    )

                with filter_col2:
                    selected_event_status = st.selectbox(
                        "Event Status",
                        options=["ALL"] + statuses
                    )

                with filter_col3:
                    event_search = st.text_input(
                        "Search user, IP, or resource",
                        placeholder="Enter a search term..."
                    )

                filtered_events = list(raw_events)

                if selected_event_name != "ALL":
                    filtered_events = [
                        event for event in filtered_events
                        if str(event.get("event_name", "Unknown"))
                        == selected_event_name
                    ]

                if selected_event_status != "ALL":
                    filtered_events = [
                        event for event in filtered_events
                        if str(event.get("event_status", "UNKNOWN"))
                        == selected_event_status
                    ]

                if event_search.strip():
                    search_text = event_search.strip().lower()
                    filtered_events = [
                        event for event in filtered_events
                        if search_text in " ".join([
                            str(event.get("user_identity", "")),
                            str(event.get("source_ip", "")),
                            str(event.get("resource_name", "")),
                            str(event.get("event_name", "")),
                            str(event.get("event_source", ""))
                        ]).lower()
                    ]

                filtered_df = pd.DataFrame([
                    {
                        "ID": event.get("id"),
                        "Event Name": event.get("event_name", "Unknown"),
                        "Event Source": event.get("event_source", "Unknown"),
                        "User Identity": event.get("user_identity", "Unknown"),
                        "Source IP": event.get("source_ip", "Unknown"),
                        "Region": event.get("region", "Unknown"),
                        "Resource": event.get("resource_name", "Not specified"),
                        "Status": event.get("event_status", "UNKNOWN"),
                        "Created At": event.get("created_at")
                    }
                    for event in filtered_events
                ])

                st.metric(
                    "Matching Events",
                    len(filtered_events)
                )

                display_table(filtered_df)

                st.divider()
                st.subheader("Event Details")
                st.caption(
                    "Expand an event to inspect its full stored CloudTrail/EventBridge JSON."
                )

                for event in filtered_events:
                    event_label = (
                        f'Event #{event.get("id")} — '
                        f'{event.get("event_name", "Unknown")} '
                        f'| {event.get("created_at", "Time unknown")}'
                    )

                    with st.expander(event_label):
                        detail_col1, detail_col2 = st.columns(2)

                        with detail_col1:
                            st.write("**User:**", event.get("user_identity", "Unknown"))
                            st.write("**Source IP:**", event.get("source_ip", "Unknown"))
                            st.write("**Event source:**", event.get("event_source", "Unknown"))

                        with detail_col2:
                            st.write("**Region:**", event.get("region", "Unknown"))
                            st.write("**Resource:**", event.get("resource_name", "Not specified"))
                            st.write("**Status:**", event.get("event_status", "UNKNOWN"))

                        st.write("**Original event JSON:**")
                        st.json(event.get("event_data", {}))

            else:
                st.info(
                    "No stored security events were returned by the API."
                )

        else:
            st.warning(
                "Unable to load raw events. Check that Flask is running "
                "and that /api/events/ is responding."
            )


    # =================================================
    # 5. INCIDENT MANAGEMENT
    # =================================================

    elif page == "Incident Management":

        st.header("🗂️ Incident Management")
        st.caption("Create, review, and update security incidents.")

        incidents = get_api_data("/api/incidents/")
        alerts = get_api_data("/api/alerts/")

        # CREATE INCIDENT
        st.subheader("Create Incident")

        if alerts is not None:
            if alerts:
                alert_options = {
                    int(alert["id"]): alert
                    for alert in alerts
                    if alert.get("id") is not None
                }

                if alert_options:
                    with st.form("create_incident_form"):
                        selected_alert_id = st.selectbox(
                            "Select an alert",
                            options=list(alert_options.keys()),
                            format_func=lambda alert_id: (
                                f'Alert #{alert_id} — '
                                f'{alert_options[alert_id].get("threat_type", "Security alert")} '
                                f'({alert_options[alert_id].get("severity", "Unknown")})'
                            )
                        )

                        default_title = (
                            alert_options[selected_alert_id].get("threat_type")
                            or "Security Incident"
                        )

                        incident_title = st.text_input(
                            "Incident title",
                            value=default_title
                        )

                        create_submitted = st.form_submit_button(
                            "Create Incident"
                        )

                    if create_submitted:
                        if not incident_title.strip():
                            st.error("Please enter an incident title.")
                        else:
                            try:
                                response = requests.post(
                                    API_URL + "/api/incidents/",
                                    json={
                                        "alert_id": selected_alert_id,
                                        "incident_title": incident_title.strip(),
                                        "assigned_to": None
                                    },
                                    timeout=10
                                )

                                if response.ok:
                                    st.success("Incident created successfully.")
                                    st.rerun()
                                else:
                                    st.error(
                                        f"Could not create incident: "
                                        f"{response.text}"
                                    )

                            except requests.RequestException as error:
                                st.error(f"Backend connection failed: {error}")
                else:
                    st.info("No usable alert IDs were returned by the API.")
            else:
                st.info("Create a security alert first, then create an incident.")
        else:
            st.warning("Unable to load alerts from the backend.")

        st.divider()

        # VIEW INCIDENTS
        st.subheader("All Incidents")

        if incidents is not None:
            if incidents:
                incident_df = pd.DataFrame(incidents)
                display_table(incident_df)

                st.divider()

                # UPDATE INCIDENT
                st.subheader("Update Incident")

                incident_options = {
                    int(incident["id"]): incident
                    for incident in incidents
                    if incident.get("id") is not None
                }

                selected_incident_id = st.selectbox(
                    "Choose an incident to update",
                    options=list(incident_options.keys()),
                    format_func=lambda incident_id: (
                        f'Incident #{incident_id} — '
                        f'{incident_options[incident_id].get("title", "Untitled")} '
                        f'[{incident_options[incident_id].get("status", "OPEN")}]'
                    )
                )

                selected_incident = incident_options[selected_incident_id]
                current_status = selected_incident.get("status", "OPEN")
                status_options = ["OPEN", "IN_PROGRESS", "CLOSED"]

                with st.form("update_incident_form"):
                    new_status = st.selectbox(
                        "Incident status",
                        options=status_options,
                        index=(
                            status_options.index(current_status)
                            if current_status in status_options
                            else 0
                        )
                    )

                    investigation_notes = st.text_area(
                        "Investigation notes",
                        value=selected_incident.get("notes") or "",
                        height=150,
                        disabled=False,
                        placeholder="Type your investigation details here..."
                    )

                    update_submitted = st.form_submit_button(
                        "Save Incident Changes"
                    )

                if update_submitted:
                    try:
                        response = requests.put(
                            API_URL + f"/api/incidents/{selected_incident_id}",
                            json={
                                "status": new_status,
                                "notes": investigation_notes
                            },
                            timeout=10
                        )

                        if response.ok:
                            st.success("Incident updated successfully.")
                            st.rerun()
                        else:
                            st.error(
                                f"Could not update incident: {response.text}"
                            )

                    except requests.RequestException as error:
                        st.error(f"Backend connection failed: {error}")

            else:
                st.info("No incidents have been created yet.")
        else:
            st.warning("Unable to load incidents from the backend.")


    # =================================================
    # 6. SECURITY REPORTS
    # =================================================

    elif page == "AWS Brute Force Monitoring":

        st.header("🛡️ AWS Brute-Force Login Monitoring")
        st.caption(
            "Failed AWS console sign-in attempts tracked by Lambda and DynamoDB."
        )

        if st.button("↻ Refresh AWS login records"):
            st.rerun()

        records, dynamodb_error = get_failed_login_records()

        if dynamodb_error:
            st.error(f"Unable to read DynamoDB table: {dynamodb_error}")
            st.info(
                "Check that your local AWS credentials are configured and "
                "that they have dynamodb:Scan permission on FailedLoginAttempts."
            )
        elif not records:
            st.info("No failed-login records are currently stored in DynamoDB.")
        else:
            login_df = pd.DataFrame(records)

            # Normalize values for display without changing the DynamoDB records.
            if "firstAttempt" in login_df.columns:
                login_df["firstAttempt"] = pd.to_numeric(
                    login_df["firstAttempt"], errors="coerce"
                )
                login_df["First Attempt (UTC)"] = pd.to_datetime(
                    login_df["firstAttempt"], unit="s", utc=True, errors="coerce"
                )
            if "attemptCount" in login_df.columns:
                login_df["attemptCount"] = pd.to_numeric(
                    login_df["attemptCount"], errors="coerce"
                )

            total_sources = len(login_df)
            total_attempts = int(
                login_df["attemptCount"].fillna(0).sum()
            ) if "attemptCount" in login_df.columns else 0
            threshold_sources = int(
                (login_df["attemptCount"] >= 5).sum()
            ) if "attemptCount" in login_df.columns else 0

            metric1, metric2, metric3 = st.columns(3)
            metric1.metric("Tracked source IPs", total_sources)
            metric2.metric("Recorded failed attempts", total_attempts)
            metric3.metric("Sources at threshold (5+)", threshold_sources)

            st.divider()
            st.subheader("Failed Login Attempts")

            display_columns = [
                column for column in
                ["sourceIPAddress", "attemptCount", "First Attempt (UTC)", "firstAttempt"]
                if column in login_df.columns
            ]
            display_table(login_df[display_columns])

            if threshold_sources:
                st.warning(
                    f"{threshold_sources} source IP(s) have reached at least "
                    "five failed attempts. Review these sources."
                )

            st.caption(
                "Data is read directly from DynamoDB table FailedLoginAttempts "
                "in us-east-1. This page does not create or modify AWS records."
            )


    elif page == "Reports":

        st.header("📊 Security Reports")

        report_df = pd.DataFrame({

            "Metric": [

                "Total Events",

                "Total Alerts",

                "Open Alerts",

                "Critical Alerts",

                "High Alerts",

                "Medium Alerts",

                "Low Alerts"

            ],

            "Value": [

                total_events,

                total_alerts,

                open_alerts,

                severity_data.get("CRITICAL", 0),

                severity_data.get("HIGH", 0),

                severity_data.get("MEDIUM", 0),

                severity_data.get("LOW", 0)

            ]

        })

        st.subheader(
            "Security Summary"
        )

        display_table(report_df)

        csv_data = report_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(

            label="⬇️ Download Security Report",

            data=csv_data,

            file_name="cloud_security_report.csv",

            mime="text/csv"

        )

else:

    st.warning(
        "Unable to load dashboard data. "
        "Please check whether Flask is running."
    )
