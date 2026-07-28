import streamlit as st
import pandas as pd

from database import get_history, get_statistics

# ==========================
# Professional Metric Card
# ==========================


def metric_card(title, value, icon):

    st.markdown(
        f"""
        <div class="card">

            <h4>
                {icon} {title}
            </h4>

            <h2>
                {value}
            </h2>

        </div>
        """,
        unsafe_allow_html=True,
    )


# ==========================
# Dashboard Function
# ==========================


def show_dashboard():

    try:

        history = get_history()
        stats = get_statistics()

        if not history:

            st.info("No scan data available yet.")
            return

        # ==========================
        # Convert Database Data
        # ==========================

        data = []

        for scan in history:

            data.append(
                {
                    "Website": scan[1],
                    "Score": scan[2],
                    "Risk": scan[3],
                    "Date": scan[6],
                }
            )

        df = pd.DataFrame(data)

        # ==========================
        # Dashboard Header
        # ==========================

        st.markdown(
            """
            <div class="card">

            <h1>
            🛡 WebShield Security Dashboard
            </h1>

            <p>
            Website vulnerability assessment analytics
            </p>

            </div>
            """,
            unsafe_allow_html=True,
        )

        # ==========================
        # Calculate High Risk
        # ==========================

        high_risk = 0

        for risk, count in stats["risk_data"]:

            if risk == "High Risk":

                high_risk = count

        # ==========================
        # Professional Metrics
        # ==========================

        col1, col2, col3, col4 = st.columns(4)

        with col1:

            metric_card("Total Scans", stats["total_scans"], "🔍")

        with col2:

            metric_card("Average Score", f"{stats['average_score']}/100", "📊")

        with col3:

            metric_card("High Risk Sites", high_risk, "🔥")

        with col4:

            metric_card("System Status", "Secure", "✅")

        st.divider()

        # ==========================
        # Security Score History
        # ==========================

        st.subheader("📈 Security Score History")

        st.bar_chart(df.set_index("Website")["Score"])

        # ==========================
        # Risk Distribution
        # ==========================

        st.subheader("⚠️ Risk Distribution")

        risk_df = df["Risk"].value_counts().reset_index()

        risk_df.columns = ["Risk", "Count"]

        st.bar_chart(risk_df.set_index("Risk"))

        # ==========================
        # Database Statistics
        # ==========================

        st.subheader("📊 Security Statistics")

        if stats["risk_data"]:

            for risk, count in stats["risk_data"]:

                st.markdown(
                    f"""
                    <div class="card">

                    <h4>
                    {risk}
                    </h4>

                    <h2>
                    {count}
                    </h2>

                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        else:

            st.info("No statistics available.")

        st.divider()

        # ==========================
        # Scan History Table
        # ==========================

        st.subheader("📋 Scan Overview")

        st.dataframe(df, use_container_width=True)

    except Exception as e:

        st.error(f"Dashboard Error: {e}")

        st.exception(e)
