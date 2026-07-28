import streamlit as st
import pandas as pd

st.write("ADMIN FILE UPDATED")
from auth import get_all_users, delete_user, update_user_role
from database import get_history, delete_scan, clear_history
from utils_export import export_csv, export_json

# =====================================
# Admin Dashboard
# =====================================


def show_admin_panel():

    st.title("👑 Admin Panel")

    # =====================================
    # User Management
    # =====================================

    st.header("👥 User Management")

    users = get_all_users()

    if users:

        user_df = pd.DataFrame(users)

        if len(user_df.columns) == 3:

            user_df.columns = ["ID", "Username", "Role"]

        st.dataframe(user_df, use_container_width=True)

        st.subheader("Change User Role")

        user_id = st.number_input("User ID", min_value=1)

        role = st.selectbox("New Role", ["user", "admin"])

        if st.button("Update Role"):

            if update_user_role(user_id, role):

                st.success("Role Updated Successfully")

                st.rerun()

        st.subheader("Delete User")

        delete_id = st.number_input("Delete User ID", min_value=1, key="delete_user")

        if st.button("Delete User"):

            if delete_user(delete_id):

                st.success("User Deleted")

                st.rerun()

    else:

        st.info("No users found")

    st.divider()

    # =====================================
    # Scan Management
    # =====================================

    st.header("📁 Scan Management")

    scans = get_history()

    if scans:

        scan_df = pd.DataFrame(scans)

        

        # Rename based on actual database columns

        if len(scan_df.columns) == 7:

            scan_df.columns = [
                "ID",
                "Website",
                "Score",
                "Risk",
                "Vulnerabilities",
                "Scan Date",
                "Extra",
            ]

        elif len(scan_df.columns) == 6:

            scan_df.columns = [
                "ID",
                "Website",
                "Score",
                "Risk",
                "Vulnerabilities",
                "Scan Date",
            ]

        else:

            scan_df.columns = [f"Column_{i+1}" for i in range(len(scan_df.columns))]

        st.dataframe(scan_df, use_container_width=True)

    else:

        st.info("No scans available")

        # =====================================
        # Export Scan Data
        # =====================================

        st.subheader("📤 Export Scan Reports")

        csv_data = export_csv(scans)

        json_data = export_json(scans)

        st.download_button(
            label="⬇️ Download CSV Report",
            data=csv_data,
            file_name="WebShield_Scan_History.csv",
            mime="text/csv",
        )

        st.download_button(
            label="⬇️ Download JSON Report",
            data=json_data,
            file_name="WebShield_Scan_History.json",
            mime="application/json",
        )

        st.divider()

        # =====================================
        # Delete Scan
        # =====================================

        st.subheader("🗑 Manage Scan Records")

        scan_id = st.number_input("Delete Scan ID", min_value=1, key="scan_delete")

        if st.button("Delete Scan"):

            delete_scan(scan_id)

            st.success("Scan Deleted")

            st.rerun()

        if st.button("Clear All Scan History"):

            clear_history()

            st.success("All Scan History Deleted")

            st.rerun()

        else:

            st.info("No scans available")
