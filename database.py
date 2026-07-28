import sqlite3
import json
import os
from datetime import datetime
import streamlit as st

# =====================================
# Database Configuration
# =====================================

DATABASE_FOLDER = "database"

DATABASE = os.path.join(DATABASE_FOLDER, "webshield.db")


# =====================================
# Create Folder
# =====================================


def create_database_folder():

    if not os.path.exists(DATABASE_FOLDER):

        os.makedirs(DATABASE_FOLDER)


# =====================================
# Connection
# =====================================


def get_connection():

    create_database_folder()

    return sqlite3.connect(DATABASE, check_same_thread=False)


# =====================================
# Create Database
# =====================================


def create_database():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans
    (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        url TEXT NOT NULL,

        score INTEGER,

        severity TEXT,

        vulnerabilities TEXT,

        severity_report TEXT,

        scan_date TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users
    (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT UNIQUE,

        password TEXT,

        role TEXT DEFAULT 'user'
    )
    """)

    conn.commit()

    conn.close()


# =====================================
# Save Scan
# =====================================


def save_scan(url, score, severity, vulnerabilities, severity_report):

    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans
            (
                url,
                score,
                severity,
                vulnerabilities,
                severity_report,
                scan_date
            )
            VALUES (?,?,?,?,?,?)
            """,
            (
                url,
                score,
                severity,
                json.dumps(vulnerabilities),
                json.dumps(severity_report),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

        conn.commit()
        conn.close()

        return True

    except Exception as e:

        st.error(f"Database Error: {e}")

        return False


# =====================================
# Get History
# =====================================


def get_history():

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                url,
                score,
                severity,
                vulnerabilities,
                severity_report,
                scan_date
            FROM scans
            ORDER BY id DESC
        """)

        data = cursor.fetchall()

        conn.close()

        return data

    except Exception as e:

        st.error(f"History Error: {e}")

        return []


# =====================================
# Dashboard Statistics
# =====================================


def get_statistics():

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(score) FROM scans")
        average_score = cursor.fetchone()[0]

        if average_score is None:
            average_score = 0

        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM scans
            GROUP BY severity
        """)

        risk_data = cursor.fetchall()

        conn.close()

        return {
            "total_scans": total_scans,
            "average_score": round(average_score, 2),
            "risk_data": risk_data,
        }

    except Exception as e:

        st.error(f"Statistics Error: {e}")

        return {
            "total_scans": 0,
            "average_score": 0,
            "risk_data": [],
        }

    # Risk distribution

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM scans
        GROUP BY severity
        """)

    risk_data = cursor.fetchall()

    conn.close()

    return {
        "total_scans": total_scans,
        "average_score": round(avg_score, 2),
        "risk_data": risk_data,
    }


# =====================================
# Previous Scan
# =====================================


def get_previous_scan(url):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
    SELECT *
    FROM scans

    WHERE url=?

    ORDER BY id DESC

    LIMIT 2
    """,
        (url,),
    )

    scans = cursor.fetchall()

    conn.close()

    if len(scans) > 1:

        return scans[1]

    return None


# =====================================
# Delete Scan
# =====================================


def delete_scan(scan_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
    DELETE FROM scans

    WHERE id=?
    """,
        (scan_id,),
    )

    conn.commit()

    conn.close()


# =====================================
# Clear History
# =====================================


def clear_history():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM scans")

    conn.commit()

    conn.close()
