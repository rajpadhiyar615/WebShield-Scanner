import streamlit as st


def load_css():

    st.markdown(
        """
        <style>

        /* Main Background */

        .stApp {
            background-color:#0E1117;
            color:white;
        }


        /* Sidebar */

        section[data-testid="stSidebar"] {

            background-color:#111827;

        }


        /* Cards */

        .card {

            background:#161B22;
            padding:20px;
            border-radius:15px;
            border:1px solid #263043;
            margin-bottom:20px;

        }


        .title {

            color:#00BFFF;
            font-size:40px;
            font-weight:700;

        }


        .subtitle {

            color:#9CA3AF;
            font-size:18px;

        }


        /* Buttons */

        div.stButton > button {

            background:#00BFFF;
            color:white;
            border-radius:10px;
            height:45px;
            font-weight:bold;

        }


        div.stButton > button:hover {

            background:#0284C7;

        }


        </style>

        """,
        unsafe_allow_html=True,
    )
