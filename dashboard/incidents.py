import requests
import streamlit as st
import pandas as pd

API_URL = "http://127.0.0.1:5000"


st.title("Incident Management Center")


response = requests.get(
    API_URL + "/api/incidents/",
    timeout=10
)

if response.ok:

    incidents = response.json()

    if incidents:

        df = pd.DataFrame(incidents)

        st.dataframe(
            df,
            use_container_width=True
        )

    else:

        st.info("No incidents recorded.")

else:

    st.error("Unable to load incidents.")