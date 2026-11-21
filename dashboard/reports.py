import requests
import pandas as pd
import streamlit as st

API_URL = "http://127.0.0.1:5000"

st.title("Security Reports")

response = requests.get(
    API_URL + "/api/alerts/",
    timeout=10
)

if response.ok:

    alerts = response.json()

    if alerts:

        df = pd.DataFrame(alerts)

        st.subheader("Security Alert Report")

        st.dataframe(
            df,
            use_container_width=True
        )

        csv_data = df.to_csv(
            index=False
        )

        st.download_button(

            label="Download CSV Report",

            data=csv_data,

            file_name="cloud_security_report.csv",

            mime="text/csv"

        )

    else:

        st.info("No alert records available.")

else:

    st.error("Could not retrieve reports.")