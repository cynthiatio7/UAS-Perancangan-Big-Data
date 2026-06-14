import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import matplotlib.pyplot as plt

st.set_page_config(
    page_title='Event Stream Dashboard',
    layout='wide'
)

# ── Load data ─────────────────────────────────────────────────────────────────
df = pd.read_csv('event_alert_stream.csv')

# ── Title ─────────────────────────────────────────────────────────────────────
st.title('Event Stream Monitoring Dashboard')
st.divider()

# ── KPI Metrics ───────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", len(df))
col2.metric("Critical Alerts", len(df[df['alert_level'] == 'CRITICAL']))
col3.metric("High Alerts",    len(df[df['alert_level'] == 'HIGH']))
col4.metric("Unique Users",   df['user_id'].nunique())

st.divider()

