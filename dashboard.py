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

st.title("Critical Alert Table")
critical_df = df[df['alert_level'] == 'CRITICAL']
st.dataframe(critical_df, use_container_width=True)
 
st.divider()

st.title("🛡️ Rekomendasi Mitigasi Ancaman")
st.markdown("Panduan langkah-langkah mitigasi berdasarkan pola anomali yang terdeteksi:")

mitigasi = {
    "Pola 1 - Terminated User": [
        "Nonaktifkan akun otomatis saat karyawan keluar (offboarding otomatis)",
        "Audit akun secara berkala untuk cari akun yang belum dinonaktifkan",
        "Terapkan Zero Trust: semua sesi harus diverifikasi ulang",
    ],
    "Pola 2 - Download Besar Data Sensitif": [
        "Pasang DLP (Data Loss Prevention) untuk blokir transfer data besar tanpa izin",
        "Enkripsi semua aset confidential dan restricted",
        "Batasi akses hanya ke aset yang benar-benar dibutuhkan (least privilege)",
    ],
    "Pola 3 - Permission Change dari IP Eksternal": [
        "Batasi permission change hanya dari jaringan internal atau VPN",
        "Wajibkan MFA (Multi-Factor Authentication) untuk ubah hak akses",
        "Setiap perubahan hak akses butuh persetujuan minimal 2 orang",
    ],
    "Pola 4 - Clearance Mismatch": [
        "Blokir otomatis jika clearance user lebih rendah dari klasifikasi aset",
        "Periksa clearance semua karyawan saat onboarding dan review berkala",
        "Kirim alert ke tim keamanan jika mismatch terdeteksi",
    ],
}

# Iterasi dictionary dan tampilkan menggunakan UI Streamlit
# Menggunakan st.expander agar rapi dan interaktif (bisa di-drop down)
for pola, tips in mitigasi.items():
    with st.expander(f"📌 {pola}"):
        for tip in tips:
            # Gunakan st.markdown untuk membuat bullet points seperti di HTML/Markdown
            st.markdown(f"- {tip}")
            
st.divider()

