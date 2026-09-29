import streamlit as st

st.set_page_config(
    page_title="CodeGuard Security",
    layout="wide"
)
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    h1, h2, h3 { color: #f0f2f6; }
    </style>
""", unsafe_allow_html=True)
st.title("CodeGuard System")
st.markdown("Security Analysis Platform")
st.divider()
tab1, tab2 = st.tabs(["Upload File", "Paste Code"])
with tab1:
    f = st.file_uploader("Choose file")
    with tab2:
    p = st.text_area("Paste code here")
    
