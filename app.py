import streamlit as st
import re

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

# دالة فحص الثغرات باستخدام Regex
def scan_code(code_text):
    vulnerabilities = []
    
    # أنماط الكشف (Regex Patterns)
    aws_pattern = r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    api_key_pattern = r"(sk_live_[0-9a-zA-Z]{24,}|api[_-]?key[_-]?['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,})"
    private_key_pattern = r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    
    if re.search(aws_pattern, code_text):
        vulnerabilities.append("⚠️ تم اكتشاف مفتاح AWS Access Key محتمل!")
    if re.search(api_key_pattern, code_text, re.IGNORECASE):
        vulnerabilities.append("🚨 تم اكتشاف مفتاح سري أو API Key مكشوف!")
    if re.search(private_key_pattern, code_text):
        vulnerabilities.append("🔑 تم اكتشاف مفتاح تشفير خاص (Private Key)!")
        
    return vulnerabilities

tab1, tab2 = st.tabs(["Upload File", "Paste Code"])

with tab1:
    f = st.file_uploader("Choose file")
    if f is not None:
        file_content = f.read().decode("utf-8", errors="ignore")
        st.success("تم رفع الملف بنجاح! جاري فحص الأكواد...")
        found_vulns = scan_code(file_content)
        if found_vulns:
            for v in found_vulns:
                st.error(v)
        else:
            st.success("✅ لم يتم اكتشاف ثغرات أو بيانات اعتماد مكشوفة في هذا الملف.")

with tab2:
    p = st.text_area("Paste code here")
    if p:
        if st.button("فحص النص الملصق"):
            with st.spinner("جاري تحليل الكود..."):
                found_vulns = scan_code(p)
                if found_vulns:
                    st.error("⚠️ تم رصد ثغرات أمنية!")
                    for v in found_vulns:
                        st.warning(v)
                else:
                    st.success("✅ لم توجد ثغرات ظاهرة في الكود الملصق.")
