import re
import streamlit as st

st.set_page_config(
    page_title="CodeGuard - Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- الشريط الجانبي (Sidebar) ---
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
    st.title("🛡️ CodeGuard")
    st.caption("منصة الفحص الأمني السريع للملفات والأكواد")
    st.divider()
    st.markdown("### 📌 معلومات النظام")
    st.info("🔒 **حماية البيانات:** لا يتم تخزين أي كود إطلاقًا (Zero-Persistence).")
    st.markdown("---")
    st.markdown("Developed with ❤️ for Security")

# --- الواجهة الرئيسية ---
st.title("🛡️ CodeGuard | درع الأمان البرمجي")
st.markdown("##### افحص كودك البرمجي واكتشف الثغرات والأخطاء الأمنية قبل النشر بسهولة واحترافية.")
st.divider()

# كروت الإحصائيات الفخمة
col1, col2, col3 = st.columns(3)
col1.metric(label="حالة النظام", value="نشط 🟢")
col2.metric(label="القواعد النشطة", value="3 Rules")
col3.metric(label="التشفير والأمان", value="100%")

st.write("")

# خيارات المدخلات (رفع ملف أو لصق كود)
tab1, tab2 = st.tabs(["📝 لصق الكود مباشرة", "📁 رفع ملف برمجي"])

code_content = ""

with tab1:
    user_code = st.text_area("أدخل الكود البرمجي هنا للفحص:", height=220, placeholder="import os\nAWS_KEY = 'AKIA1234567890EXAMPLE'...")
    if user_code:
        code_content = user_code

with tab2:
    uploaded_file = st.file_uploader("اختر ملفًا (.py, .js, .txt)", type=["py", "txt", "js"])
    if uploaded_file is not None:
        try:
            code_content = uploaded_file.getvalue().decode("utf-8")
            st.success(f"تم تحميل الملف: `{uploaded_file.name}` بنجاح!")
        except UnicodeDecodeError:
            st.error("تعذر قراءة الملف. يرجى رفعه بترميز UTF-8.")

# دالة الفحص
def scan_code(code_text: str) -> list[dict]:
    rules = [
        {
            "name": "AWS Access Key Leak",
            "pattern": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            "severity": "🔴 عالية جداً (Critical)",
            "attack_scenario": "تمكين المهاجم من الوصول الكامل لتسريب بيانات السحابة وتدمير الموارد.",
            "fix": "استخدم متغيرات البيئة: `os.getenv('AWS_ACCESS_KEY_ID')`"
        },
        {
            "name": "Hardcoded Password",
            "pattern": re.compile(r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]"),
            "severity": "🟠 عالية (High)",
            "attack_scenario": "سهولة اختراق الحسابات وقواعد البيانات بمجرد قراءة الكود المصدري.",
            "fix": "تخزين كلمة المرور في ملف `.env` واستدعائها برمجياً."
        },
        {
            "name": "Generic API Key Leak",
            "pattern": re.compile(r"(?i)(api[_-]?key|secret|token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
            "severity": "🟡 متوسطة (Medium)",
            "attack_scenario": "استغلال الصلاحيات لإجراء طلبات غير مصرح بها باسم التطبيق.",
            "fix": "تشفير المفاتيح واستدعاؤها عبر متغيرات البيئة."
        }
    ]
    
    safe_pattern = re.compile(r"(os\.getenv|os\.environ|process\.env|env\.get|get_secret|vault|\.env)", re.IGNORECASE)
    findings = []

    for line_num, line in enumerate(code_text.splitlines(), 1):
        if safe_pattern.search(line):
            continue
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule in rules:
            for match in rule["pattern"].finditer(line):
                findings.append({
                    "line": line_num,
                    "issue": rule["name"],
                    "severity": rule["severity"],
                    "scenario": rule["attack_scenario"],
                    "fix": rule["fix"],
                    "code_snippet": stripped,
                    "matched_value": match.group(0)
                })
    return findings

# زر الفحص
st.write("")
if st.button("🚀 ابدأ الفحص الأمني الشامل", type="primary", use_container_width=True):
    if code_content.strip():
        with st.spinner("جاري تحليل الكود والبحث عن الثغرات..."):
            results = scan_code(code_content)
            st.divider()
            
            if results:
                st.error(f"🚨 تم اكتشاف {len(results)} ثغرة أمنية تتطلب معالجتها!")
                for item in results:
                    with st.expander(f"⚠️ {item['issue']} — (السطر {item['line']})", expanded=True):
                        c1, c2 = st.columns(2)
                        c1.write(f"**درجة الخطورة:** {item['severity']}")
                        c1.write(f"**القيمة المكتشفة:** `{item['matched_value']}`")
                        c2.write(f"**السطر البرمجي:** `{item['code_snippet']}`")
                        
                        st.markdown("---")
                        st.write(f"🎯 **سيناريو الهجوم:** {item['scenario']}")
                        st.success(f"💡 **طريقة الإصلاح:** {item['fix']}")
            else:
                st.balloons()
                st.success("🎉 الكود آمن تماماً! لم يتم العثور على أي ثغرات برمجية مسجلة.")
    else:
        st.warning("⚠️ الرجاء إدخال كود أو رفع ملف أولاً لإجراء الفحص.")
                        findings.append({
    "line": line_num,
    "issue": rule["name"],
    "severity": rule["severity"],
    "scenario": rule["attack_scenario"],
    "fix": rule["fix"],
    "code_snippet": stripped,
    "matched_value": match.group(0)
})

    return findings


uploaded_file = st.file_uploader(
    "اختر ملف برمجي لفحصه (.py, .js, .txt)",
    type=["py", "txt", "js"],
)

if uploaded_file is not None:
    try:
        code_content = uploaded_file.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        st.error("تعذر قراءة الملف. ارفع ملفًا نصيًا بترميز UTF-8.")
    else:
        st.caption(f"الملف المحدد: `{uploaded_file.name}`")
        if st.button("🔍 ابدأ الفحص الآن", type="primary"):
            results = scan_code(code_content)

            if results:
                st.error(f"تم العثور على {len(results)} ثغرة أمنية!")
                for item in results:
                    with st.expander(f"⚠️ {item['issue']} (السطر {item['line']})"):
                        st.write(f"درجة الخطورة: {item['severity']}")
                        st.write(f"**القيمة المكتشفة:** `{item['matched_value']}`")
                        st.write(f"**السطر البرمجي:** `{item['code_snippet']}`")
                        st.write(f"**سيناريو الهجوم:** {item['scenario']}")
                        st.success(f"**طريقة الإصلاح:** {item['fix']}")
            else:
                st.success("🎉 الكود آمن تمامًا! لم يتم العثور على ثغرات مسجلة.")

