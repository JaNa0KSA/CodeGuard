import re

import streamlit as st


st.set_page_config(
    page_title="CodeGuard - Scanner",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CodeGuard | فاحص الثغرات ومساعد الأمان البرمجي")
st.write("ارفع كودك البرمجي لفحصه فورًا مع ضمان عدم حفظ البيانات (Zero-Persistence).")


def scan_code(code_text: str) -> list[dict]:
    rules = [
        {
            "name": "AWS Access Key",
            "pattern": re.compile(
                r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
            ),
            "severity": "High",
            "attack_scenario": "تمكين المهاجم من الوصول الكامل لتسريب بيانات السحابة أو استهلاك الموارد.",
            "fix": "استخدم متغيرات البيئة: os.getenv('AWS_ACCESS_KEY_ID')",
        },
        {
            "name": "Hardcoded Password",
            "pattern": re.compile(
                r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]"
            ),
            "severity": "High",
            "attack_scenario": "سهولة اختراق الحسابات وقواعد البيانات بمجرد رؤية الكود المصدري.",
            "fix": "تخزين كلمة المرور في ملف .env واستدعاؤها برمجياً.",
        },
        {
            "name": "Generic API Key",
            "pattern": re.compile(
                r"(?i)(api[_-]?key|secret|token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
            ),
            "severity": "Medium",
            "attack_scenario": "استغلال الصلاحيات لإجراء طلبات غير مصرح بها باسم التطبيق.",
            "fix": "تشفير المفاتيح واستدعاؤها عبر متغيرات البيئة.",
        },
    ]
    safe_pattern = re.compile(
        r"(os\.getenv|os\.environ|process\.env|env\.get|get_secret|vault|\.env)",
        re.IGNORECASE,
    )
    findings = []

    for line_num, line in enumerate(code_text.splitlines(), 1):
        if safe_pattern.search(line):
            continue

        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for rule in rules:
            for match in rule["pattern"].finditer(line):
                findings.append(
                    {
                        "line": line_num,
                        "issue": rule["name"],
                        "severity": rule["severity"],
                        "scenario": rule["attack_scenario"],
                        "fix": rule["fix"],
                        "code_snippet": stripped,
                        "matched_value": match.group(0),
                    }
                )

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
                    with st.expander(
                        f"⚠️ {item['issue']} (السطر {item['line']}) - "
                        f"درجة الخطورة: {item['severity']} ):
                        st.write(f"**القيمة المكتشفة:** `{item['matched_value']}`")
                        st.write(f"**السطر البرمجي:** `{item['code_snippet']}`")
                        st.write(f"**سيناريو الهجوم:** {item['scenario']}")
                        st.success(f"**طريقة الإصلاح:** {item['fix']}")
            else:
                st.success("🎉 الكود آمن تمامًا! لم يتم العثور على ثغرات مسجلة.")
