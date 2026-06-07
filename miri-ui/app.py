import streamlit as st
import pandas as pd
import ssl
import os
import requests
import plotly.express as px
from dotenv import load_dotenv

from dynamodb import get_scan_result, get_scan_history, get_guide_data_with_meta, register_user, authenticate_user


load_dotenv()
LAMBDA_API_URL = os.getenv("LAMBDA_API_URL", "")

def get_user_id() -> str:
    return st.session_state.get('user_id', '')

def get_account_id() -> str:
    return st.session_state.get('account_id', '')

SEVERITY_META = {
    "CIS-AWS-v7.0.0" : {
        "Level 1": "필수적인 기본 보안 설정입니다.\n비즈니스 운영에 지장을 주지 않으므로 신속한 적용을 권장합니다.",
        "Level 2": "심층 방어를 위한 엄격한 설정입니다.\n서비스 기능이 제한될 수 있어 충분한 테스트 후 적용을 권장합니다."
    }
}

def invoke_scanner():

    payload = {
        "user_id": get_user_id(),
    }
    
    try:
        # API Gateway로 POST 요청 전송
        response = requests.post(LAMBDA_API_URL, json=payload, timeout=30)
        response.raise_for_status() # 4xx, 5xx 에러 시 예외 발생
        return response.json()
    except Exception as e:
        st.error("❌ 스캔 실행 중 알 수 없는 오류가 발생했습니다.")
        print(f"[LOG] 내부 오류 발생: {str(e)}")
        return None

# [추가됨] 표에 색상을 입히는 함수는 위쪽에 미리 정의해야 합니다!
def color_status(val):
    color = 'red' if val == 'FAIL' else 'green'
    return f'color: {color}; font-weight: bold'

@st.dialog(" ", width="medium")
def show_guide_modal(check_id, isms_p=None):
    # 1. DB에서 데이터 패치
    data_package = get_guide_data_with_meta(check_id)
    
    if not data_package or not data_package.get("guide"):
        st.error(f"앗! 규칙 ID '{check_id}'에 대한 가이드 데이터를 DB에서 찾을 수 없습니다.")
        st.info("데이터베이스에 해당 가이드가 적재되어 있는지 확인해 주세요.")
        return

    guide_data = data_package["guide"]
    meta_data = data_package.get("meta") if data_package.get("meta") else {}

    # 🌟 pro 팁: 맨 위에 제목이 들어갈 '빈 공간(Container)'을 먼저 선언합니다.
    title_placeholder = st.container()

    # 🌟 제목 아래에 등급과 언어 버튼을 배치할 7:3 컬럼 생성
    col1, col2 = st.columns([8, 2])
    
    # col2(우측)에 언어 선택 라디오 버튼을 먼저 실행하여 lang 변수를 확보합니다.
    with col2:
        selected_lang = st.radio(
            "언어 선택", 
            options=["ko", "en"], 
            format_func=lambda x: "🇰🇷 한국어" if x == "ko" else "🇺🇸 English",
            horizontal=True,
            label_visibility="collapsed"
        )
    
    lang = selected_lang 
    
    # 다국어 파싱 헬퍼 함수
    def parse_i18n_text(field_value, default_text="내용 없음"):
        if isinstance(field_value, dict):
            return field_value.get(lang, default_text)
        elif isinstance(field_value, str):
            return field_value
        return default_text

    # 2. 메타 데이터 데이터 추출 및 파싱
    service = guide_data.get("service", "AWS")
    severity = guide_data.get("severity", "Level 1")
    rule_id = guide_data.get("rule_id", check_id)
    title = parse_i18n_text(guide_data.get("title"), "제목 없음")
    
    # 🌟 맨 위 빈 공간에 전체 너비로 대제목 렌더링
    title_placeholder.markdown(f"## [{service} {rule_id}] {title}")
    
    # DB METADATA에서 등급 가이드 설명문 추출
    severity_definitions = meta_data.get("severity_definitions", {})
    target_severity_dict = severity_definitions.get(severity, {})
    severity_help = parse_i18n_text(target_severity_dict, "해당 등급에 대한 상세 설명이 없습니다.")
    
    # 🌟 col1(좌측)에 Severity(말풍선 포함) 렌더링
    with col1:
        st.markdown(f"**Severity:** {severity}", help=severity_help)
        
    st.divider() # 타이틀 세션 구분선
    
    # 3. 상세 설명 및 근거
    st.subheader("📖 Description & Rationale")
    description = parse_i18n_text(guide_data.get("description"), "설명이 제공되지 않았습니다.")
    rationale = parse_i18n_text(guide_data.get("rationale"), "위험성 근거가 제공되지 않았습니다.")
    
    st.markdown("**Description:**")
    st.info(description)
    
    st.markdown("**Rationale:**")
    st.warning(rationale)
    st.divider()
    
    # 4. 조치 방법 (Remediation)
    st.subheader("💡 Remediation")
    remediation = guide_data.get("remediation", {})
    
    tab1, tab2 = st.tabs(["💻 AWS Console", "⌨️ AWS CLI"])
    
    with tab1:
        console_guide = parse_i18n_text(remediation.get("console"), "콘솔 가이드가 제공되지 않았습니다.")
        st.markdown(console_guide)
        
    with tab2:
        cli_cmd = remediation.get("cli", "")
        if cli_cmd:
            st.code(cli_cmd, language="bash")
        else:
            st.write("CLI 명령어가 제공되지 않았습니다." if lang == "ko" else "CLI command is not provided.")
               
    # 5. 참고 자료
    references = guide_data.get("references", [])
    if references:
        st.divider()
        expander_title = "📚 References"
        with st.expander(expander_title):
            for ref in references:
                if ref.startswith("http"):
                    st.markdown(f"- [{ref}]({ref})")
                else:
                    st.markdown(f"- {ref}")

    # 6. ISMS-P 연관 항목
    if isms_p:
        st.divider()
        st.subheader("🇰🇷 ISMS-P 연관 항목")
        for item in isms_p:
            st.markdown(f"- **{item['id']}** {item['name']}")

# [1] SSL 에러 방지
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context
os.environ['PYTHONHTTPSVERIFY'] = '0'

# [2] 페이지 설정
st.set_page_config(
    page_title="MIRI - AWS Security Dashboard",
    page_icon="☁️",
    layout="wide"
)

# [3] 인증 게이트 — 미로그인 시 로그인/회원가입 화면만 표시
if not st.session_state.get('logged_in', False):
    st.title("☁️ MIRI")
    login_tab, signup_tab = st.tabs(["로그인", "회원가입"])

    with login_tab:
        with st.form("login_form"):
            uid = st.text_input("아이디")
            pw  = st.text_input("비밀번호", type="password")
            submitted = st.form_submit_button("로그인", use_container_width=True)

        if submitted:
            if not uid or not pw:
                st.error("아이디와 비밀번호를 입력하세요.")
            else:
                result = authenticate_user(uid, pw)
                if result['ok']:
                    st.session_state['logged_in']  = True
                    st.session_state['user_id']    = uid
                    st.session_state['account_id'] = result['account_id']
                    st.rerun()
                else:
                    st.error(result['error'])

    with signup_tab:
        with st.form("signup_form"):
            new_uid        = st.text_input("아이디")
            new_pw         = st.text_input("비밀번호", type="password")
            new_pw_confirm = st.text_input("비밀번호 확인", type="password")
            new_account_id = st.text_input("AWS Account ID (12자리)")
            submitted_signup = st.form_submit_button("회원가입", use_container_width=True)

        if submitted_signup:
            if not all([new_uid, new_pw, new_pw_confirm, new_account_id]):
                st.error("모든 항목을 입력하세요.")
            elif new_pw != new_pw_confirm:
                st.error("비밀번호가 일치하지 않습니다.")
            elif not new_account_id.isdigit() or len(new_account_id) != 12:
                st.error("AWS Account ID는 12자리 숫자여야 합니다.")
            else:
                result = register_user(new_uid, new_pw, new_account_id)
                if result['ok']:
                    st.success("회원가입이 완료되었습니다.")
                    st.info(
                        "아래 External ID를 복사하여 AWS IAM 역할의 신뢰 정책에 등록해 주세요. "
                        "이 값은 다시 확인할 수 없습니다."
                    )
                    st.code(result['external_id'])
                else:
                    st.error(result['error'])

    st.stop()

# [4] 사이드바 구성
with st.sidebar:
    st.title("☁️ MIRI Scanner")
    st.info("AWS 환경의 보안 취약점을 점검합니다.")

    st.markdown("---")
    st.write(f"**User:** `{get_user_id()}`")
    st.write(f"**Account:** `{get_account_id()}`")

    if st.button("로그아웃", use_container_width=True):
        st.session_state.clear()
        st.rerun()

    if st.button("🚀 Run Security Scan", width="stretch"):
        with st.spinner("🔍 MIRI is scanning your AWS environment..."):
            # 1. API 호출
            result_data = invoke_scanner()

            if result_data:
                # 2. 결과 데이터를 세션 스테이트에 저장 (화면 새로고침 대비)
                st.session_state['account_id'] = result_data.get('account')
                scan_id = result_data.get('scan_id', "")

                if (scan_id):
                    response = get_scan_result(get_user_id(), scan_id)

                    if response:
                        st.session_state['scan_results'] = response.get('Findings', [])
                        st.session_state['summary'] = response.get('Summary', {})
                        st.success("✅ Scan Completed!")
                    else:
                        st.error("❌ DB에서 스캔 결과를 찾을 수 없습니다.")
                else:
                    st.error("❌ SCAN ID를 찾을 수 없습니다.")

# [4] 메인 화면 구성
st.title("Dashboard: AWS Security Assessment")
st.caption(f"Showing results for Account: {get_account_id()}")

tab1, tab2 = st.tabs(["📊 최신 스캔 결과", "📈 최근 보안 점수 추이"])

with tab1:
    # 세션에 결과가 있으면 실제 데이터를 쓰고, 없으면 0으로 표시
    results = st.session_state.get('scan_results', [])
    summary = st.session_state.get('summary', {"total_checks_evaluated": 0, "passed_checks": 0, "failed_checks": 0})

    # 상단 요약 지표 업데이트
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Checks", summary['total_checks_evaluated'])
    col2.metric("Passed", summary['passed_checks'])
    col3.metric("Failed", summary['failed_checks'], delta_color="inverse")

    st.markdown("---")

    # 결과가 있을 때만 원 그래프(Pie chart) 그리기
    if summary['total_checks_evaluated'] > 0:
        st.subheader("Scan Results Overview")
        
        # 그래프를 위한 데이터프레임 생성
        pie_data = pd.DataFrame({
            'Status': ['Passed', 'Failed'],
            'Count': [summary['passed_checks'], summary['failed_checks']]
        })
        
        # Plotly로 도넛형 원 그래프 생성 (hole=0.4)
        fig = px.pie(pie_data, values='Count', names='Status', 
                    color='Status',
                    color_discrete_map={'Passed':'#2ecc71', 'Failed':'#e74c3c'},
                    hole=0.4)
        
        # 그래프 디자인 살짝 다듬기
        fig.update_traces(textposition='inside', textinfo='percent+label')
        fig.update_layout(margin=dict(t=0, b=0, l=0, r=0), height=350)
        
        # 대시보드에 그래프 출력
        st.plotly_chart(fig, width="stretch")
        st.markdown("---")

    if results:
        df = pd.DataFrame(results)
        display_df = df[['check_id', 'service', 'resource_id', 'status', 'reason']]
        
        st.markdown("### 📋 보안 스캔 결과")
        st.caption("💡 상세 조치 가이드를 보려면 **해당 행(Row)을 클릭**하세요.")
        
        # 1.56 버전의 핵심 기능인 on_select와 selection_mode를 적용합니다.
        selection = st.dataframe(
            display_df,
            on_select="rerun",                 # 클릭 시 스크립트 재실행하여 감지
            selection_mode="single-row",       # 한 번에 한 행만 선택 가능하도록 설정
            hide_index=True,                   # 인덱스 숨김
            width='stretch'
        )
        
        # 사용자가 행을 클릭했는지 확인 후 모달창 실행
        if selection and selection["selection"]["rows"]: # type: ignore
            selected_row_idx = selection["selection"]["rows"][0] # type: ignore
            clicked_check_id = display_df.iloc[selected_row_idx]['check_id']
            clicked_isms_p = results[selected_row_idx].get('isms_p', [])

            show_guide_modal(clicked_check_id, isms_p=clicked_isms_p)
    else:
        st.info("👈 사이드바에서 정보를 입력하고 스캔을 실행하면 결과가 여기에 표시됩니다.")

# ----------------- 탭 2: 보안 점수 추이 -----------------
with tab2:
    st.subheader("Historical Security Score Trend")
    st.write("과거 스캔 기록을 바탕으로 보안 점수 변화를 확인합니다.")

    # DynamoDB에서 사용자의 히스토리 데이터를 가져옵니다.
    history_data = get_scan_history(get_user_id())

    if history_data:
        # 데이터 형태가 고정되어 있다는 가정하에 '리스트 컴프리헨션'으로 단 3줄 만에 가공!
        parsed_data = [
            {
                'date': item['SK'].replace('SCAN#', ''), # type: ignore
                'score': item['Summary'].get('score', 0) # type: ignore
            }
            for item in history_data if item.get('SK', '').startswith('SCAN#') # type: ignore
        ]
        
        if parsed_data:
            history_df = pd.DataFrame(parsed_data)
            
            # 날짜형식으로 변환 후 정렬
            history_df['date'] = pd.to_datetime(history_df['date'])
            history_df = history_df.sort_values(by='date')
            
            # 꺾은선 그래프 렌더링
            trend_fig = px.line(
                history_df, x='date', y='score', markers=True,
                title="Security Score Over Time",
                labels={'date': 'Scan Date', 'score': 'Security Score (0-100)'}
            )
            
            trend_fig.update_layout(yaxis=dict(range=[0, 105]), hovermode="x unified")
            trend_fig.update_traces(line_color='#3498db', marker=dict(size=8))
            
            st.plotly_chart(trend_fig, width="stretch")
        else:
            st.warning("스캔 히스토리 데이터가 부족하여 그래프를 그릴 수 없습니다.")
    else:
        st.info("보안 스캔 히스토리 데이터가 아직 없습니다. 스캔을 먼저 실행해 보세요.")