import streamlit as st
import pandas as pd
import ssl
import os
import requests
import plotly.express as px
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("API_URL", "")

def invoke_scanner(account_id, external_id):
    payload = {
        "target_account_id": account_id,
        "external_id": external_id
    }
    
    try:
        # API Gateway로 POST 요청 전송
        response = requests.post(API_URL, json=payload, timeout=30)
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

# [1] SSL 에러 방지 (아까 마주친 에러 예방용)
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

# [3] 사이드바 구성
with st.sidebar:
    st.title("☁️ MIRI Scanner")
    st.info("AWS 환경의 보안 취약점을 점검합니다.")
    
    st.markdown("---")
    st.subheader("AWS Account Configuration")
    
    target_account = st.text_input("AWS Account ID", placeholder="123456789012")
    external_id = st.text_input("External ID", type="password", help="AssumeRole에 필요한 보안 ID")
    
    st.markdown("---")
    if st.button("🚀 Run Security Scan", use_container_width=True):
        if not target_account:
            st.warning("Please enter a Target Account ID.")
        else:
            with st.spinner("🔍 MIRI is scanning your AWS environment..."):
                # 1. API 호출
                result_data = invoke_scanner(target_account, external_id)
                
                if result_data:
                    # 2. 결과 데이터를 세션 스테이트에 저장 (화면 새로고침 대비)
                    st.session_state['scan_results'] = result_data.get('findings', [])
                    st.session_state['summary'] = result_data.get('summary', {})
                    st.success("✅ Scan Completed!")

# [4] 메인 화면 구성
st.title("Dashboard: AWS Security Assessment")
st.caption(f"Connected to: {target_account if target_account else 'None'}")


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
    st.plotly_chart(fig, use_container_width=True)
    st.markdown("---")

# 상세 테이블 업데이트
if results:
    df = pd.DataFrame(results)
    
    # 컬럼 순서나 이름을 보기 좋게 조정
    display_df = df[['check_id', 'service', 'resource_id', 'status', 'reason']]
    
    # pandas 최신 버전에서는 applymap 대신 map을 권장하므로 향후를 위해 미리 반영할 수도 있지만
    # 일단 기존 방식(applymap)을 유지하되 정상 작동하도록 배치
    st.dataframe(
        display_df.style.applymap(color_status, subset=['status']),
        use_container_width=True
    )
else:
    st.info("👈 사이드바에서 정보를 입력하고 스캔을 실행하면 결과가 여기에 표시됩니다.")