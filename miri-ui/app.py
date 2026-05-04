import streamlit as st
import pandas as pd
import ssl
import os
import requests
import plotly.express as px
from dotenv import load_dotenv

from dynamodb import get_scan_result, get_scan_history


load_dotenv()
LAMBDA_API_URL = os.getenv("LAMBDA_API_URL", "")

USER_ID = 'twalla'
ACCOUNT_ID = ""

def invoke_scanner():

    payload = {
        "user_id": USER_ID,
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

# [3] 사이드바 구성
with st.sidebar:
    st.title("☁️ MIRI Scanner")
    st.info("AWS 환경의 보안 취약점을 점검합니다.")
    
    st.markdown("---")
    st.write(f"**Target Account:** `{USER_ID}`")
    
    if st.button("🚀 Run Security Scan", width="stretch"):
        with st.spinner("🔍 MIRI is scanning your AWS environment..."):
            # 1. API 호출
            result_data = invoke_scanner()
            
            if result_data:
                # 2. 결과 데이터를 세션 스테이트에 저장 (화면 새로고침 대비)
                ACCOUNT_ID = result_data.get('account')
                scan_id = result_data.get('scan_id', "")

                if (scan_id):
                    response = get_scan_result(USER_ID, scan_id)

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
current_account = st.session_state.get('account_id', ACCOUNT_ID)
st.caption(f"Showing results for Account: {ACCOUNT_ID}")

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

    # 상세 테이블 업데이트
    if results:
        df = pd.DataFrame(results)
        
        # 컬럼 순서나 이름을 보기 좋게 조정
        display_df = df[['check_id', 'service', 'resource_id', 'status', 'reason']]
        
        # pandas 최신 버전에서는 applymap 대신 map을 권장하므로 향후를 위해 미리 반영할 수도 있지만
        # 일단 기존 방식(applymap)을 유지하되 정상 작동하도록 배치
        st.dataframe(
            display_df.style.map(color_status, subset=['status']),
            width="stretch"
        )
    else:
        st.info("👈 사이드바에서 정보를 입력하고 스캔을 실행하면 결과가 여기에 표시됩니다.")

# ----------------- 탭 2: 보안 점수 추이 -----------------
with tab2:
    st.subheader("Historical Security Score Trend")
    st.write("과거 스캔 기록을 바탕으로 보안 점수 변화를 확인합니다.")

    # DynamoDB에서 사용자의 히스토리 데이터를 가져옵니다.
    history_data = get_scan_history(USER_ID)

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