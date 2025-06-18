import json
import streamlit as st # type: ignore
import pandas as pd # type: ignore
import plotly.express as px # type: ignore
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod
from enum import Enum
import subprocess
import webbrowser
import time
import threading
from gpt import OpenAIClient

# ==================== Domain ====================

class ImpactLevel(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    OPTIMIZATION = "Optimization"

class ConfidenceLevel(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

@dataclass
class Vulnerability:
    id: str
    check: str
    impact: str
    confidence: str
    description: str
    elements: List[Dict] = None
    
    def __post_init__(self):
        if self.elements is None:
            self.elements = []

@dataclass
class Vulnerability_GPT:
    id: str
    title: str
    explanation: str

@dataclass
class SecurityScore:
    total_score: float
    impact_counts: Dict[str, int]
    deployment_status: str
    total_deduction: float

@dataclass
class ReportSummary:
    vulnerability_count: int
    security_score: float
    main_concerns: List[str]
    user_prompt: str
    summary_contents: str
    
    def __init__(self, summary_str):
        self.summary_contents = summary_str
    
@dataclass
class VulnerabilityDetail:
    vulnerability: Vulnerability
    code_locations: List[str]
    technical_explanation: str
    personalized_explanation: str
    reference_links: List[str]

# ==================== Use Cases Layer ====================

class SecurityScoreCalculator:
    """보안 점수 계산 로직"""
    
    IMPACT_WEIGHTS = {
        'High': 20,
        'Medium': 10,
        'Low': 5,
        'Informational': 2,
        'Optimization': 0
    }
    
    CONFIDENCE_MULTIPLIERS = {
        'High': 1.0,
        'Medium': 0.7,
        'Low': 0.4
    }
    
    @classmethod
    def calculate(cls, vulnerabilities: List[Vulnerability]) -> SecurityScore:
        if not vulnerabilities:
            return SecurityScore(
                total_score=100.0,
                impact_counts={level.value: 0 for level in ImpactLevel},
                deployment_status="배포 권장 - 매우 안전함",
                total_deduction=0.0
            )
        
        impact_counts = {level.value: 0 for level in ImpactLevel}
        total_deduction = 0.0
        
        for vuln in vulnerabilities:
            impact_counts[vuln.impact] += 1
            
            impact_score = cls.IMPACT_WEIGHTS.get(vuln.impact, 1)
            confidence_ratio = cls.CONFIDENCE_MULTIPLIERS.get(vuln.confidence, 0.5)
            deduction = impact_score * confidence_ratio
            total_deduction += deduction
        
        final_score = max(0, 100 - total_deduction)
        deployment_status = cls._get_deployment_status(final_score)
        
        return SecurityScore(
            total_score=round(final_score, 1),
            impact_counts=impact_counts,
            deployment_status=deployment_status,
            total_deduction=round(total_deduction, 1)
        )
    
    @staticmethod
    def _get_deployment_status(score: float) -> str:
        if score >= 90:
            return "배포 권장 - 매우 안전함"
        elif score >= 70:
            return "주의하여 배포 가능 - 일부 취약점 존재"
        elif score >= 50:
            return "배포 전 수정 필요 - 중요한 취약점 존재"
        else:
            return "배포 금지 - 심각한 보안 위험 존재"

class VulnerabilityPrioritizer:
    """취약점 우선순위 정렬 로직"""
    
    IMPACT_PRIORITY = {'High': 4, 'Medium': 3, 'Low': 2, 'Informational': 1, 'Optimization': 0}
    CONFIDENCE_PRIORITY = {'High': 3, 'Medium': 2, 'Low': 1}
    
    @classmethod
    def sort_by_priority(cls, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        def priority_key(vuln):
            impact_score = cls.IMPACT_PRIORITY.get(vuln.impact, 0)
            confidence_score = cls.CONFIDENCE_PRIORITY.get(vuln.confidence, 0)
            return (impact_score, confidence_score)
        
        return sorted(vulnerabilities, key=priority_key, reverse=True)

class VulnerabilityDetailProcessor:
    """취약점 상세 정보 처리 로직"""
    
    @staticmethod
    def process(vulnerability: Vulnerability, raw_data: Dict, vulnerability_gpt: Vulnerability_GPT) -> VulnerabilityDetail:
        code_locations = VulnerabilityDetailProcessor._extract_code_locations(raw_data)

        technical_explanation = f"이 취약점은 {vulnerability.check} ({vulnerability_gpt.title}) 유형으로, {vulnerability.impact} 수준의 위험도를 가집니다."
        personalized_explanation = vulnerability_gpt.explanation
        
        reference_links = VulnerabilityDetailProcessor._get_reference_links(vulnerability.check)
        
        return VulnerabilityDetail(
            vulnerability=vulnerability,
            code_locations=code_locations,
            technical_explanation=technical_explanation,
            personalized_explanation=personalized_explanation,
            reference_links=reference_links
        )
    
    @staticmethod
    def _extract_code_locations(raw_data: Dict) -> List[str]:
        locations = []
        elements = raw_data.get('elements', [])
        
        for element in elements:
            if 'source_mapping' in element:
                source_info = element['source_mapping']
                filename = element['name']
                lines = source_info.get('lines', 'Unknown')
                locations.append(f"name: {filename}, 라인: {lines}")
        
        return locations
    
    @staticmethod
    def _get_reference_links(check_name: str) -> List[str]: #Slither check 유형에 따라 링크 생성 하게 함
        base_links = [
            f"https://github.com/crytic/slither/wiki/Detector-Documentation#{check_name.lower().replace(' ', '-')}"
        ]
        return base_links

# ==================== Infrastructure Layer ====================

class SlitherDataParser:
    """Slither JSON 데이터 파싱"""
    
    @staticmethod
    def parse(json_data: Dict) -> tuple[List[Vulnerability], List[Dict]]:
        vulnerabilities = []
        raw_detectors = []
        
        if 'results' not in json_data or 'detectors' not in json_data['results']:
            return vulnerabilities, raw_detectors
        
        for detector in json_data['results']['detectors']:
            vulnerability = Vulnerability(
                id=detector.get('id', 'None'),
                check=detector.get('check', 'Unknown'),
                impact=detector.get('impact', 'Unknown'),
                confidence=detector.get('confidence', 'Unknown'),
                description=detector.get('description', 'No description'),
                elements=detector.get('elements', [])
            )
            vulnerabilities.append(vulnerability)
            raw_detectors.append(detector)
        
        return vulnerabilities, raw_detectors

class GPTDataParser:
    """GPT 결과 중 detectors 파싱"""
    
    @staticmethod
    def parse(detectors_gpt: Dict) -> List[Vulnerability_GPT]:
        vulnerabilities_gpt = []
        
        for detector in detectors_gpt:
            vulnerability_gpt = Vulnerability_GPT(
                id=detector.get('id', 'None'),
                title=detector.get('title', 'Unknown'),
                explanation=detector.get('explanation', 'Unknown'),
            )
            vulnerabilities_gpt.append(vulnerability_gpt)
        
        return vulnerabilities_gpt

# ==================== Presentation Layer : Streamlit 화면 구성 코드!!! ====================

class StreamlitReportRenderer:
    """Streamlit 보고서 렌더링"""
    
    @staticmethod
    def render_security_score_section(security_score: SecurityScore):
        st.markdown("""
            <style>
            .score-card {
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 10px rgba(0,0,0,0.05);
                padding: 20px;
                margin-bottom: 20px;
            }
            .score-title {
                font-size: 24px;
                font-weight: 600;
                color: #FFFFFF;
                margin-bottom: 10px;
            }
            .score-highlight {
                font-size: 32px;
                font-weight: 700;
                color: #2563eb;
            }
            .deployment-status {
                font-size: 18px;
                font-weight: 500;
                margin-top: 10px;
            }
            </style>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns([1, 2])

        with col1:
            with st.container():
                st.markdown('<div class="score-title">보안 점수</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="score-highlight">{security_score.total_score} / 100</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
                st.markdown('<div class="score-title">배포 권장 여부</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
                status = security_score.deployment_status
                if "권장" in status:
                    st.success(f"✅ {status}")
                elif "주의" in status:
                    st.warning(f"⚠️ {status}")
                elif "금지" in status:
                    st.error(f"⛔ {status}")
                    
                    

        with col2:
            with st.container():
                filtered_impact_counts = {
                    k: v for k, v in security_score.impact_counts.items() if v > 0
                }

                if filtered_impact_counts:
                    impact_keys = list(filtered_impact_counts.keys())
                    impact_values = list(filtered_impact_counts.values())
                    impact_descriptions = {
                            "High": "심각한 위험으로 빠른 조치가 반드시 필요합니다.",
                            "Medium": "중간 정도 위험이므로 점검해야 합니다.",
                            "Low": "위험도는 낮지만, 상황에 따라 확인해 두는 것이 좋습니다.",
                            "Informational": "보안에 참고할 만한 정보성 내용입니다.",
                            "Optimization": "성능을 높이기 위한 개선 권고 사항입니다."
                        }
                    hover_texts = [impact_descriptions.get(k, "") for k in impact_keys]

                    fig = px.pie(
                        names=impact_keys,
                        values=impact_values,
                        title="취약점 Impact 비율",
                        color=impact_keys,
                        color_discrete_map={
                            "High": "#ef4444",
                            "Medium": "#f59e0b",
                            "Low": "#3b82f6",
                            "Informational": "#10b981",
                            "Optimization": "#a78bfa"
                        }
                    )

                    fig.update_traces(
                        textinfo='label+percent',
                        textfont_size=14,
                        pull=[0.05] * len(impact_keys),
                        customdata=[[desc] for desc in hover_texts],
                        domain=dict(x=[0.25, 0.75], y=[0.1, 0.9]),
                        hovertemplate="<b>%{label}</b><br>%{percent}<br>%{customdata[0]}<extra></extra>"
                    )

                    fig.update_layout(
                        margin=dict(t=50, b=20, l=20, r=20),
                        title=dict(
                            text="취약점 비율",
                            font=dict(size=24),
                            x=0.5,
                            xanchor='center'
                        ),
                        font=dict(size=12),
                        legend=dict(
                            font=dict(size=12),
                            x=0.8,
                            y=0.5,
                            bgcolor='rgba(0,0,0,0)',
                            bordercolor='rgba(0,0,0,0)'
                        )
                    )

                    st.plotly_chart(
                        fig,
                        use_container_width=True,
                        config={
                            "displaylogo": False,
                            "modeBarButtonsToRemove": ["toImage"]
                        }
                    )
                else:
                    st.info("❗ 표시할 취약점 Impact 데이터가 없습니다.")
                st.markdown('</div>', unsafe_allow_html=True)


    @staticmethod
    def render_summary_section(summary: ReportSummary):
        st.markdown("### 보고서 요약")
        st.markdown(
                    f"""
                    <div style="
                        background-color: rgba(0, 51, 102, 0.8);
                        font-size: 19px;
                        border-radius: 20px;
                        padding: 15px;
                        color: #d5efff;
                        ">
                        {summary.summary_contents}
                    </div>
                    """,
                    unsafe_allow_html=True
                )


    
    @staticmethod
    def render_vulnerabilities_section(vulnerability_details: list):
        st.header("발견된 취약점 상세")
        
        if not vulnerability_details:
            st.success("발견된 취약점이 없습니다.")
            return
        
        # Impact 설명 추가
        impact_descriptions = {
            "High": "심각한 위험으로 빠른 조치가 반드시 필요합니다.",
            "Medium": "중간 정도 위험이므로 점검해야 합니다.",
            "Low": "위험도는 낮지만, 상황에 따라 확인해 두는 것이 좋습니다.",
            "Informational": "보안에 참고할 만한 정보성 내용입니다.",
            "Optimization": "성능을 높이기 위한 개선 권고 사항입니다."
        }
        impact_colors = {
            "High": "#ef4444",
            "Medium": "#f59e0b",
            "Low": "#3b82f6",
            "Informational": "#10b981",
            "Optimization": "#a78bfa"
        }
        impact_groups = {}
        for detail in vulnerability_details:
            impact = detail.vulnerability.impact
            impact_groups.setdefault(impact, []).append(detail)
        
        tab_names = [f"{impact} ({len(details)}개)" for impact, details in impact_groups.items()]
        tabs = st.tabs(tab_names)
        
        for tab, (impact, details) in zip(tabs, impact_groups.items()):
            with tab:
                description = impact_descriptions.get(impact, "")
                color = impact_colors.get(impact, "#cccccc")  # fallback color

                st.markdown(
                f"""
                <div style="
                    background-color: {color}33;
                    border-left: 8px solid {color};
                    padding: 20px 24px;
                    border-radius: 10px;
                    margin-bottom: 24px;
                    width: 95%;
                    line-height: 1.6;
                    font-weight: 600;
                    font-size: 1.1rem;
                    color: #FFFFFF;
                ">
                    {description}
                </div>
                """,
                unsafe_allow_html=True
                )
                for detail in details:
                    StreamlitReportRenderer._render_vulnerability_card(detail)


    IMPACT_COLORS = {
        "High": "#ef4444",
        "Medium": "#f59e0b",
        "Low": "#3b82f6",
        "Informational": "#10b981",
        "Optimization": "#a78bfa"
    }


    @staticmethod
    def _render_vulnerability_card(detail):
        vuln = detail.vulnerability
        color = StreamlitReportRenderer.IMPACT_COLORS.get(vuln.impact, "#999999")
        


        st.markdown(f"### <span style='color:{color}'>{vuln.check}</span>", unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Impact:** <span style='color:{color}; font-weight:600'>{vuln.impact}</span>", unsafe_allow_html=True)
        with col2:
            st.markdown(f"**Confidence:** {vuln.confidence}")

        if detail.code_locations:
            with st.expander("발견된 위치", expanded=True):
                for location in detail.code_locations:
                    st.code(location)

        st.markdown("**취약점 설명:**")
        st.write(detail.technical_explanation)

        st.markdown("**맞춤형 설명:**")
        st.write(detail.personalized_explanation)

        if detail.reference_links:
            st.markdown("**참조 링크:**")
            for link in detail.reference_links:
                st.markdown(f"- 🔗 [{link}]({link})")

        st.markdown("</div>", unsafe_allow_html=True)

# ==================== Application Layer ====================

class ReportService:
    
    def __init__(self):
        self.data_parser = SlitherDataParser()
        self.gpt_data_parser = GPTDataParser()
        self.score_calculator = SecurityScoreCalculator()
        self.prioritizer = VulnerabilityPrioritizer()
        self.detail_processor = VulnerabilityDetailProcessor()
        self.renderer = StreamlitReportRenderer()
    
    def generate_report(self, json_data: Dict, user_prompt: str, summary_gpt: str, detectors_gpt: Dict):
        
        # 데이터 파싱
        vulnerabilities, raw_detectors = self.data_parser.parse(json_data)
        
        # 보안 점수 계산
        security_score = self.score_calculator.calculate(vulnerabilities)
        summary = ReportSummary(summary_gpt)
        
        # 취약점 우선순위 정렬 #필요 없음 # 그리고 정렬할 거면 vulnerabilities 말고 raw랑 gpt 결과도 같이 해야.
        # sorted_vulnerabilities = self.prioritizer.sort_by_priority(vulnerabilities)

        # GPT 결과 파싱
        vulnerabilities_gpt = self.gpt_data_parser.parse(detectors_gpt)
        
        # 취약점 상세 정보 처리
        vulnerability_details = []
        # for vuln, raw in zip(sorted_vulnerabilities, raw_detectors):
        for vuln, raw, gpt in zip(vulnerabilities, raw_detectors, vulnerabilities_gpt):
            assert vuln.id == gpt.id # FIXME 디버깅 끝나면 삭제
            detail = self.detail_processor.process(vuln, raw, gpt)
            vulnerability_details.append(detail)
        
        # Streamlit 렌더링
        #  FIXME 추후 빠질지도
        self._render_complete_report(security_score, summary, vulnerability_details)


        
    def _render_complete_report(self, security_score: SecurityScore, summary: ReportSummary, vulnerability_details: List[VulnerabilityDetail]):
        st.set_page_config(
            page_title="스마트 컨트랙트 보안 보고서",
            layout="wide",
            initial_sidebar_state="expanded"
        )

        st.markdown("""
            <style>
            .main {
                background-color: #f4f4f4;
                padding: 20px;
                border-radius: 10px;
            }
            .report-title {
                font-size: 32px;
                font-weight: bold;
                color: #2c3e50;
            }
            </style>
        """, unsafe_allow_html=True)

        st.title("[SmartSecure] 스마트 컨트랙트 보안 취약점 분석 리포트")
        st.markdown("---")
        
        self.renderer.render_security_score_section(security_score)
        st.markdown("---")
        
        self.renderer.render_summary_section(summary)
        st.markdown("---")
        
        self.renderer.render_vulnerabilities_section(vulnerability_details)

# ==================== Main Entry Point ====================

def load_json_file(file_path: str) -> Optional[Dict]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        st.error(f"JSON 파일 로드 실패: {e}")
        return None

def start_streamlit_server():
    """Streamlit 서버 시작"""
    try:
        subprocess.run(["streamlit", "run", "report.py", "--server.headless", "true", "--server.port", "8501"], 
                      check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Streamlit 서버 시작 실패: {e}")

def open_browser_delayed():
    time.sleep(3)
    try:
        webbrowser.open("http://localhost:8501")
        print("브라우저에서 보고서를 열었습니다: http://localhost:8501")
    except Exception as e:
        print(f"브라우저 열기 실패: {e}")

def process_analysis_result(response_data: Dict[str, Any]):
    
    print("=== 분석 결과 처리 시작 ===")
    print(f"파일명: {response_data['filename']}")
    print(f"프롬프트: {response_data['prompt']}")
    print(f"결과 파일: {response_data['result_json_file']}")
    
    json_data = load_json_file(response_data['result_json_file'])
    
    # Slither 탐지 에러 대비
    if json_data is None:
        return
    if json_data.get('success') is not True:
        return
    if json_data.get('error') is not None:
        print(json_data['error'])
        return
    
    # OpenAI API 연결
    openai_client = OpenAIClient()
    openai_response = openai_client.prompt_analysis(json_data, response_data['prompt'])
    
    # OpenAI API 호출 에러 대비
    if openai_response is None:
        return
    
    # 보고서 데이터를 임시 파일에 저장 (Streamlit에서 읽기 위해)
    report_data = {
        'json_data': json_data,
        'user_prompt': response_data['prompt'],
        'filename': response_data['filename'],
        'summary_gpt': openai_response['summary'],
        'detectors_gpt': openai_response['detectors'],
    }
    
    with open('temp_report_data.json', 'w', encoding='utf-8') as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    # Streamlit 서버가 실행 중 확인
    try:
        import requests # type: ignore
        response = requests.get("http://localhost:8501", timeout=2)
        print("Streamlit 서버가 이미 실행 중입니다.")
        threading.Thread(target=open_browser_delayed).start()
    except:
        print("Streamlit 서버를 시작합니다...")
        threading.Thread(target=start_streamlit_server, daemon=True).start()
        threading.Thread(target=open_browser_delayed).start()
    
    print("=== 분석 결과 처리 완료 ===")


# Stremalit 실행을 위해서 (새고 등)
if __name__ == "__main__":
    temp_file = Path('temp_report_data.json')
    
    if temp_file.exists():
        try:
            with open(temp_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            report_service = ReportService()
            report_service.generate_report(
                report_data['json_data'], 
                report_data['user_prompt'],
                report_data['summary_gpt'],
                report_data['detectors_gpt']
            )
            
        except Exception as e:
            st.error(f"보고서 데이터 로드 실패: {e}")
    else:
        st.info("[Smart Secure] Smart Contract 보안 취약점 분석 Report")
        st.write("분석을 실행하면 보고서가 여기에 표시됩니다.")