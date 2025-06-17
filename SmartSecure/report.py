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
        
        st.metric("보안 점수", f"{security_score.total_score}/100")
        st.write(security_score.deployment_status)
        
    
    @staticmethod
    def render_summary_section(summary: ReportSummary):
        st.header("보고서 요약")
        st.markdown(summary.summary_contents)
    
    @staticmethod
    def render_vulnerabilities_section(vulnerability_details: List[VulnerabilityDetail]):
        st.header("발견된 취약점 상세")
        
        if not vulnerability_details:
            st.success("발견된 취약점이 없습니다.")
            return
        
        # Impact별로 그룹화
        impact_groups = {}
        for detail in vulnerability_details:
            impact = detail.vulnerability.impact
            if impact not in impact_groups:
                impact_groups[impact] = []
            impact_groups[impact].append(detail)
        
        # 탭 생성
        tab_names = [f"{impact} ({len(details)}개)" for impact, details in impact_groups.items()]
        tabs = st.tabs(tab_names)
        
        for tab, (impact, details) in zip(tabs, impact_groups.items()):
            with tab:
                for detail in details:
                    StreamlitReportRenderer._render_vulnerability_card(detail)
    
    @staticmethod
    def _render_vulnerability_card(detail: VulnerabilityDetail):
       
        vuln = detail.vulnerability
        
        with st.container():
            st.markdown(f"### {vuln.check}")
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Impact:** {vuln.impact}")
            with col2:
                st.markdown(f"**Confidence:** {vuln.confidence}")
            
            # TODO 업로드 된 코드 보이게 혹은 아예 해당 부분 삭제
            if detail.code_locations:
                st.markdown("**발견된 위치:**")
                for location in detail.code_locations:
                    st.code(location)
            
            st.markdown("**취약점 설명:**")
            st.write(detail.technical_explanation)
            
            st.markdown("**맞춤형 설명:**")
            st.write(detail.personalized_explanation)
            
            # 참조 링크
            st.markdown("**참조 링크:**")
            for link in detail.reference_links:
                st.markdown(f"- [{link}]({link})")
            
            st.markdown("---")

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
        st.set_page_config(page_title="스마트 컨트랙트 보안 취약점 분석 보고서", layout="wide")

        st.title("[Smart Secure] Smart Contract 보안 취약점 분석 Report ")
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