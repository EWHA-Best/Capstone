# EWHA-Best Repository
  
이 레포지토리는 2025 봄학기 캡스톤디자인과창업프로젝트 '스타트' 과목에서 4팀, 이데댕김의 비전문가도 쉽게 접근할 수 있는 스마트 컨트랙트 보안 취약점 자동 분석 웹서비스인 **"SmartSecure"** 구현을 목표로 한다.  


Slither 기반의 정적 분석 결과를 OpenAI GPT-4 API로 해석하여 비전문가 맞춤형 설명과 요약 리포트를 자동 생성하고, Streamlit을 활용해 직관적인 웹 UI로 시각화하여 제공한다.  

이를 통해 스마트 컨트랙트 보안 위험도를 신속히 파악하고 비전문가, 비개발자도 쉽게 이해할 수 있는 맞춤형 보안 리포트를 제공하는 데 목적이 있다.

---

# 프로젝트명: SmartSecure

SmartSecure는 비전문가를 위한 스마트 컨트랙트 보안 취약점 자동 분석 및 사용자 맞춤형 리포트 생성 웹서비스이다.  
Slither 기반 보안 검사 결과를 OpenAI GPT-4 API로 해석하여 비전문가도 이해하기 쉬운 설명과 요약을 생성하고, Streamlit UI로 시각화해 제공한다.

---

## 프로젝트 개요

- **목적**  
  - 스마트 컨트랙트 보안 취약점 자동 탐지 및 이해하기 쉬운 리포트 제공  
  - 개발자 및 스타트업 대표 등 비전문가도 보안 위험을 빠르게 인지할 수 있도록 지원  
  - 보안 취약점에 따른 위험도별 조치 우선순위 제시

- **주요 기능**  
  - Slither 도구를 통한 스마트 컨트랙트 취약점 정적 분석  
  - OpenAI GPT-4.1 API 연동으로 취약점 유형별 맞춤형 설명 및 요약 생성  
  - Streamlit 기반 대시보드에서 보안 점수, 취약점 분포, 상세 보고서 시각화  

---

## 프로젝트 구조 및 주요 파일

```

SmartSecure/
├── gpt.py                 # OpenAI GPT API 연동 및 취약점 분석 리포트 생성 로직
├── main.py                # 스마트 컨트랙트 업로드 및 Slither 실행 후 결과 처리 API
├── report.py              # Streamlit UI 구성, 분석 리포트 시각화
├── results/
│   ├── result.json        # Slither 분석 결과 JSON 파일
├── uploaded\_contracts/   # 분석 대상 스마트 컨트랙트 코드 파일
├── .gitignore
├── GroundRule.md          # 팀 그라운드룰
├── README.md              # 프로젝트 설명 문서
└── 프롬프트                # OpenAI API에 사용하는 프롬프트 예시 텍스트 파일

````

---

## 주요 코드 파일 상세 설명

### 1. gpt.py — OpenAI GPT API 연동

- `OpenAIClient` 클래스를 통해 OpenAI GPT-4.1 모델과 통신  
- Slither 분석 결과 JSON 데이터와 사용자의 서비스 목적을 입력받아, 비전문가도 쉽게 이해할 수 있도록 취약점 유형별 설명과 요약 리포트 생성  
- Prompt 내 비전문가 맞춤형 설명 가이드 포함  
- JSON 형태의 구조화된 리포트 결과를 반환  

---

### 2. report.py — Streamlit 기반 보안 Report UI

- 보안 점수 및 배포 권장 여부 시각화  
- Plotly Pie 차트로 취약점 위험도 분포 표현  
- 발견된 취약점 상세 목록을 Impact 별 탭으로 구분하여 표시  
- 각 취약점에 대해 코드 위치, 기술적 설명, 맞춤형 설명, 참조 링크를 제공  
- 직관적이고 깔끔한 디자인을 위한 CSS 스타일 및 HTML 마크업 사용

---

### 3. main.py — 스마트 컨트랙트 보안 분석 실행

- Slither를 이용한 스마트 컨트랙트 취약점 분석 자동화  
- 분석 결과를 `result.json`으로 저장 및 로드  
- gpt.py의 OpenAIClient를 호출해 사용자 맞춤형 리포트 생성  
- Streamlit을 통해 report.py UI를 실행하도록 연결  


## 사용 기술

* Solidity 스마트 컨트랙트
* Slither: 스마트 컨트랙트 정적 분석 도구
* OpenAI GPT API: 자연어 기반 취약점 설명 및 요약 생성
* Streamlit: 데이터 대시보드 및 UI 프레임워크
* Plotly: 데이터 시각화 (파이 차트 등)

---

## 팀원 소개

- 2176355 정혜교  
- 2176278 이원주  
- 2376329 황지은  
