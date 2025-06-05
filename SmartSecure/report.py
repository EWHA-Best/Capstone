import json
from pathlib import Path

def process_analysis_result(response_data):
    """FastAPI에서 받은 데이터를 처리하는 메인 함수"""
    print("=== 분석 결과 처리 시작 ===")
    print(f"파일명: {response_data['filename']}")
    print(f"프롬프트: {response_data['prompt']}")
    print(f"결과 파일: {response_data['result_json_file']}")
    
    # JSON 파일 로드
    json_data = load_json_file(response_data['result_json_file'])
    if json_data is None:
        return
    
    # 취약점 데이터 추출
    vulnerabilities = extract_vulnerabilities(json_data)
    print(f"발견된 취약점 수: {len(vulnerabilities)}")
    
    # 보안 점수 계산
    security_score = calculate_security_score(vulnerabilities)
    print(f"보안 점수: {security_score}")
    
    print("=== 분석 결과 처리 완료 ===")

def load_json_file(file_path):
    """JSON 파일 로드"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"JSON 파일 로드 실패: {e}")
        return None

def extract_vulnerabilities(json_data):
    """JSON에서 취약점 정보 추출"""
    vulnerabilities = []
    
    if 'results' in json_data and 'detectors' in json_data['results']:
        for detector in json_data['results']['detectors']:
            vuln = {
                'check': detector.get('check', 'Unknown'),
                'impact': detector.get('impact', 'Unknown'),
                'confidence': detector.get('confidence', 'Unknown'),
                'description': detector.get('description', 'No description')
            }
            vulnerabilities.append(vuln)
    
    return vulnerabilities

def calculate_security_score(vulnerabilities):
    """간단한 보안 점수 계산"""
    if not vulnerabilities:
        return 100
    
    total_deduction = 0
    for vuln in vulnerabilities:
        if vuln['impact'] == 'High':
            total_deduction += 10
        elif vuln['impact'] == 'Medium':
            total_deduction += 5
        elif vuln['impact'] == 'Low':
            total_deduction += 2
    
    return max(0, 100 - total_deduction)