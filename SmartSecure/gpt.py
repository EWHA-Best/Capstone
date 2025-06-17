from typing import Dict, List, Any, Optional
from dotenv import load_dotenv # type: ignore
import os
from openai import OpenAI # type: ignore

load_dotenv()

# ==================== OpenAI Integration ====================

class OpenAIClient:
    """OpenAI API 클라이언트"""
    
    def __init__(self):
        self.client = OpenAI(
            api_key=os.getenv('OPENAI_API_KEY')
        )
        self.system_prompt = """# 목적
                                주어진 보안 취약점 점검 결과, 사용자의 서비스 목적을 기반으로 어떤 유형의 보안 취약점이 발견됐는지 설명하는 레포트를 생성하는 것.


                                # 맥락1
                                주어진 보안 취약점 점검 결과를 json_obj라고 하면,
                                각 보안 취약점의 유형은 json_obj["results"]["detectors"][i]["check"]에서 확인할 수 있습니다.
                                각 유형에 대한 설명은 https://github.com/crytic/slither/wiki/Detector-Documentation 를 참고하세요.


                                # 맥락2
                                사용자는 블록체인 및 스마트 컨트랙트 분야를 잘 모르는 비전문가이며, 관련 기술을 서비스에 적용하고자 하는 의사결정자(스타트업의 대표 또는 소규모 프로젝트의 책임자)입니다.

                                따라서 레포트는 
                                1. 비전문가가 이해할 수 있을 만큼 쉬워야 합니다. 전문 용어 사용을 최대한 지양하세요.
                                2. 간결해야 합니다. 자세한 원리보다는 그래서 우리 서비스에 어떤 피해가 있을 것 같은지, 얼마나 치명적인 문제인지 위주로 설명하세요.


                                # 지시
                                레포트의 구성요소를 json object 형태로 작성하세요.
                                {
                                detectors: [
                                    {
                                        "id": "json_obj["results"]["detectors"][i]["id"] value 그대로",
                                        "type": "json_obj["results"]["detectors"][i]["check"] value 그대로",
                                        "title": "type을 한국어로 번역",
                                        "impact": "json_obj["results"]["detectors"][i]["impact"] value 그대로",
                                        "explanation": "이 유형의 취약점에 대한 비전문가도 이해하기 쉬운 설명. 간단해야 함. 사용자의 서비스 목적에 기반하여 어떤 피해가 발생할 수 있는지 예시 포함.",
                                    },
                                ],
                                summary: "5줄 이내의 요약"
                                }
                            """
    
    def prompt_analysis(self, json_data: Dict, user_prompt: str) -> str:
        try:
            print(f"=== OpenAI API 호출 시작 ===")
            
            response = self.client.chat.completions.create(
                model="gpt-4.1",
                messages=[
                    {
                        "role": "system", 
                        "content": self.system_prompt
                    },
                    {
                        "role": "user", 
                        "content": f"1. 보안 취약점 점검 결과:\n{str(json_data)}\n\n2. 사용자의 서비스 목적:\n{user_prompt}" # TODO json_data 가공해야 할지도
                    }
                ],
                max_tokens=2000,
                temperature=0.25
            )
            
            ai_response = response.choices[0].message.content
            
            print(f"=== OpenAI 응답 test ===\n{ai_response}") # FIXME 연결 확인 test 후 지우기
            
            print(f"=== OpenAI API 호출 완료 ===")
            
            return ai_response
            
        except Exception as e:
            error_msg = f"OpenAI API 호출 실패: {e}"
            print(error_msg)
            return error_msg