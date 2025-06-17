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
    
    def test_prompt_analysis(self, user_prompt: str) -> str:
        '''TEST용이야!!!!!! '''

        try:
            print(f"=== OpenAI API 테스트 시작 ===")
            print(f"전송할 프롬프트: {user_prompt}")
            
            response = self.client.chat.completions.create(
                model="gpt-4.1",
                messages=[
                    {
                        "role": "system", 
                        "content": "당신은 스마트 컨트랙트 보안 전문가입니다. 사용자의 요청을 분석하고 적절한 응답을 제공하세요."
                    },
                    {
                        "role": "user", 
                        "content": f"다음을 분석해주세요: {user_prompt}"
                    }
                ],
                max_tokens=500,
                temperature=0.25
            )
            
            ai_response = response.choices[0].message.content
            print(f"=== OpenAI 응답 ===")
            print(ai_response)
            print(f"=== OpenAI API 테스트 완료 ===")
            
            return ai_response
            
        except Exception as e:
            error_msg = f"OpenAI API 호출 실패: {e}"
            print(error_msg)
            return error_msg