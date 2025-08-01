from fastapi import FastAPI, UploadFile, File, Form, HTTPException # type: ignore
from pathlib import Path
import subprocess
import json
from report import process_analysis_result
from dotenv import load_dotenv
import os 
app = FastAPI()

load_dotenv()

UPLOAD_DIR = Path("uploaded_contracts")
UPLOAD_DIR.mkdir(exist_ok=True)

RESULT_DIR = Path("results")
RESULT_DIR.mkdir(exist_ok=True)

def run_slither_analysis(sol_file_path: Path) -> dict:
    solc_path = os.getenv('SOLC_PATH')
    # SOLC_PATH = "C:/program_Wonjoo/solidity-windows/solc_0.4.25/solc.exe
    # SOLC_PATH = "/opt/homebrew/bin/solc"
    # SOLC_PATH = "D:/solc/solc-0.4.25.exe"
    report_path = RESULT_DIR / "result.json"

    if report_path.exists():
        report_path.unlink()

    cmd = (
    f'slither --solc "{solc_path}" "{sol_file_path}" --json "{report_path}"'
    )
    result = subprocess.run(cmd, shell=True)

    # if result.returncode != 0:
    #     raise RuntimeError(f"Slither 분석 실패, 리턴코드: {result.returncode}")

    if not report_path.exists():
        raise FileNotFoundError("Slither 결과 파일이 생성되지 않았습니다.")

    return report_path

@app.post("/upload/file")
async def upload_contract_file(
    file: UploadFile = File(...),
    prompt: str = Form(...)
):
    if not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Solidity (.sol) 파일만 허용됩니다.")
    
    file_path = UPLOAD_DIR / file.filename
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    try:
        analysis_result_path = run_slither_analysis(file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Slither 분석 중 오류 발생: {str(e)}")


    response_data = {
        "message": "파일 업로드 및 Slither 분석 성공",
        "filename": file.filename,
        "prompt": prompt,
        "result_json_file": str(analysis_result_path)
    }
    
    process_analysis_result(response_data)
    
    return response_data