from fastapi import FastAPI, UploadFile, File, Form, HTTPException # type: ignore
from pathlib import Path
import subprocess
import json

app = FastAPI()

UPLOAD_DIR = Path("uploaded_contracts")
UPLOAD_DIR.mkdir(exist_ok=True)

RESULT_DIR = Path("results")
RESULT_DIR.mkdir(exist_ok=True)

def run_slither_analysis(sol_file_path: Path) -> dict:
    solc_path = "/opt/homebrew/bin/solc"
    # solc_path = "D:/solc/solc-0.4.25.exe"
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

    return {
        "message": "파일 업로드 및 Slither 분석 성공",
        "filename": file.filename,
        "prompt": prompt,
        "result_json_file": str(analysis_result_path)
    }