from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from pathlib import Path
import subprocess
import json

app = FastAPI()

UPLOAD_DIR = Path("uploaded_contracts")
UPLOAD_DIR.mkdir(exist_ok=True)

RESULT_DIR = Path("slither_results")
RESULT_DIR.mkdir(exist_ok=True)

def run_slither_analysis(sol_file_path: Path) -> dict:
    solc_path = "D:/solc/solc-0.4.25.exe"
    report_path = RESULT_DIR / f"{sol_file_path.stem}.json"

    cmd = (
    f'slither --solc "{solc_path}" "{sol_file_path}" --json "{report_path}.json"'
    )
    result = subprocess.run(cmd, shell=True)

    if result.returncode != 0:
        raise RuntimeError(f"Slither 분석 실패, 리턴코드: {result.returncode}")

    if not report_path.exists():
        raise FileNotFoundError("Slither 결과 파일이 생성되지 않았습니다.")

    return report_path


@app.post("/upload/text")
async def upload_contract_text(contract_name: str = Form(...), code: str = Form(...)):
    try:
        unquoted_code = code.strip('"')
        file_path = UPLOAD_DIR / f"{contract_name}.sol"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(unquoted_code)
        
        print(f"스마트 컨트랙트 저장 경로: {file_path}")

        analysis_result = run_slither_analysis(file_path)
        return {
            "message": "텍스트로 업로드된 스마트 컨트랙트 저장 및 Slither 분석 성공",
            "filename": file_path.name,
            "result_json_file": str(RESULT_DIR / f"{contract_name}.json"),
            "analysis_result": analysis_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload/file")
async def upload_contract_file(file: UploadFile = File(...)):
    if not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Solidity (.sol) 파일만 허용됩니다.")
    
    file_path = UPLOAD_DIR / file.filename
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    try:
        analysis_result = run_slither_analysis(file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Slither 분석 중 오류 발생: {str(e)}")

    return {
        "message": "파일 업로드 및 Slither 분석 성공",
        "filename": file.filename,
        "result_json_file": str(RESULT_DIR / f"{Path(file.filename).stem}.json"),
        "analysis_result": analysis_result
    }