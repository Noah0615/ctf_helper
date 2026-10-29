# CTF 풀이 도우미

문제 설명과 첨부 파일을 로컬 Ollama 또는 OpenAI Responses API로 분석하는 로컬 웹 도구입니다. 파일 분석, 디코딩, 아카이브 조회, ELF 정적 분석과 사용자가 지정한 CTF 서버에 대한 제한된 HTTP/TCP 확인을 지원합니다. 출력되는 플래그는 근거가 붙은 **후보**이며 공식 채점 결과가 아닙니다.

## 빠른 시작

Python 3.11 이상과 [Ollama](https://ollama.com/download)를 설치한 뒤 저장소 루트에서 실행하세요.

```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
ollama pull qwen3:8b
python scripts/ctf_helper.py serve
```

브라우저에서 <http://127.0.0.1:8765/>를 엽니다. Ollama가 자동 실행되지 않는 환경에서는 별도 터미널에서 `ollama serve`를 실행하세요. 다른 Ollama 태그를 쓰려면 서버를 시작하기 전에 `CTF_HELPER_OLLAMA_MODEL` 환경 변수를 설정하세요.

OpenAI 모델은 선택 사항입니다. 사용하려면 **서버를 실행하는 터미널에서** `OPENAI_API_KEY`를 설정하세요. 키를 소스 파일이나 저장소에 넣지 마세요.

```powershell
# Windows PowerShell 예시
$env:OPENAI_API_KEY = '여기에_자신의_API_키'
python scripts/ctf_helper.py serve
```

```bash
# macOS/Linux 예시
export OPENAI_API_KEY='여기에_자신의_API_키'
python scripts/ctf_helper.py serve
```

API 키를 설정하지 않아도 로컬 Ollama 모드는 사용할 수 있습니다. Python 의존성 설치와 Ollama 모델 다운로드는 각각 필요합니다. 선택적 Docker 계산 기능은 Docker와 로컬 `python:3.11-alpine` 이미지가 있을 때만 켜세요.

## 문서

- [사용 가이드](CTF_HELPER_GUIDE.md)
- [설계 및 구현 검증 보고서](CTF_HELPER_DESIGN_REPORT.md)

실행 결과와 업로드 파일 사본은 로컬 `results/ctf_helper/`에 저장됩니다. `.runtime/`의 사용량 원장과 함께 Git에서 제외됩니다. OpenAI 모드는 문제 설명과 도구가 읽은 파일 내용이 API로 전송될 수 있습니다. [OpenAI 공식 빠른 시작 문서](https://developers.openai.com/api/docs/quickstart)도 참고하세요.
