# CTF 풀이 도우미

문제 설명과 첨부 파일을 로컬 Ollama 또는 OpenAI Responses API로 분석하는 로컬 웹 도구입니다. 파일 분석, 디코딩, 아카이브 조회, ELF 정적 분석과 사용자가 지정한 CTF 서버에 대한 제한된 HTTP/TCP 확인을 지원합니다. 2026 ACDC 프로필에서는 AI 보안 영역과 CTF/KotH 방식을 선택하고, 조각·미끼 문자열을 따로 표시하며, 저장된 실행에서 이어 분석할 수 있습니다. 출력되는 플래그는 근거가 붙은 **후보**이며 공식 채점 결과가 아닙니다.

웹 문제에서 소스가 접두사 오라클이나 작은 정수 범위를 보여주면 모델은 `http_prefix_oracle`·`http_integer_oracle`로 지정된 문제 서버를 자동 탐색할 수 있습니다. 두 도구는 합계 300회 요청과 도구 호출당 5분 제한을 공유하며, 응답에서 발견한 플래그 후보를 기록합니다.

파일 또는 **폴더 선택**과 폴더 드래그 앤 드롭을 지원합니다. 하위 파일의 상대 경로를 보존해 모델이 `list_files`, `read_file`, `search_files`로 조회할 수 있습니다. 첨부 한도는 최대 **256개, 파일당 32 MiB, 합계 96 MiB**입니다.

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

분석 중 문제 서버에 보낸 HTTP/TCP 요청은 각 실행의 `requests.jsonl`과 `result.json`에 기록됩니다. 요청 헤더의 인증 값과 일반적인 비밀번호·토큰 필드는 기록 전에 가리지만, 자유 형식 입력에 든 모든 비밀이 자동으로 제거되는 것은 아니므로 실행 기록을 공개하기 전에 확인하세요.
