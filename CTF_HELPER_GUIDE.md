# CTF 풀이 도우미 가이드

문제 설명과 코드/첨부 파일을 입력하면 로컬 Ollama(Qwen3 8B) 또는 OpenAI Responses API(GPT-5.4 Mini / GPT-5.4)가 분석 근거와 flag 후보를 제시합니다. 웹·시스템·리버싱·암호·포렌식·AI 보안·클라우드/Web3 분야를 선택할 수 있으며, 분야별 맞춤 지침과 도구가 자동으로 적용됩니다.

---

## 1. 지원 모델 및 비용 관리

| 모델 | 구동 환경 | 특징 및 용도 | 비용 / 과금 한도 |
|---|---|---|---|
| **로컬 Qwen3 8B** (`qwen3:8b`) | 로컬 Ollama | 로컬 GPU/CPU 구동 | OpenAI API 사용료 없음 |
| **GPT-5.4 Mini** (`gpt-5.4-mini`) | OpenAI Responses API | 빠르고 경제적인 상용 모델, 복합 인코딩 추론 | 입력 \$0.75 / 캐시 \$0.075 / 출력 \$4.50 (M당) |
| **GPT-5.4** (`gpt-5.4`) | OpenAI Responses API | 심층 추론 및 높은 분석력 | 입력 \$2.50 / 캐시 \$0.25 / 출력 \$15.00 (M당) |

### 안전한 키 관리 및 예산 보호 (Budget Ledger)
- **API 키**: OpenAI를 사용하려면 서버 프로세스의 `OPENAI_API_KEY` 환경 변수를 설정합니다. 키는 저장소에 기록하지 않고 브라우저에 반환하지 않습니다. 서버 주소를 입력한 로컬 모델 분석은 해당 CTF 서버에 네트워크 요청을 보낼 수 있습니다.
- **도구별 사용 한도**: 단일 실행당 **\$2.00**, 이 도구에서 누적 **\$30.00**를 목표 한도로 설정했습니다. 요청 전 예상 비용을 SQLite(`openai-usage.sqlite3`) 원장에 예약하고 한도 초과 요청을 차단합니다.
- **한도 표시**: 웹 화면 상단에는 이 도구 원장의 남은 한도만 표시됩니다. **OpenAI 계정의 충전 잔액을 조회하거나 보증하지 않습니다.** 계정의 실제 잔액과 사용량은 OpenAI 플랫폼의 결제·사용량 페이지에서 확인하세요.
- **데이터 전송**: GPT 모델 선택 시 문제 설명, 첨부 파일의 텍스트 미리보기, 분석 중 모델이 읽은 파일 내용과 도구 결과가 OpenAI API로 전송됩니다. 로컬 Qwen 선택 시 이 데이터는 OpenAI로 전송되지 않습니다.

---

## 2. 웹 화면 사용법 (권장)

저장소를 복제한 폴더에서 Python 3.11 이상과 Ollama를 준비하세요. Windows PowerShell 예시:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
ollama pull qwen3:8b
.\.venv\Scripts\python.exe scripts\ctf_helper.py serve
```

Ollama 서비스가 자동 시작되지 않으면 다른 터미널에서 `ollama serve`를 실행하세요. OpenAI를 사용하려면 서버 시작 전에 같은 터미널에서 `$env:OPENAI_API_KEY = '자신의_API_키'`를 설정하세요. macOS/Linux에서는 가상 환경을 `source .venv/bin/activate`로 활성화한 후 `python -m pip install -r requirements.txt`, `ollama pull qwen3:8b`, `python scripts/ctf_helper.py serve`를 실행할 수 있습니다.

브라우저에서 `http://127.0.0.1:8765`를 엽니다:
1. **분석 모델 선택**: 드롭다운에서 `로컬 Qwen3 8B`, `OpenAI GPT-5.4 Mini`, 또는 `OpenAI GPT-5.4`를 선택합니다.
2. **CTF 분야**: 웹해킹·시스템해킹·리버싱·암호학·포렌식·AI 보안·클라우드/Web3 중 선택합니다. 선택한 분야에 맞는 힌트와 도구 우선순위가 자동 적용됩니다.
   - **대회 프로필**: `2026 ACDC`를 선택하면 `AI for Security`, `Security for AI`, `AI Platform Security` 중 하나를 지정하거나 자동 판별할 수 있습니다. `CTF`와 `KotH` 방식은 분석 지침을 달리합니다. 대회 세부 규칙이 공개되지 않아 KotH 점수 계산이나 자동 점령 기능은 제공하지 않습니다.
3. **문제 설명 입력**: 문제 제목, 설명, flag 형식 등을 입력합니다. 입력창에 문제 서버 주소(`http://...`, `nc host port` 등)가 있으면 문제 서버 칸에 자동 입력됩니다.
4. **파일·폴더 첨부**: `파일 선택`, `폴더 선택` 버튼 또는 파일·폴더 드래그 앤 드롭을 사용합니다 (최대 256개, 파일당 32 MiB, 총 96 MiB). 폴더 내부의 상대 경로가 목록에 표시되고 분석 도구에서 그대로 조회됩니다. 빈 폴더와 심볼릭 링크는 첨부하지 않습니다. 큰 폴더는 브라우저에서 읽고 전송하는 데 시간이 걸릴 수 있습니다.
   - ELF 파일은 보호 기법·함수 심볼·선택한 함수의 디스어셈블리까지 분석할 수 있습니다.
   - 사용자 입력이 명시된 TCP CTF 서버에만 제한된 메뉴 입력을 보내 결과를 확인할 수 있습니다. 이 도구는 실행당 새 연결을 만들고, 최대 8회·호출당 12단계·총 4 KiB 입력으로 제한됩니다.
5. **문제 서버 연결 (선택)**:
   - 지원 포맷: `http(s)://host:port/`, `nc host port`, `ncat host port`, `telnet host port`, `socat TCP:host:port`, `ssh -p port host`, `host:port`
   - TCP 연결 후 데이터가 없으면 HTTP GET 프로브를 자동 전송하여 웹 서비스 여부를 스스로 감지합니다.
6. **단축키 및 편의 기능**:
   - `Ctrl + Enter`: 문제 설명이나 코드 입력창에서 즉시 분석 시작
   - `초기화`: 한 번의 클릭으로 모든 필드 및 파일 목록 리셋
   - `1클릭 Flag 복사`: 추출된 각 flag 옆의 `복사` 버튼으로 클립보드에 즉시 복사
   - `전체 결과 복사`: 최종 분석 보고서 및 flag 후보 전체를 클립보드로 복사
   - `이어서 분석`: 완료된 결과 또는 최근 기록을 연 뒤 새 서버 응답, 실패한 시도, 추가 단서를 입력합니다. 새 실행 ID를 만들고 이전 문제 설명, 파일, 후보 분류, 최근 분석 단계를 가져옵니다.
   - `문제 서버 요청 기록`: 실행 중 사용한 HTTP/TCP 요청 경로, 입력 미리보기, 응답을 확인합니다. 요청 본문의 해시도 결과 JSON에 저장됩니다.

---

## 3. 내장 분석 도구 목록

도우미는 모델이 호출할 수 있는 격리된 안전 도구 모음을 제공합니다:

| 도구 이름 | 기능 및 설명 |
|---|---|
| `list_files` / `read_file` | 하위 폴더를 포함한 첨부 파일 목록 조회 및 상대 경로로 텍스트/16진수 미리보기 |
| `search_files` | 하위 폴더를 포함한 텍스트 파일 내 키워드 대소문자 무시 검색 |
| `decode_text` | Base64, Base32, Base85, Hex(공백/접두사 허용), URL 디코드, HTML 엔티티, 8비트 바이너리 ASCII, ROT13 및 Caesar 전단(Flag 매칭 자동 감지), 문자열 역순 변환 |
| `analyze_binary` | 파일 실행 없이 시그니처(ELF, PE, Mach-O, PCAP/PCAPNG, GZIP, BZIP2, 7z, XZ, SQLite, PDF, PNG/JPEG), 엔트로피, 인쇄 가능 문자열(ASCII 및 UTF-16LE 광범위 추출), ELF PIE 보호 여부 분석 및 flag 자동 탐색 |
| `inspect_archive` | 디스크 추출 없이 ZIP 및 TAR 아카이브 파일 목록/압축률 확인 및 내부 소형 텍스트 파일 flag 자동 추출 |
| `read_archive_entry` | ZIP/TAR 아카이브 내부의 특정 소스 코드/설정 파일을 메모리에서 안전하게 직접 읽기 |
| `hash_calc` | 입력 텍스트 또는 첨부 파일의 MD5, SHA1, SHA256 암호학적 해시 계산 |
| `http_get` / `http_post` | 명시된 CTF 원본 서버로의 GET/POST 요청 (최대 8회, 선택적 헤더, 응답 헤더·쿠키·에러 본문 보존 및 flag 자동 탐지) |
| `run_python` | 사용자가 켜고 Docker 및 `python:3.11-alpine` 이미지가 설치된 경우에만 제한된 컨테이너에서 Python 계산 |

---

## 4. 명령줄(CLI) 사용법

PowerShell 터미널에서 직접 문제를 분석할 수 있습니다.

### 로컬 Qwen3 8B로 풀이
```powershell
.\.venv\Scripts\python.exe scripts\ctf_helper.py solve --problem "이 문자열을 디코딩하세요" --file .\문제\cipher.txt
```

### OpenAI GPT-5.4 Mini로 풀이
```powershell
.\.venv\Scripts\python.exe scripts\ctf_helper.py solve --model gpt-5.4-mini --problem "이 문자열을 디코딩하세요" --file .\문제\cipher.txt
```

### OpenAI GPT-5.4로 풀이
```powershell
.\.venv\Scripts\python.exe scripts\ctf_helper.py solve --model gpt-5.4 --problem-file .\문제\설명.txt --file .\문제\chall.py
```

### 주요 CLI 옵션
- `--problem "문자열"` 또는 `--problem-file .\경로.txt`: 문제 설명 지정
- `--file .\경로`: 첨부 파일 (여러 개일 경우 `--file`을 반복 사용)
- `--file .\문제폴더`: 폴더 안 파일을 재귀적으로 첨부하고 폴더 이름부터 상대 경로 보존
- `--model`: `qwen3:8b`(기본값), `gpt-5.4-mini`, `gpt-5.4`. 기본 Ollama 태그는 `CTF_HELPER_OLLAMA_MODEL`로 변경 가능
- `--tcp-endpoint ctf.example:1337` 또는 `http://ctf.example:8080/`: 명시한 CTF 문제 서버에 연결
- `--category web|pwn|reversing|crypto|forensics|ai-security|cloud-web3`: CTF 분야 지정
- `--profile acdc-2026 --track auto|ai-for-security|security-for-ai|ai-platform-security --challenge-mode ctf|koth`: ACDC 분석 지침 지정
- `--flag-regex '정규식'`: 커스텀 flag 포맷 (기본값: `(?:ACDC|FLAG|CTF|DH|APS)\{[^}\r\n]{1,160}\}`)
- `--max-steps <정수>`: 최대 도구 호출/추론 단계 (로컬 Ollama 8B: 기본값 25, 최대 50 / OpenAI: 기본값 8, 최대 15)
- `--docker-python`: 격리된 오프라인 컨테이너에서 Python 계산 허용
- `continue <실행 ID> --note "새 단서" [--model gpt-5.4]`: 저장된 문제와 파일을 사용해 새 실행에서 이어 분석

> **로컬 Ollama 분석**: 기본 25단계와 16,384 토큰 컨텍스트 옵션을 사용합니다. 대화가 길어지면 요약해 계속 분석하지만, 요약 과정에서 단서가 손실될 수 있으며 정확한 플래그 도출을 보장하지 않습니다.

---

## 5. 결과 확인 및 주의사항

- **후보 flag 근거 구분**: 화면 및 결과 JSON에 **입력에서 관찰됨**, **디코딩 결과**, **바이너리 문자열**, **아카이브 내부**, **격리 Python 출력**, **문제 웹 응답**, **문제 서버**, **모델 후보**가 출처와 함께 보존됩니다. `fragment`/`decoy`로 판단한 문자열은 `flag_observations`에 남기고 `flag_candidates`에서는 제외합니다. 이 분류는 휴리스틱이므로 틀릴 수 있으며, 공식 정답 판정은 아닙니다.
- **공식 판정 확인**: 추출된 flag는 후보이며 실제 정답 여부는 대회 채점 플랫폼에서 확인해야 합니다.
- **서버 전용 flag**: 코드가 서버의 `/flag`를 읽는 경우, 첨부된 코드와 바이너리만으로 실제 값은 알 수 없습니다. 문제 VM을 켜고 최신 `host:port`를 입력해야 합니다. `DH{...}` 같은 형식 예시는 후보에서 자동 제외됩니다.
- **결과 저장소**: 모든 실행 결과와 첨부 사본은 `results\ctf_helper\<실행 ID>\`에 `result.json`으로 저장됩니다. 문제 서버 요청은 같은 폴더의 `requests.jsonl`에도 남습니다. 인증 헤더와 일반적인 토큰 필드는 가리지만 공개 전 기록을 확인하세요.
- **대회 규정 준수**: 대회 주최 측의 AI 도구 사용 규정을 반드시 확인하고 준수하세요.

---

## 6. 테스트 검증

```powershell
.\.venv\Scripts\python.exe tests\test_ctf_helper.py
```
