# AirLLM Qwen3-14B 연결

AirLLM 4.0.0의 레이어 스트리밍으로 `Qwen/Qwen3-14B`를 실행하는 선택 기능입니다. Ollama와 별개인 CUDA Python 서버를 `127.0.0.1:8766`에 띄우며, CTF 도우미에서는 `AirLLM Qwen3-14B`를 선택합니다. 기존 도구·파일 분석·풀이 코드 저장·이어 분석 흐름을 사용합니다. 다른 모델로 자동 전환하지 않습니다.

## 이 PC의 조건과 한계

- RTX 5060 8GB에는 Blackwell을 지원하는 CUDA PyTorch가 필요합니다. 설치 스크립트는 CUDA 12.8 wheel을 사용하고 작은 행렬 연산으로 실제 CUDA 실행을 확인합니다.
- RAM 16GB의 여유를 위해 레이어 prefetch를 끕니다. 변환·추론 도중 메모리가 부족할 가능성은 남습니다.
- 원본은 약 30GB이고 변환된 레이어 사본도 생깁니다. 첫 준비 시 최소 70GiB 여유를 검사하며, 100GB 이상을 권장합니다. 다른 SSD는 `--cache` / PowerShell `-Cache`로 지정합니다.
- 레이어를 매번 디스크에서 읽으므로 매우 느릴 수 있습니다. 8B보다 빠르거나 항상 더 잘 푸는 것을 보장하지 않습니다. 이 GPU의 실제 초/토큰은 실행 후 `/health`의 `last_seconds / last_tokens`로 확인합니다.

## Windows 설치

기본 CTF 도우미 환경에 torch를 설치하지 않고 `.venv_airllm`을 따로 만듭니다. Python 3.11 이상이 필요합니다. 저장소 루트에서:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup_airllm.ps1
# python 명령이 없다면 실제 인터프리터 경로 지정:
# powershell -File scripts/setup_airllm.ps1 -Python C:\Python311\python.exe
powershell -ExecutionPolicy Bypass -File scripts/start_airllm.ps1
```

setup은 패키지·GPU만 점검하며 모델 가중치를 다운로드하지 않습니다. start는 처음에 모델을 다운로드·변환하고 다음부터 저장된 사본을 사용합니다. 원본 가중치 삭제는 기본으로 꺼져 있습니다. 전용 캐시의 원본을 변환 후 지우려면 `-DeleteOriginal`을 명시합니다. 작업이 끝날 때까지 캐시 파일을 직접 지우지 마세요.

```powershell
# 저장 경로 변경
powershell -File scripts/start_airllm.ps1 -Cache D:\models\ctf-airllm
# 출력 길이 변경 (늘릴수록 오래 걸림)
powershell -File scripts/start_airllm.ps1 -MaxNewTokens 1024
```

8B Ollama 모델이 GPU를 점유 중이면 사용 중인 분석을 마친 뒤 `ollama stop lab-qwen3-8b-16k:locked`로 내려 VRAM을 확보하세요. AirLLM 창을 닫으면 해당 서버도 종료됩니다.

## WSL2 / Linux

WSL2 Ubuntu와 GPU 드라이버가 이미 준비되어 있다면 Linux 파일 시스템의 작업 폴더에서 실행합니다. `/mnt/c` 대신 Linux SSD 경로를 캐시로 사용하면 Windows 파일 경유 비용을 피할 수 있습니다. 스크립트는 WSL 설치나 재부팅을 자동으로 수행하지 않습니다.

```bash
bash scripts/setup_airllm.sh
.venv_airllm/bin/python scripts/ctf_airllm_server.py --load --cache "$HOME/ctf-airllm-cache"
```

Windows의 CTF 도우미가 WSL localhost에 연결되지 않으면 Windows 기본 경로로 실행하거나 WSL의 localhost 전달 설정을 확인합니다. AirLLM 서버는 loopback에만 바인딩합니다.

## 도우미에서 사용

1. 서버를 실행하고 `http://127.0.0.1:8766/health`에서 `state`를 확인합니다. `loading`은 다운로드·레이어 변환 중이며 `error`에는 실패 이유가 있습니다. 준비 전에는 선택이 비활성화됩니다.
2. CTF 도우미 서버를 재시작하고 화면을 새로고침합니다. `모델 상태 새로고침`을 누르면 AirLLM의 준비 상태를 다시 읽습니다.
3. `AirLLM Qwen3-14B`와 Quick 모드로 시작합니다. 첫 출력 512토큰, 컨텍스트 8192토큰, 기본 분석 8단계입니다. Deep은 thinking이 출력 한도를 먼저 소모할 수 있습니다.
4. 진행 및 결과에는 사용한 모델 ID `airllm:qwen3-14b`와 기존 도구 호출 결과가 저장됩니다. 이어 분석에도 선택한 모델과 추론 모드가 전달됩니다.

```bash
python scripts/ctf_helper.py solve --problem '문제 설명' --model airllm:qwen3-14b --max-steps 8
```

Qwen 공식 채팅 템플릿에 도구 스키마와 이전 도구 결과를 넣고 `<tool_call>` JSON을 해석합니다. 허용된 도구 이름과 객체 인수만 실행하며 생성한 Python을 이 서버가 직접 실행하지 않습니다. 컨텍스트를 초과하거나 도구 호출이 잘리면 명시적으로 오류를 반환합니다. 입력을 조용히 잘라내지 않습니다.

생성 대기 시간 기본값은 요청당 4시간입니다. 환경 변수 `CTF_AIRLLM_TIMEOUT`(초)로 바꿀 수 있습니다. 일시적인 통신 오류 뒤 생성 요청을 자동 재전송하지 않습니다. `CTF_AIRLLM_URL`은 기본 `http://127.0.0.1:8766`이며 로컬 HTTP 주소만 허용합니다.

압축은 선택 실험입니다. `4bit` / `8bit`에는 별도 `bitsandbytes` 설치와 GPU 호환성 검증이 필요하며 기본 설치·시작에는 사용하지 않습니다.

## 근거

- [AirLLM 공식 Quickstart](https://github.com/lyogavin/airllm): Qwen3 계열 지원과 레이어 캐시 설명
- [AirLLM 4.0.0 구현](https://github.com/lyogavin/airllm/blob/v4.0.0/air_llm/airllm/airllm_base.py): prefetch·압축·레이어 저장·generate API
- [Qwen3-14B 모델 카드](https://huggingface.co/Qwen/Qwen3-14B): thinking 템플릿과 권장 sampling 설정
