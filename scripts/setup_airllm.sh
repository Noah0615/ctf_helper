#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m venv "$task_root/.venv_airllm"
task_python="$task_root/.venv_airllm/bin/python"
"$task_python" -m pip install --upgrade pip
"$task_python" -m pip install 'torch>=2.7,<3' --index-url https://download.pytorch.org/whl/cu128
"$task_python" -m pip install -r "$task_root/requirements-airllm.txt"
"$task_python" "$task_root/scripts/ctf_airllm_server.py" --check
printf '%s\n' "Ready. Run .venv_airllm/bin/python scripts/ctf_airllm_server.py --load"
