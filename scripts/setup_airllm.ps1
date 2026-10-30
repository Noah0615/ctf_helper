param([string]$Python = "python")
$ErrorActionPreference = "Stop"
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskVenv = Join-Path $taskRoot ".venv_airllm"
$taskPython = Join-Path $taskVenv "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $taskPython)) {
    & $Python -m venv $taskVenv
    if ($LASTEXITCODE -ne 0) { throw "AirLLM venv creation failed. Use Python 3.11 or newer." }
}
& $taskPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
# RTX 50 / Blackwell needs a CUDA wheel with sm_120 support.
& $taskPython -m pip install "torch>=2.7,<3" --index-url https://download.pytorch.org/whl/cu128
if ($LASTEXITCODE -ne 0) { throw "CUDA PyTorch installation failed" }
& $taskPython -m pip install -r (Join-Path $taskRoot "requirements-airllm.txt")
if ($LASTEXITCODE -ne 0) { throw "AirLLM installation failed" }
& $taskPython (Join-Path $PSScriptRoot "ctf_airllm_server.py") --check
if ($LASTEXITCODE -ne 0) { throw "CUDA preflight failed. No model weights downloaded." }
Write-Host "Environment ready. Run: powershell -File scripts/start_airllm.ps1"
