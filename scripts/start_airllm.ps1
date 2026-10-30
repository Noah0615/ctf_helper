param(
    [string]$Cache = "",
    [int]$Context = 8192,
    [int]$MaxNewTokens = 512,
    [ValidateSet("none", "4bit", "8bit")][string]$Compression = "none",
    [switch]$DeleteOriginal
)
$ErrorActionPreference = "Stop"
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskPython = Join-Path $taskRoot ".venv_airllm\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $taskPython)) { throw "Run scripts/setup_airllm.ps1 first." }
$taskArgs = @((Join-Path $PSScriptRoot "ctf_airllm_server.py"), "--load", "--context", $Context, "--max-new-tokens", $MaxNewTokens)
if ($Cache) { $taskArgs += @("--cache", $Cache) }
if ($Compression -ne "none") { $taskArgs += @("--compression", $Compression) }
if ($DeleteOriginal) { $taskArgs += "--delete-original" }
& $taskPython @taskArgs
exit $LASTEXITCODE
