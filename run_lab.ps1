$ErrorActionPreference = 'Stop'
$env:PYTHONPATH = "$PWD\src"
if (Get-Command python -ErrorAction SilentlyContinue) {
    python -m detectlab.cli --input data\events.jsonl --out artifacts
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    py -3 -m detectlab.cli --input data\events.jsonl --out artifacts
} else {
    throw 'Python 3.10+ was not found. Install it from https://www.python.org/downloads/windows/ and reopen PowerShell.'
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
