$ErrorActionPreference = 'Stop'
$env:PYTHONPATH = "$PWD\src"
if (Get-Command python -ErrorAction SilentlyContinue) {
    python -m unittest discover -s tests -v
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    py -3 -m unittest discover -s tests -v
} else {
    throw 'Python 3.10+ was not found. Install it from https://www.python.org/downloads/windows/ and reopen PowerShell.'
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
