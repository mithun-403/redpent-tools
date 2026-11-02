# redpent-tools tool installer for Windows (PowerShell).
# Uses winget/choco/scoop where available; go tools via `go install`.
#   .\install.ps1            # all lanes
#   .\install.ps1 -Passive   # passive + boundary only
#   .\install.ps1 -Check     # report status only
param([switch]$Passive, [switch]$Check)

function Have($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

$pm = if (Have winget) { "winget" } elseif (Have choco) { "choco" } elseif (Have scoop) { "scoop" } else { "" }
Write-Host "==> OS=Windows  package-manager=$pm"

if ($Check) {
  "whois","dig","subfinder","httpx","theHarvester","waybackurls","nmap","masscan","ffuf","nikto","wafw00f","sslscan","openssl","curl","go" |
    ForEach-Object { "{0,-14} {1}" -f $_, $(if (Have $_) {"present"} else {"MISSING"}) }
  return
}

function PkgInstall($name, $wingetId, $chocoId, $scoopId) {
  if (Have $name) { Write-Host "  ok   $name (present)"; return }
  Write-Host "  +    $name via $pm"
  switch ($pm) {
    "winget" { winget install --silent --accept-package-agreements --accept-source-agreements -e --id $wingetId }
    "choco"  { choco install -y $chocoId }
    "scoop"  { scoop install $scoopId }
    default  { Write-Host "  !!   no package manager; install $name manually" }
  }
}

function GoInstall($name, $mod) {
  if (Have $name) { Write-Host "  ok   $name (present)"; return }
  if (-not (Have go)) { Write-Host "  !!   go missing; cannot install $name"; return }
  Write-Host "  +    $name via go install"; go install $mod
}

Write-Host "==> Python dependencies"
python -m pip install -r "$PSScriptRoot\requirements.txt"

Write-Host "==> Passive + boundary tools"
PkgInstall "nmap" "Insecure.Nmap" "nmap" "nmap"          # nmap ships dig? no — see below
PkgInstall "curl" "cURL.cURL" "curl" "curl"
PkgInstall "openssl" "ShiningLight.OpenSSL.Light" "openssl" "openssl"
python -m pip install wafw00f theHarvester
GoInstall "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
GoInstall "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
GoInstall "waybackurls" "github.com/tomnomnom/waybackurls@latest"
Write-Host "  note: 'dig' comes with BIND tools for Windows (isc.org) or use nslookup; sslscan via WSL/Docker."

if (-not $Passive) {
  Write-Host "==> Active tools (gated at runtime)"
  PkgInstall "masscan" "" "masscan" "masscan"
  PkgInstall "nikto" "" "nikto" "nikto"
  GoInstall "ffuf" "github.com/ffuf/ffuf/v2@latest"
}

Write-Host "==> Done. Add go bin to PATH if needed:  `$env:PATH += ';' + (Join-Path $HOME 'go\bin')"
Write-Host "==> For tools without native Windows builds (sslscan, masscan, nikto), the Docker image is recommended."
