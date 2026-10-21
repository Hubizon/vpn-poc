# Downloads wintun.dll (the Windows TUN driver library used for the VPN adapter)
# into the project folder, where `cargo run` from here will find it.
# Official source: https://www.wintun.net/
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$zip = Join-Path $env:TEMP 'wintun.zip'
Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $zip
$tmp = Join-Path $env:TEMP 'wintun-extract'
Expand-Archive $zip -DestinationPath $tmp -Force
Copy-Item (Join-Path $tmp 'wintun\bin\amd64\wintun.dll') (Join-Path $root 'wintun.dll') -Force
foreach ($dir in @('target\debug', 'target\release')) {
    $targetPath = Join-Path $root $dir
    if (Test-Path $targetPath) {
        Copy-Item (Join-Path $tmp 'wintun\bin\amd64\wintun.dll') $targetPath -Force
    }
}
Remove-Item $zip, $tmp -Recurse -Force
Write-Host "wintun.dll saved to $root"
