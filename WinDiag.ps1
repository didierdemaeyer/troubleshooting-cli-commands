<#=====================================================================
  WinDiag.ps1
  One‑stop diagnostics for Windows (native PowerShell)
  - Network configuration
  - Ping / Traceroute
  - DNS lookup
  - Listening ports / firewall rules
  - Process snapshot
  - Disk usage
  - System / hardware summary
  - Recent error events
  --------------------------------------------------------------------
  Usage:
      .\WinDiag.ps1               # defaults to 8.8.8.8 as the test host
      .\WinDiag.ps1 1.1.1.1       # specify a different target host
  =====================================================================#>

param(
    [string]$TargetHost = '8.8.8.8'   # default host if none supplied
)

# --------------------------------------------------------------------
# Helper: create a timestamped folder for all output files
# --------------------------------------------------------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
# TODO: Fix reportRoot Join-Path without hardcoded home dir
# $reportRoot = Join-Path $env:USERPROFILE "WinDiag-$timestamp"
$reportRoot  = Join-Path "/home/didier" "WinDiag-$timestamp"

New-Item -ItemType Directory -Path $reportRoot | Out-Null

function Log {
    param([string]$msg)
    Write-Host "[*] $msg"
    Add-Content -Path (Join-Path $reportRoot "summary.log") -Value "[*] $msg"
}
Log "=== Windows Diagnostics started ==="
Log "Target host: $TargetHost"
Log "Report folder: $reportRoot"
Add-Content -Path (Join-Path $reportRoot "summary.log") ""

# --------------------------------------------------------------------
# Helper: run a command, capture its output, and store it as a .txt file
# --------------------------------------------------------------------
function Run-AndSave {
    param(
        [string]$Description,
        [scriptblock]$ScriptBlock
    )
    $outFile = Join-Path $reportRoot "$Description.txt"
    Log "Running: $Description"
    try {
        & $ScriptBlock *>&1 | Out-File -FilePath $outFile -Encoding utf8
    } catch {
        "Command failed: $_" | Out-File -FilePath $outFile -Append -Encoding utf8
    }
    "`n" | Out-File -FilePath $outFile -Append -Encoding utf8
}

# --------------------------------------------------------------------
# 1️⃣ Network Interfaces & Routing
# --------------------------------------------------------------------
Run-AndSave "Network_Interfaces" {
    Get-NetIPAddress -AddressFamily IPv4,IPv6 |
        Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressState |
        Format-Table -AutoSize
}
Run-AndSave "Routing_Table" {
    Get-NetRoute |
        Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric |
        Format-Table -AutoSize
}

# --------------------------------------------------------------------
# 2️⃣ Ping & Traceroute
# --------------------------------------------------------------------
Run-AndSave "Ping_$TargetHost" {
    Test-Connection -ComputerName $TargetHost -Count 4 -ErrorAction SilentlyContinue |
        Format-Table -AutoSize
}
Run-AndSave "Traceroute_$TargetHost" {
    tracert $TargetHost
}

# --------------------------------------------------------------------
# 3️⃣ DNS Lookup
# --------------------------------------------------------------------
Run-AndSave "DNS_Lookup_$TargetHost" {
    Resolve-DnsName -Name $TargetHost -ErrorAction SilentlyContinue |
        Select-Object Name,QueryType,IPAddress |
        Format-Table -AutoSize
}

# --------------------------------------------------------------------
# 4️⃣ Listening Ports (TCP/UDP) + Firewall Rules
# --------------------------------------------------------------------
Run-AndSave "Listening_Ports" {
    Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress,LocalPort,OwningProcess |
        Format-Table -AutoSize
}
Run-AndSave "Firewall_Rules" {
    Get-NetFirewallRule -Enabled True |
        Select-Object DisplayName,Direction,Action,Protocol,LocalPort |
        Format-Table -AutoSize
}

# --------------------------------------------------------------------
# 5️⃣ Process Snapshot (top 20 by CPU)
# --------------------------------------------------------------------
Run-AndSave "Top_Processes_By_CPU" {
    Get-Process |
        Sort-Object CPU -Descending |
        Select-Object -First 20 Id,ProcessName,CPU,WorkingSet |
        Format-Table -AutoSize
}

# --------------------------------------------------------------------
# 6️⃣ Disk Usage
# --------------------------------------------------------------------
Run-AndSave "Disk_Usage" {
    Get-PSDrive -PSProvider FileSystem |
        Select-Object Name,Free,Used, @{Name='TotalGB';Expression={"{0:N2}" -f ($_.Free + $_.Used)/1GB}},
        @{Name='Free%';Expression={"{0:P1}" -f ($_.Free/($_.Free+$_.Used))}} |
        Format-Table -AutoSize
}

# --------------------------------------------------------------------
# 7️⃣ System / Hardware Summary
# --------------------------------------------------------------------
Run-AndSave "System_Info" {
    systeminfo
}
Run-AndSave "Hardware_Summary" {
    Get-CimInstance -ClassName Win32_ComputerSystem |
        Select-Object Manufacturer,Model,TotalPhysicalMemory |
        Format-List
}
Run-AndSave "BIOS_Info" {
    Get-CimInstance -ClassName Win32_BIOS |
        Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate |
        Format-List
}

# --------------------------------------------------------------------
# 8️⃣ Recent Error Events (System & Application logs)
# --------------------------------------------------------------------
Run-AndSave "Recent_System_Errors" {
    Get-WinEvent -LogName System -FilterXPath "*[System/Level=2]" -MaxEvents 30 |
        Select-Object TimeCreated,Id,Message |
        Format-Table -Wrap -AutoSize
}
Run-AndSave "Recent_Application_Errors" {
    Get-WinEvent -LogName Application -FilterXPath "*[System/Level=2]" -MaxEvents 30 |
        Select-Object TimeCreated,Id,Message |
        Format-Table -Wrap -AutoSize
}

# --------------------------------------------------------------------
# Wrap‑up
# --------------------------------------------------------------------
Log ""
Log "=== Diagnostics complete ==="
Log "All files saved under: $reportRoot"
Log "To archive them:"
Log "    Compress-Archive -Path \"$reportRoot\*\" -DestinationPath \"${reportRoot}.zip\""
Log "Happy troubleshooting!"
