<#=====================================================================
  UnifiedDiag.ps1
  One‑stop diagnostics for Windows, Linux, and macOS.
  Works with:
      • Windows PowerShell (5.1) or PowerShell 7+
      • PowerShell 7+ on Linux/macOS
  --------------------------------------------------------------------
  Usage:
      pwsh ./UnifiedDiag.ps1                # defaults to 8.8.8.8
      pwsh ./UnifiedDiag.ps1 1.1.1.1        # custom target host
  =====================================================================#>

param(
    [string]$TargetHost = '8.8.8.8'   # default ping target
)

# --------------------------------------------------------------------
# Create a timestamped folder for all output files
# --------------------------------------------------------------------
$timestamp   = Get-Date -Format "yyyyMMdd-HHmmss"
# TODO: Fix reportRoot Join-Path without hardcoded home dir
# $reportRoot  = Join-Path $env:USERPROFILE "UnifiedDiag-$timestamp"
$reportRoot  = Join-Path "/home/didier" "UnifiedDiag-$timestamp"
New-Item -ItemType Directory -Path $reportRoot | Out-Null

function Log {
    param([string]$msg)
    Write-Host "[*] $msg"
    Add-Content -Path (Join-Path $reportRoot "summary.log") -Value "[*] $msg"
}
Log "=== Unified Diagnostics started ==="
Log "Target host: $TargetHost"
Log "Report folder: $reportRoot"
Add-Content -Path (Join-Path $reportRoot "summary.log") ""

# --------------------------------------------------------------------
# Helper: run a script block and dump its output to a file
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
# Detect OS
# --------------------------------------------------------------------
switch ($PSVersionTable.OS) {
    {$_ -match 'Windows'} { $OS = 'Windows' }
    {$_ -match 'Darwin'}  { $OS = 'macOS'   }
    default               { $OS = 'Linux'   }
}
Log "Detected OS: $OS"

# --------------------------------------------------------------------
# 1️⃣ NETWORK INTERFACES & ROUTING
# --------------------------------------------------------------------
if ($OS -eq 'Windows') {
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
}
elseif ($OS -eq 'macOS') {
    Run-AndSave "Network_Interfaces" { ifconfig }
    Run-AndSave "Routing_Table"    { netstat -nr }
}
else { # Linux
    Run-AndSave "Network_Interfaces" { ip addr show }
    Run-AndSave "Routing_Table"    { ip route show }
}

# --------------------------------------------------------------------
# 2️⃣ PING & TRACEROUTE
# --------------------------------------------------------------------
Run-AndSave "Ping_$TargetHost" {
    if ($OS -eq 'Windows') {
        Test-Connection -ComputerName $TargetHost -Count 4 -ErrorAction SilentlyContinue |
            Format-Table -AutoSize
    } else {
        ping -c 4 $TargetHost
    }
}
Run-AndSave "Traceroute_$TargetHost" {
    if ($OS -eq 'Windows') { tracert $TargetHost } else { traceroute $TargetHost }
}

# --------------------------------------------------------------------
# 3️⃣ DNS LOOKUP
# --------------------------------------------------------------------
Run-AndSave "DNS_Lookup_$TargetHost" {
    if ($OS -eq 'Windows') {
        nslookup $TargetHost
    } else {
        dig $TargetHost +short
    }
}

# --------------------------------------------------------------------
# 4️⃣ LISTENING PORTS & FIREWALL (where applicable)
# --------------------------------------------------------------------
if ($OS -eq 'Windows') {
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
}
elseif ($OS -eq 'macOS') {
    Run-AndSave "Listening_Ports" {
        lsof -iTCP -sTCP:LISTEN -Pn
    }
    Run-AndSave "Firewall_Status" {
        /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
    }
}
else { # Linux
    Run-AndSave "Listening_Ports" {
        ss -tulnp
    }
    Run-AndSave "Firewall_Rules" {
        if (Get-Command nft -ErrorAction SilentlyContinue) {
            nft list ruleset
        } elseif (Get-Command iptables -ErrorAction SilentlyContinue) {
            iptables -L -v -n
        } else {
            "No firewall tool detected."
        }
    }
}

# --------------------------------------------------------------------
# 5️⃣ PROCESS SNAPSHOT (top 20 by CPU)
# --------------------------------------------------------------------
Run-AndSave "Top_Processes_By_CPU" {
    Get-Process |
        Sort-Object CPU -Descending |
        Select-Object -First 20 Id,ProcessName,CPU,WorkingSet |
        Format-Table -AutoSize
}

# --------------------------------------------------------------------
# 6️⃣ DISK USAGE
# --------------------------------------------------------------------
if ($OS -eq 'Windows') {
    Run-AndSave "Disk_Usage" {
        Get-PSDrive -PSProvider FileSystem |
            Select-Object Name,Free,Used,
                @{Name='TotalGB';Expression={"{0:N2}" -f ($_.Free + $_.Used)/1GB}},
                @{Name='Free%';Expression={"{0:P1}" -f ($_.Free/($_.Free+$_.Used))}} |
            Format-Table -AutoSize
    }
}
elseif ($OS -eq 'macOS') {
    Run-AndSave "Disk_Usage" { df -h }
}
else { # Linux
    Run-AndSave "Disk_Usage" { df -hT }
}

# --------------------------------------------------------------------
# 7️⃣ SYSTEM / HARDWARE INFO
# --------------------------------------------------------------------
if ($OS -eq 'Windows') {
    Run-AndSave "System_Info" { systeminfo }
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
}
elseif ($OS -eq 'macOS') {
    Run-AndSave "System_Info" { system_profiler SPSoftwareDataType }
    Run-AndSave "Hardware_Summary" { system_profiler SPHardwareDataType }
}
else { # Linux
    Run-AndSave "System_Info" { uname -a }
    Run-AndSave "Hardware_Summary" {
        if (Get-Command lshw -ErrorAction SilentlyContinue) {
            lshw -short
        } else {
            "lshw not installed – install via apt/yum/pacman if needed."
        }
    }
}

# --------------------------------------------------------------------
# 8️⃣ RECENT ERROR EVENTS (system logs)
# --------------------------------------------------------------------
if ($OS -eq 'Windows') {
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
}
elseif ($OS -eq 'macOS') {
    Run-AndSave "Recent_System_Errors" {
        log show --predicate 'eventMessage contains "error"' --last 1h | tail -n 50
    }
}
else { # Linux
    Run-AndSave "Recent_Journal_Errors" {
        journalctl -p 3 -xb --no-pager | tail -n 50
    }
}

# --------------------------------------------------------------------
# Wrap‑up
# --------------------------------------------------------------------
Log ""
Log "=== Diagnostics complete ==="
Log "All files saved under: $reportRoot"
Log "To archive them (Windows PowerShell or PowerShell 7):"
Log "    Compress-Archive -Path `"$reportRoot\*`" -DestinationPath `"$reportRoot.zip`""
Log "Happy troubleshooting!"
