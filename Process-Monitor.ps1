<#
.SYNOPSIS
    Live activity monitor for a binary (name or PID). Procmon-lite for the console.

.DESCRIPTION
    Subscribes to WMI process creation/termination events and polls each tracked
    PID for loaded modules (DLLs) and network connections. If Sysmon is installed
    on the target, also tails file/registry/DNS/image-load events for matched PIDs.

    Follows child processes automatically. Works locally or remotely via WinRM.

.PARAMETER Target
    Process name (e.g. "notepad.exe") or numeric PID to follow. Name match is
    case-insensitive; child processes of matched PIDs are followed too.

.PARAMETER ComputerName
    Target host for remote mode. Omit to monitor the local machine.

.PARAMETER Credential
    Credential for the remote session.

.PARAMETER UseSSL
    Use HTTPS (WinRM 5986).

.PARAMETER PollInterval
    Seconds between polling cycles (modules, network, sysmon tail). Default 1.

.PARAMETER NoModules
    Do not track loaded modules (cuts noise for large processes).

.EXAMPLE
    # Follow every notepad.exe on the local machine
    .\Process-Monitor.ps1 -Target notepad.exe

.EXAMPLE
    # Follow PID 1234 on 192.168.122.3
    $c = Import-Clixml .\admin.xml
    .\Process-Monitor.ps1 -Target 1234 -ComputerName 192.168.122.3 -Credential $c
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Target,
    [string]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$UseSSL,
    [int]$PollInterval = 1,
    [switch]$NoModules
)

# -----------------------------------------------------------------------------
# Monitor body — runs on the target host (local or inside a PSSession via Job).
# Emits PSCustomObjects; the local renderer consumes them via Receive-Job.
# -----------------------------------------------------------------------------
$monitorBody = {
    param($Target, $Interval, $NoModules)

    $ErrorActionPreference = 'SilentlyContinue'

    $targetPid = $null
    $targetPattern = $null
    if ($Target -match '^\d+$') {
        $targetPid = [int]$Target
    } else {
        $targetPattern = $Target
        if ($targetPattern -notlike '*.exe') { $targetPattern += '.exe' }
    }

    function Emit {
        param([string]$Kind, [int]$ProcId, [string]$Name, [string]$Msg)
        [pscustomobject]@{
            Time      = Get-Date
            Kind      = $Kind
            ProcessId = $ProcId
            Name      = $Name
            Message   = $Msg
        }
    }

    # WMI indication subscriptions (use __InstanceCreationEvent for full object).
    # Under remoting the default namespace/scope may refuse __Instance* events; we
    # surface any failure so the operator sees why PROC_START/STOP are missing.
    $qStart = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    $qStop  = "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    $wmiOK = $true
    try { Register-CimIndicationEvent -Query $qStart -SourceIdentifier 'PM_Start' -ErrorAction Stop | Out-Null }
    catch { $wmiOK = $false; Emit 'WARN' 0 '' "Register PM_Start failed: $($_.Exception.Message)" }
    try { Register-CimIndicationEvent -Query $qStop  -SourceIdentifier 'PM_Stop'  -ErrorAction Stop | Out-Null }
    catch { $wmiOK = $false; Emit 'WARN' 0 '' "Register PM_Stop failed: $($_.Exception.Message)" }
    if ($wmiOK) { Emit 'INFO' 0 '' 'WMI process indication subscriptions OK' }
    else        { Emit 'INFO' 0 '' 'Falling back to process polling (no WMI indications)' }

    $monitored = New-Object 'System.Collections.Generic.HashSet[int]'
    $snapshots = @{}  # PID -> @{ Modules; Connections }

    # Attach to any processes already running that match
    $initial = if ($targetPid) {
        Get-Process -Id $targetPid -ErrorAction SilentlyContinue
    } elseif ($targetPattern) {
        Get-Process | Where-Object { ($_.ProcessName + '.exe') -ieq $targetPattern }
    }
    foreach ($p in @($initial)) {
        [void]$monitored.Add($p.Id)
        Emit 'ATTACH' $p.Id $p.ProcessName "attached to existing process"
    }

    # Detect Sysmon presence
    $sysmonLog = $null
    try {
        $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    } catch {}
    $lastSysmonRid = 0
    if ($sysmonLog) {
        $head = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($head) { $lastSysmonRid = $head.RecordId }
        Emit 'INFO' 0 '' "Sysmon detected; tailing Microsoft-Windows-Sysmon/Operational"
    } else {
        Emit 'INFO' 0 '' "Sysmon not installed; using WMI + polling only"
    }
    Emit 'INFO' 0 '' "Target=$Target  PollInterval=${Interval}s  NoModules=$NoModules  HostedOn=$env:COMPUTERNAME"

    # Polling fallback for process detection (used if WMI indications failed,
    # and as a safety net even when they work — remoting sometimes drops events)
    $prevPids = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $prevPids[[int]$_.ProcessId] = @{
            Name = "$($_.Name)"; Ppid = [int]$_.ParentProcessId; Cmd = "$($_.CommandLine)"
        }
    }
    $cycle = 0

    $sysmonKindMap = @{
        1  = 'PROC_CREATE'; 2  = 'FILE_TIME'; 3  = 'NETWORK';   5 = 'PROC_END'
        6  = 'DRIVER_LOAD'; 7  = 'IMAGE_LOAD'; 8 = 'REMOTE_THR'; 9 = 'RAW_ACCESS'
        10 = 'PROC_ACCESS'; 11 = 'FILE_CREATE'; 12 = 'REG_KEY'; 13 = 'REG_VALUE'
        14 = 'REG_RENAME';  15 = 'FILE_STREAM'; 17 = 'PIPE_CREATE'; 18 = 'PIPE_CONNECT'
        22 = 'DNS';         23 = 'FILE_DELETE'
    }

    while ($true) {
        $cycle++

        # --- Polling-based process diff (complements WMI indications) -----
        $curPids = @{}
        try {
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
                $curPids[[int]$_.ProcessId] = @{
                    Name = "$($_.Name)"; Ppid = [int]$_.ParentProcessId; Cmd = "$($_.CommandLine)"
                }
            }
        } catch { Emit 'WARN' 0 '' "Win32_Process poll failed: $($_.Exception.Message)" }

        foreach ($kv in $curPids.GetEnumerator()) {
            if ($prevPids.ContainsKey($kv.Key)) { continue }
            $procId = [int]$kv.Key
            $info = $kv.Value
            $attach = $false
            if     ($targetPid     -and $procId -eq $targetPid)     { $attach = $true }
            elseif ($targetPattern -and $info.Name -ieq $targetPattern) { $attach = $true }
            elseif ($monitored.Contains($info.Ppid))                { $attach = $true }
            if ($attach -and -not $monitored.Contains($procId)) {
                [void]$monitored.Add($procId)
                Emit 'PROC_START' $procId $info.Name "ppid=$($info.Ppid) cmd=[$($info.Cmd)]"
            }
        }
        foreach ($k in @($prevPids.Keys)) {
            if (-not $curPids.ContainsKey($k)) {
                if ($monitored.Contains($k)) {
                    [void]$monitored.Remove($k)
                    $snapshots.Remove($k)
                    Emit 'PROC_STOP' $k $prevPids[$k].Name "(exit detected by polling)"
                }
            }
        }
        $prevPids = $curPids

        if (($cycle % 10) -eq 0) {
            Emit 'HEARTBEAT' 0 '' "cycle=$cycle monitored=$($monitored.Count) totalProcs=$($curPids.Count)"
        }

        # --- Drain process-start events ------------------------------------
        foreach ($ev in (Get-Event -SourceIdentifier 'PM_Start' -ErrorAction SilentlyContinue)) {
            $ti = $ev.SourceEventArgs.NewEvent.TargetInstance
            $procId = [int]$ti.ProcessId
            $name   = "$($ti.Name)"
            $ppid   = [int]$ti.ParentProcessId
            $cmd    = "$($ti.CommandLine)"
            $attach = $false
            if     ($targetPid     -and $procId -eq $targetPid)   { $attach = $true }
            elseif ($targetPattern -and $name   -ieq $targetPattern) { $attach = $true }
            elseif ($monitored.Contains($ppid))                   { $attach = $true }
            if ($attach -and -not $monitored.Contains($procId)) {
                [void]$monitored.Add($procId)
                Emit 'PROC_START' $procId $name "ppid=$ppid cmd=[$cmd]"
            }
            Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue
        }

        # --- Drain process-stop events -------------------------------------
        foreach ($ev in (Get-Event -SourceIdentifier 'PM_Stop' -ErrorAction SilentlyContinue)) {
            $ti = $ev.SourceEventArgs.NewEvent.TargetInstance
            $procId = [int]$ti.ProcessId
            $name   = "$($ti.Name)"
            if ($monitored.Contains($procId)) {
                [void]$monitored.Remove($procId)
                $snapshots.Remove($procId)
                Emit 'PROC_STOP' $procId $name "exitcode=$($ti.ExitCode)"
            }
            Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue
        }

        # --- Poll each monitored PID ---------------------------------------
        foreach ($p in @($monitored)) {
            $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
            if (-not $proc) { continue }

            $prev = $snapshots[$p]

            if (-not $NoModules) {
                $mods = @()
                try { $mods = @($proc.Modules | ForEach-Object { $_.FileName }) } catch {}
                if ($prev) {
                    $new = $mods | Where-Object { $_ -and ($_ -notin $prev.Modules) }
                    foreach ($m in $new) { Emit 'MODULE_LOAD' $p $proc.ProcessName $m }
                } else {
                    foreach ($m in $mods) { Emit 'MODULE_INIT' $p $proc.ProcessName $m }
                }
            } else {
                $mods = @()
            }

            $conns = @()
            try {
                $conns = @(Get-NetTCPConnection -OwningProcess $p -ErrorAction SilentlyContinue | ForEach-Object {
                    "{0}:{1} -> {2}:{3} [{4}]" -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $_.State
                })
            } catch {}
            if ($prev) {
                $opened = $conns | Where-Object { $_ -notin $prev.Connections }
                $closed = $prev.Connections | Where-Object { $_ -notin $conns }
                foreach ($c in $opened) { Emit 'NET_OPEN'  $p $proc.ProcessName $c }
                foreach ($c in $closed) { Emit 'NET_CLOSE' $p $proc.ProcessName $c }
            } else {
                foreach ($c in $conns) { Emit 'NET_OPEN' $p $proc.ProcessName $c }
            }

            $snapshots[$p] = @{ Modules = $mods; Connections = $conns }
        }

        # --- Drain Sysmon tail for monitored PIDs --------------------------
        if ($sysmonLog) {
            $batch = @()
            try {
                $batch = @(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' `
                    -MaxEvents 200 -ErrorAction SilentlyContinue |
                    Where-Object { $_.RecordId -gt $lastSysmonRid } |
                    Sort-Object RecordId)
            } catch {}
            foreach ($wev in $batch) {
                $lastSysmonRid = $wev.RecordId
                $data = @{}
                try {
                    $xml = [xml]$wev.ToXml()
                    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
                } catch { continue }
                $evPid = 0
                if ($data.ProcessId) { [int]::TryParse($data.ProcessId, [ref]$evPid) | Out-Null }
                if (-not $monitored.Contains($evPid)) { continue }
                $kind = $sysmonKindMap[[int]$wev.Id]
                if (-not $kind) { $kind = "SYSMON_$($wev.Id)" }
                $detail = switch ([int]$wev.Id) {
                    1  { "image=$($data.Image) cmd=[$($data.CommandLine)] ppid=$($data.ParentProcessId)" }
                    3  { "$($data.Protocol) $($data.SourceIp):$($data.SourcePort) -> $($data.DestinationIp):$($data.DestinationPort) ($($data.DestinationHostname))" }
                    7  { "loaded=$($data.ImageLoaded) signed=$($data.Signed)" }
                    11 { "target=$($data.TargetFilename)" }
                    12 { "op=$($data.EventType) target=$($data.TargetObject)" }
                    13 { "target=$($data.TargetObject) details=$($data.Details)" }
                    14 { "target=$($data.TargetObject) newname=$($data.NewName)" }
                    22 { "query=$($data.QueryName) result=$($data.QueryResults)" }
                    23 { "target=$($data.TargetFilename)" }
                    default {
                        ($data.GetEnumerator() | Where-Object { $_.Key -notin 'UtcTime','ProcessGuid','ProcessId','User' } |
                         ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
                    }
                }
                Emit "SYS_$kind" $evPid ($data.Image | Split-Path -Leaf -ErrorAction SilentlyContinue) $detail
            }
        }

        Start-Sleep -Seconds $Interval
    }
}

# -----------------------------------------------------------------------------
# Render loop (local)
# -----------------------------------------------------------------------------
$kindColor = @{
    'INFO'        = 'DarkGray'
    'ATTACH'      = 'Green'
    'PROC_START'  = 'Green'
    'PROC_STOP'   = 'Red'
    'MODULE_INIT' = 'DarkCyan'
    'MODULE_LOAD' = 'Cyan'
    'NET_OPEN'    = 'Yellow'
    'NET_CLOSE'   = 'DarkYellow'
}
function Get-EventColor {
    param([string]$Kind)
    if ($kindColor.ContainsKey($Kind)) { return $kindColor[$Kind] }
    if ($Kind -like 'SYS_REG_*')  { return 'Magenta' }
    if ($Kind -like 'SYS_FILE_*') { return 'Yellow'  }
    if ($Kind -like 'SYS_NET*' -or $Kind -eq 'SYS_DNS') { return 'Cyan' }
    if ($Kind -like 'SYS_PROC_*') { return 'Green' }
    if ($Kind -like 'SYS_IMAGE_LOAD') { return 'DarkCyan' }
    return 'Gray'
}

function Format-Event {
    param($e)
    if (-not $e) { return }
    $ts = ([datetime]$e.Time).ToString('HH:mm:ss.fff')
    $pidStr = if ($e.ProcessId) { ([int]$e.ProcessId).ToString().PadLeft(6) } else { '     -' }
    $nm = if ($e.Name) { "($($e.Name))" } else { '' }
    $line = "[{0}] {1,-14} pid={2} {3,-18} {4}" -f $ts, $e.Kind, $pidStr, $nm, $e.Message
    Write-Host $line -ForegroundColor (Get-EventColor $e.Kind)
}

$session = $null
try {
    if ($ComputerName) {
        Write-Host "Connecting to $ComputerName via WinRM..." -ForegroundColor DarkGray
        $p = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
        if ($Credential) { $p.Credential = $Credential }
        if ($UseSSL)     { $p.UseSSL     = $true }
        $session = New-PSSession @p
        Write-Host "Monitoring on $ComputerName. Press Ctrl+C to stop." -ForegroundColor Green
        Invoke-Command -Session $session -ScriptBlock $monitorBody `
            -ArgumentList $Target, $PollInterval, [bool]$NoModules |
            ForEach-Object { Format-Event $_ }
    } else {
        Write-Host "Monitoring locally. Press Ctrl+C to stop." -ForegroundColor Green
        & $monitorBody $Target $PollInterval ([bool]$NoModules) |
            ForEach-Object { Format-Event $_ }
    }
}
finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
}
