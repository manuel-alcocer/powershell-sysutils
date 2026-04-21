<#
.SYNOPSIS
    Full-screen registry browser (TUI). Two-pane layout: subkeys | values.

.DESCRIPTION
    Uses the Windows console API for full-screen rendering. Navigation via
    arrow keys, Enter, Backspace. Optional remote mode via WinRM.

.PARAMETER ComputerName
    Target host for remote mode. Omit to browse local machine.

.PARAMETER Credential
    Credential for the remote session.

.PARAMETER UseSSL
    Use HTTPS (WinRM 5986) instead of HTTP (5985).

.EXAMPLE
    .\Registry-TUI.ps1

.EXAMPLE
    $c = Get-Credential administrator
    .\Registry-TUI.ps1 -ComputerName 192.168.122.3 -Credential $c
#>
[CmdletBinding()]
param(
    [string]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$UseSSL
)

$script:Session  = $null
$script:IsRemote = [bool]$ComputerName

# -----------------------------------------------------------------------------
# Remote-safe registry operations (same contract as Registry-Navigator.ps1)
# -----------------------------------------------------------------------------
$script:OpsBlock = {
    param($Action, $Hive, $SubKey, $Extra)

    function Open-Key {
        param($H, $S)
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::$H,
            [Microsoft.Win32.RegistryView]::Default)
        if ([string]::IsNullOrEmpty($S)) { return $base }
        return $base.OpenSubKey($S, $false)
    }

    switch ($Action) {
        'list' {
            $k = Open-Key $Hive $SubKey
            if (-not $k) { return @{ error = "Key not found: $Hive\$SubKey" } }
            $subs = @($k.GetSubKeyNames() | Sort-Object)
            $vals = foreach ($n in ($k.GetValueNames() | Sort-Object)) {
                $kind = $k.GetValueKind($n)
                $data = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
                [pscustomobject]@{ Name = $n; Kind = "$kind"; Data = $data }
            }
            $k.Close()
            return @{ subkeys = $subs; values = @($vals) }
        }
        'exists' {
            $k = Open-Key $Hive $SubKey
            if ($k) { $k.Close(); return $true } else { return $false }
        }
        'find' {
            $results = New-Object System.Collections.Generic.List[object]
            $root = Open-Key $Hive $SubKey
            if (-not $root) { return @() }
            $pat = [regex]::new($Extra, 'IgnoreCase')
            $stack = New-Object System.Collections.Generic.Stack[object]
            $stack.Push(@{ Key = $root; Path = $SubKey; IsRoot = $true })
            while ($stack.Count -gt 0 -and $results.Count -lt 500) {
                $cur = $stack.Pop()
                try {
                    foreach ($n in $cur.Key.GetValueNames()) {
                        if ($pat.IsMatch($n)) {
                            $results.Add([pscustomobject]@{
                                Path = $cur.Path; Kind = 'Value'; Name = $n
                            })
                            if ($results.Count -ge 500) { break }
                        }
                    }
                    foreach ($sn in $cur.Key.GetSubKeyNames()) {
                        if ($pat.IsMatch($sn)) {
                            $results.Add([pscustomobject]@{
                                Path = $cur.Path; Kind = 'Key'; Name = $sn
                            })
                            if ($results.Count -ge 500) { break }
                        }
                        try {
                            $child = $cur.Key.OpenSubKey($sn, $false)
                            if ($child) {
                                $childPath = if ($cur.Path) { "$($cur.Path)\$sn" } else { $sn }
                                $stack.Push(@{ Key = $child; Path = $childPath; IsRoot = $false })
                            }
                        } catch {}
                    }
                } catch {}
                if (-not $cur.IsRoot) { try { $cur.Key.Close() } catch {} }
            }
            $root.Close()
            return ,@($results.ToArray())
        }
    }
}

$script:ESC = [char]27
$script:FrameBuffer = New-Object System.Text.StringBuilder

function Hide-Cursor { try { [Console]::CursorVisible = $false } catch {}; [Console]::Write("$script:ESC[?25l") }
function Show-Cursor { try { [Console]::CursorVisible = $true }  catch {}; [Console]::Write("$script:ESC[?25h") }

# ANSI 16-color mapping for PowerShell ConsoleColor names
$script:AnsiColor = @{
    'Black'       = 30; 'DarkBlue'    = 34; 'DarkGreen'   = 32; 'DarkCyan'    = 36
    'DarkRed'     = 31; 'DarkMagenta' = 35; 'DarkYellow'  = 33; 'Gray'        = 37
    'DarkGray'    = 90; 'Blue'        = 94; 'Green'       = 92; 'Cyan'        = 96
    'Red'         = 91; 'Magenta'     = 95; 'Yellow'      = 93; 'White'       = 97
}

function Get-AnsiSgr {
    param([string]$Fg, [string]$Bg)
    $f = $script:AnsiColor[$Fg]; if ($null -eq $f) { $f = 37 }
    $b = $script:AnsiColor[$Bg]; if ($null -eq $b) { $b = 30 }
    $b += 10
    return "$script:ESC[${f};${b}m"
}

function Begin-Frame {
    [void]$script:FrameBuffer.Clear()
    [void]$script:FrameBuffer.Append("$script:ESC[?25l")
}

function End-Frame {
    try {
        $w = [Console]::WindowWidth; $h = [Console]::WindowHeight
        [void]$script:FrameBuffer.Append("$script:ESC[${h};${w}H")
    } catch {}
    [Console]::Write($script:FrameBuffer.ToString())
    [void]$script:FrameBuffer.Clear()
}

function Invoke-Op {
    param([string]$Action, [string]$Hive = '', [string]$SubKey = '', [string]$Extra = '')
    if ($script:IsRemote) {
        return Invoke-Command -Session $script:Session -ScriptBlock $script:OpsBlock `
            -ArgumentList $Action, $Hive, $SubKey, $Extra
    }
    return & $script:OpsBlock $Action $Hive $SubKey $Extra
}

# -----------------------------------------------------------------------------
# State
# -----------------------------------------------------------------------------
$HiveAliases = @{
    'HKLM' = 'LocalMachine'; 'HKCU' = 'CurrentUser';  'HKCR' = 'ClassesRoot'
    'HKU'  = 'Users';        'HKCC' = 'CurrentConfig'
}
$HiveShort = @{
    'LocalMachine' = 'HKLM'; 'CurrentUser' = 'HKCU'; 'ClassesRoot' = 'HKCR'
    'Users'        = 'HKU';  'CurrentConfig' = 'HKCC'
}
$HiveList = 'HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC'

$script:Hive       = $null
$script:Path       = ''
$script:Subkeys    = @()
$script:Values     = @()
$script:Pane       = 'keys'   # 'keys' | 'values'
$script:KeyIdx     = 0
$script:ValIdx     = 0
$script:KeyScroll  = 0
$script:ValScroll  = 0
$script:Status     = ''
$script:LastError  = ''

# -----------------------------------------------------------------------------
# Drawing primitives
# -----------------------------------------------------------------------------
function Write-At {
    param([int]$Col, [int]$Row, [string]$Text, $Fg = 'Gray', $Bg = 'Black')
    try {
        if ($Row -lt 0 -or $Row -ge [Console]::WindowHeight) { return }
        if ($Col -lt 0 -or $Col -ge [Console]::WindowWidth) { return }
    } catch { return }
    $sgr = Get-AnsiSgr $Fg $Bg
    $reset = "$script:ESC[0m"
    [void]$script:FrameBuffer.Append("$script:ESC[$($Row + 1);$($Col + 1)H$sgr$Text$reset")
}

function Write-Row {
    param([int]$Row, [string]$Text, $Fg, $Bg, [int]$Width)
    if ($Text.Length -gt $Width) { $Text = $Text.Substring(0, $Width) }
    elseif ($Text.Length -lt $Width) { $Text = $Text.PadRight($Width) }
    Write-At 0 $Row $Text $Fg $Bg
}

function Format-InlineData {
    param($d)
    if ($null -eq $d) { return '<null>' }
    if ($d -is [byte[]]) {
        $take = [Math]::Min(8, $d.Length)
        $hex = ($d[0..($take - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
        if ($d.Length -gt 8) { $hex += " ... ($($d.Length)B)" }
        return $hex
    }
    if ($d -is [array]) { return ($d -join ' | ') }
    return "$d"
}

function Get-DisplayPath {
    if (-not $script:Hive) { return '\' }
    $h = $HiveShort[$script:Hive]
    if ($script:Path) { return "$h\$($script:Path)" }
    return $h
}

# -----------------------------------------------------------------------------
# State management
# -----------------------------------------------------------------------------
function Update-Listing {
    $script:LastError = ''
    if (-not $script:Hive) {
        $script:Subkeys = @($HiveList)
        $script:Values  = @()
    } else {
        $r = Invoke-Op 'list' $script:Hive $script:Path
        if ($r.error) {
            $script:Subkeys = @()
            $script:Values  = @()
            $script:LastError = $r.error
        } else {
            $script:Subkeys = @($r.subkeys)
            $script:Values  = @($r.values)
        }
    }
    $script:KeyIdx = 0
    $script:ValIdx = 0
    $script:KeyScroll = 0
    $script:ValScroll = 0
    if (-not $script:Hive) { $script:Pane = 'keys' }
}

function Get-KeyList {
    if (-not $script:Hive) { return ,@($HiveList) }
    return ,@(,'[..]' + $script:Subkeys)
}

# -----------------------------------------------------------------------------
# Screen rendering
# -----------------------------------------------------------------------------
function Redraw {
    Begin-Frame
    $w = [Console]::WindowWidth
    $h = [Console]::WindowHeight
    $leftW  = [Math]::Max(20, [Math]::Floor($w * 0.4))
    $rightW = $w - $leftW - 1
    $contentStart = 3
    $contentEnd   = $h - 3
    $rows = $contentEnd - $contentStart + 1
    if ($rows -lt 1) { $rows = 1 }

    # Title bar
    $scope = if ($script:IsRemote) { "remote: $ComputerName" } else { 'local' }
    $title = " Registry TUI  [$scope]"
    Write-Row 0 $title 'White' 'DarkBlue' $w

    # Path bar
    $path = ' ' + (Get-DisplayPath)
    Write-Row 1 $path 'Black' 'Gray' $w

    # Column header row
    $hdrKeys = if ($script:Pane -eq 'keys') { ' Subkeys ' } else { ' Subkeys ' }
    $hdrVals = if ($script:Pane -eq 'values') { ' Values ' } else { ' Values ' }
    $fgK = if ($script:Pane -eq 'keys') { 'Black' } else { 'Gray' }
    $bgK = if ($script:Pane -eq 'keys') { 'Yellow' } else { 'DarkGray' }
    $fgV = if ($script:Pane -eq 'values') { 'Black' } else { 'Gray' }
    $bgV = if ($script:Pane -eq 'values') { 'Yellow' } else { 'DarkGray' }
    Write-At 0 2 (''.PadRight($leftW)) 'Gray' 'Black'
    Write-At 0 2 $hdrKeys.PadRight($leftW) $fgK $bgK
    Write-At $leftW 2 '|' 'DarkGray' 'Black'
    Write-At ($leftW + 1) 2 $hdrVals.PadRight($rightW) $fgV $bgV

    # Adjust scroll windows
    $keys = Get-KeyList
    if ($script:KeyIdx -lt $script:KeyScroll) { $script:KeyScroll = $script:KeyIdx }
    elseif ($script:KeyIdx -ge $script:KeyScroll + $rows) { $script:KeyScroll = $script:KeyIdx - $rows + 1 }
    if ($script:ValIdx -lt $script:ValScroll) { $script:ValScroll = $script:ValIdx }
    elseif ($script:ValIdx -ge $script:ValScroll + $rows) { $script:ValScroll = $script:ValIdx - $rows + 1 }

    # Keys pane
    for ($i = 0; $i -lt $rows; $i++) {
        $idx = $i + $script:KeyScroll
        $row = $contentStart + $i
        $name = if ($idx -lt $keys.Count) { $keys[$idx] } else { '' }
        $text = if ($name) { ' ' + $name } else { '' }
        $isSel = ($idx -eq $script:KeyIdx -and $idx -lt $keys.Count)
        if ($isSel -and $script:Pane -eq 'keys') {
            Write-Row-Segment 0 $row $text 'Black' 'Cyan' $leftW
        } elseif ($isSel) {
            Write-Row-Segment 0 $row $text 'White' 'DarkGray' $leftW
        } else {
            $fg = if ($name) { 'Yellow' } else { 'Gray' }
            Write-Row-Segment 0 $row $text $fg 'Black' $leftW
        }
        Write-At $leftW $row '|' 'DarkGray' 'Black'
    }

    # Values pane
    for ($i = 0; $i -lt $rows; $i++) {
        $idx = $i + $script:ValScroll
        $row = $contentStart + $i
        $col = $leftW + 1
        if ($idx -ge $script:Values.Count) {
            Write-Row-Segment $col $row '' 'Gray' 'Black' $rightW
            continue
        }
        $v = $script:Values[$idx]
        $name = if ($v.Name) { $v.Name } else { '(Default)' }
        $kind = "$($v.Kind)"
        $data = Format-InlineData $v.Data
        $nameCol = [Math]::Min(28, [Math]::Floor($rightW * 0.4))
        $kindCol = 10
        $dataCol = $rightW - $nameCol - $kindCol - 4
        $n = if ($name.Length -gt $nameCol) { $name.Substring(0, $nameCol - 1) + '~' } else { $name }
        $k = if ($kind.Length -gt $kindCol) { $kind.Substring(0, $kindCol) } else { $kind }
        $d = if ($data.Length -gt $dataCol) { $data.Substring(0, [Math]::Max(0, $dataCol - 1)) + '~' } else { $data }
        $text = ' ' + $n.PadRight($nameCol) + ' ' + $k.PadRight($kindCol) + ' ' + $d
        $isSel = ($idx -eq $script:ValIdx)
        if ($isSel -and $script:Pane -eq 'values') {
            Write-Row-Segment $col $row $text 'Black' 'Cyan' $rightW
        } elseif ($isSel) {
            Write-Row-Segment $col $row $text 'White' 'DarkGray' $rightW
        } else {
            Write-Row-Segment $col $row $text 'Gray' 'Black' $rightW
        }
    }

    # Status line
    $statusRow = $h - 2
    $msg = if ($script:LastError) { $script:LastError } else { $script:Status }
    $fg = if ($script:LastError) { 'White' } else { 'Yellow' }
    $bg = if ($script:LastError) { 'DarkRed' } else { 'Black' }
    Write-Row $statusRow (' ' + $msg) $fg $bg $w

    # Help bar
    $help = ' Up/Dn move   Lt/Rt/Tab pane   Enter descend   Bksp up   v view   / find   g go   r refresh   q quit'
    Write-Row ($h - 1) $help 'Black' 'Gray' $w
    End-Frame
}

function Write-Row-Segment {
    param([int]$Col, [int]$Row, [string]$Text, $Fg, $Bg, [int]$Width)
    if ($Text.Length -gt $Width) { $Text = $Text.Substring(0, $Width) }
    elseif ($Text.Length -lt $Width) { $Text = $Text.PadRight($Width) }
    Write-At $Col $Row $Text $Fg $Bg
}

# -----------------------------------------------------------------------------
# Inline input (bottom status line). Blocking line editor.
# -----------------------------------------------------------------------------
function Read-Inline {
    param([string]$Prompt)
    $w = [Console]::WindowWidth
    $row = [Console]::WindowHeight - 2
    $buffer = New-Object System.Text.StringBuilder
    $cursor = 0
    $promptLen = $Prompt.Length + 1
    while ($true) {
        Begin-Frame
        Write-Row $row (' ' + $Prompt + $buffer.ToString()) 'Black' 'Yellow' $w
        # Place cursor at input position and make visible in the same buffer flush
        [void]$script:FrameBuffer.Append("$script:ESC[$($row + 1);$($promptLen + $cursor + 1)H")
        [void]$script:FrameBuffer.Append("$script:ESC[?25h")
        [Console]::Write($script:FrameBuffer.ToString())
        [void]$script:FrameBuffer.Clear()
        $k = [Console]::ReadKey($true)
        Hide-Cursor
        switch ($k.Key) {
            ([ConsoleKey]::Enter)  { return $buffer.ToString() }
            ([ConsoleKey]::Escape) { return $null }
            ([ConsoleKey]::Backspace) {
                if ($cursor -gt 0) { [void]$buffer.Remove($cursor - 1, 1); $cursor-- }
            }
            ([ConsoleKey]::Delete) {
                if ($cursor -lt $buffer.Length) { [void]$buffer.Remove($cursor, 1) }
            }
            ([ConsoleKey]::LeftArrow)  { if ($cursor -gt 0) { $cursor-- } }
            ([ConsoleKey]::RightArrow) { if ($cursor -lt $buffer.Length) { $cursor++ } }
            ([ConsoleKey]::Home)       { $cursor = 0 }
            ([ConsoleKey]::End)        { $cursor = $buffer.Length }
            default {
                $ch = $k.KeyChar
                if ($ch -and [int]$ch -ge 32 -and [int]$ch -ne 127) {
                    [void]$buffer.Insert($cursor, $ch); $cursor++
                }
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Value detail modal
# -----------------------------------------------------------------------------
function Show-ValueModal {
    param($v)
    [Console]::Clear()
    Begin-Frame
    $w = [Console]::WindowWidth
    $h = [Console]::WindowHeight
    $name = if ($v.Name) { $v.Name } else { '(Default)' }
    Write-Row 0 " Value: $name" 'White' 'DarkBlue' $w
    Write-Row 1 " Path: $(Get-DisplayPath)" 'Black' 'Gray' $w
    Write-At 2 3 "Kind: $($v.Kind)" 'Cyan' 'Black'
    Write-At 2 5 'Data:' 'Cyan' 'Black'

    $row = 6
    $max = $h - 2
    $d = $v.Data
    if ($d -is [byte[]]) {
        for ($i = 0; $i -lt $d.Length -and $row -lt $max; $i += 16) {
            $end = [Math]::Min($i + 15, $d.Length - 1)
            $bytes = $d[$i..$end]
            $hex = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ' '
            $asc = ($bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } }) -join ''
            $line = "{0:X8}  {1,-48}  {2}" -f $i, $hex, $asc
            Write-At 2 $row $line 'Gray' 'Black'; $row++
        }
        if ($row -ge $max -and ($d.Length - $i) -gt 0) {
            Write-At 2 $row "  ... truncated ($($d.Length) bytes total)" 'DarkGray' 'Black'
        }
    } elseif ($d -is [array]) {
        foreach ($item in $d) {
            if ($row -ge $max) { break }
            Write-At 2 $row "  $item" 'Gray' 'Black'; $row++
        }
    } else {
        $s = "$d"
        $ww = $w - 4
        while ($s.Length -gt 0 -and $row -lt $max) {
            $chunk = if ($s.Length -le $ww) { $s } else { $s.Substring(0, $ww) }
            Write-At 2 $row $chunk 'Gray' 'Black'; $row++
            if ($s.Length -le $ww) { break }
            $s = $s.Substring($ww)
        }
    }
    Write-Row ($h - 1) ' Press any key to return' 'Black' 'Gray' $w
    End-Frame
    [Console]::ReadKey($true) | Out-Null
    [Console]::Clear()
}

# -----------------------------------------------------------------------------
# Actions
# -----------------------------------------------------------------------------
function Invoke-Descend {
    $keys = Get-KeyList
    if ($script:KeyIdx -ge $keys.Count) { return }
    $sel = $keys[$script:KeyIdx]
    if ($sel -eq '[..]') { Invoke-GoUp; return }
    if (-not $script:Hive) {
        $script:Hive = $HiveAliases[$sel]
        $script:Path = ''
    } else {
        $newPath = if ($script:Path) { "$($script:Path)\$sel" } else { $sel }
        if (-not (Invoke-Op 'exists' $script:Hive $newPath)) {
            $script:LastError = "Access denied or missing: $newPath"
            return
        }
        $script:Path = $newPath
    }
    Update-Listing
}

function Invoke-GoUp {
    if (-not $script:Hive) { return }
    if ($script:Path) {
        $segs = $script:Path -split '\\'
        if ($segs.Count -le 1) { $script:Path = '' }
        else { $script:Path = ($segs[0..($segs.Count - 2)]) -join '\' }
    } else {
        $script:Hive = $null
    }
    Update-Listing
}

function Invoke-GoTo {
    $input = Read-Inline 'Go to: '
    if (-not $input) { return }
    $input = $input.Trim().TrimEnd('\', '/')
    if (-not $input) { return }
    $parts = $input.Split('\', 2)
    $first = $parts[0]
    $rest  = if ($parts.Length -gt 1) { $parts[1] } else { '' }
    if (-not $HiveAliases.ContainsKey($first.ToUpper())) {
        $script:LastError = "Expected HKLM/HKCU/HKCR/HKU/HKCC prefix, got: $first"; return
    }
    $hive = $HiveAliases[$first.ToUpper()]
    if (-not (Invoke-Op 'exists' $hive $rest)) {
        $script:LastError = "Path not found: $input"; return
    }
    $script:Hive = $hive; $script:Path = $rest
    Update-Listing
}

function Invoke-Find {
    $pat = Read-Inline 'Find (regex): '
    if (-not $pat) { return }
    if (-not $script:Hive) {
        $script:LastError = 'Select a hive before searching.'; return
    }
    $script:Status = "Searching ..."
    Redraw
    $results = Invoke-Op 'find' $script:Hive $script:Path $pat
    if (-not $results -or $results.Count -eq 0) {
        $script:Status = '(no matches)'; return
    }
    Show-FindResults $results
}

function Show-FindResults {
    param($results)
    $idx = 0
    $scroll = 0
    while ($true) {
        Begin-Frame
        $w = [Console]::WindowWidth
        $h = [Console]::WindowHeight
        Write-Row 0 " Find results: $($results.Count)" 'White' 'DarkBlue' $w
        Write-Row 1 ' Enter: jump | Esc: back | Up/Dn: move' 'Black' 'Gray' $w
        $rows = $h - 4
        if ($idx -lt $scroll) { $scroll = $idx }
        elseif ($idx -ge $scroll + $rows) { $scroll = $idx - $rows + 1 }
        for ($i = 0; $i -lt $rows; $i++) {
            $r = $scroll + $i
            $row = 3 + $i
            if ($r -ge $results.Count) { Write-Row-Segment 0 $row '' 'Gray' 'Black' $w; continue }
            $it = $results[$r]
            $p = if ($it.Path) { $it.Path } else { '' }
            $text = " [$($it.Kind)] $($HiveShort[$script:Hive])\$p\ >> $($it.Name)"
            if ($r -eq $idx) {
                Write-Row-Segment 0 $row $text 'Black' 'Cyan' $w
            } else {
                Write-Row-Segment 0 $row $text 'Gray' 'Black' $w
            }
        }
        End-Frame
        $k = [Console]::ReadKey($true)
        switch ($k.Key) {
            ([ConsoleKey]::Escape)    { [Console]::Clear(); return }
            ([ConsoleKey]::Q)         { [Console]::Clear(); return }
            ([ConsoleKey]::UpArrow)   { if ($idx -gt 0) { $idx-- } }
            ([ConsoleKey]::DownArrow) { if ($idx -lt $results.Count - 1) { $idx++ } }
            ([ConsoleKey]::Home)      { $idx = 0 }
            ([ConsoleKey]::End)       { $idx = $results.Count - 1 }
            ([ConsoleKey]::PageUp)    { $idx = [Math]::Max(0, $idx - $rows) }
            ([ConsoleKey]::PageDown)  { $idx = [Math]::Min($results.Count - 1, $idx + $rows) }
            ([ConsoleKey]::Enter) {
                $it = $results[$idx]
                $script:Path = $it.Path
                Update-Listing
                if ($it.Kind -eq 'Key') {
                    $target = $it.Name
                    $kidx = ([array]::IndexOf($script:Subkeys, $target))
                    if ($kidx -ge 0) { $script:KeyIdx = $kidx + 1 }  # +1 for [..]
                    $script:Pane = 'keys'
                } else {
                    $vidx = 0
                    for ($i = 0; $i -lt $script:Values.Count; $i++) {
                        if ($script:Values[$i].Name -eq $it.Name) { $vidx = $i; break }
                    }
                    $script:ValIdx = $vidx
                    $script:Pane = 'values'
                }
                [Console]::Clear()
                return
            }
        }
    }
}

function Invoke-ViewValue {
    if ($script:Pane -ne 'values') { return }
    if ($script:ValIdx -ge $script:Values.Count) { return }
    Show-ValueModal $script:Values[$script:ValIdx]
}

# -----------------------------------------------------------------------------
# Main loop
# -----------------------------------------------------------------------------
if ($script:IsRemote) {
    Write-Host "Connecting to $ComputerName via WinRM..." -ForegroundColor DarkGray
    $p = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
    if ($Credential) { $p.Credential = $Credential }
    if ($UseSSL)     { $p.UseSSL = $true }
    $script:Session = New-PSSession @p
}

$origTitle = $null
try {
    try { $origTitle = [Console]::Title } catch {}
    try { [Console]::Title = 'Registry TUI' } catch {}
    Hide-Cursor
    [Console]::Clear()
    Update-Listing

    while ($true) {
        Redraw
        $k = [Console]::ReadKey($true)
        $script:Status = ''
        $script:LastError = ''
        $keys = Get-KeyList

        $rows = [Console]::WindowHeight - 5

        if ($k.Modifiers -band [ConsoleModifiers]::Control -and $k.Key -eq [ConsoleKey]::C) { break }

        switch ($k.Key) {
            ([ConsoleKey]::Q)          { return }
            ([ConsoleKey]::Escape)     { return }
            ([ConsoleKey]::Tab)        { $script:Pane = if ($script:Pane -eq 'keys') { 'values' } else { 'keys' } }
            ([ConsoleKey]::LeftArrow)  { $script:Pane = 'keys' }
            ([ConsoleKey]::RightArrow) { if ($script:Values.Count -gt 0) { $script:Pane = 'values' } }
            ([ConsoleKey]::UpArrow) {
                if ($script:Pane -eq 'keys') { if ($script:KeyIdx -gt 0) { $script:KeyIdx-- } }
                else { if ($script:ValIdx -gt 0) { $script:ValIdx-- } }
            }
            ([ConsoleKey]::DownArrow) {
                if ($script:Pane -eq 'keys') { if ($script:KeyIdx -lt $keys.Count - 1) { $script:KeyIdx++ } }
                else { if ($script:ValIdx -lt $script:Values.Count - 1) { $script:ValIdx++ } }
            }
            ([ConsoleKey]::Home) {
                if ($script:Pane -eq 'keys') { $script:KeyIdx = 0 } else { $script:ValIdx = 0 }
            }
            ([ConsoleKey]::End) {
                if ($script:Pane -eq 'keys') { $script:KeyIdx = [Math]::Max(0, $keys.Count - 1) }
                else { $script:ValIdx = [Math]::Max(0, $script:Values.Count - 1) }
            }
            ([ConsoleKey]::PageUp) {
                if ($script:Pane -eq 'keys') { $script:KeyIdx = [Math]::Max(0, $script:KeyIdx - $rows) }
                else { $script:ValIdx = [Math]::Max(0, $script:ValIdx - $rows) }
            }
            ([ConsoleKey]::PageDown) {
                if ($script:Pane -eq 'keys') { $script:KeyIdx = [Math]::Min($keys.Count - 1, $script:KeyIdx + $rows) }
                else { $script:ValIdx = [Math]::Min($script:Values.Count - 1, $script:ValIdx + $rows) }
            }
            ([ConsoleKey]::Enter)     { if ($script:Pane -eq 'keys') { Invoke-Descend } else { Invoke-ViewValue } }
            ([ConsoleKey]::Backspace) { Invoke-GoUp }
            ([ConsoleKey]::R)         { [Console]::Clear(); Update-Listing }
            ([ConsoleKey]::V)         { Invoke-ViewValue }
            ([ConsoleKey]::Oem2)      { Invoke-Find }
            ([ConsoleKey]::G)         { Invoke-GoTo }
            default { }
        }
    }
}
finally {
    Show-Cursor
    try { [Console]::ResetColor() } catch {}
    try { [Console]::Clear() } catch {}
    if ($origTitle) { try { [Console]::Title = $origTitle } catch {} }
    if ($script:Session) { Remove-PSSession $script:Session -ErrorAction SilentlyContinue }
}
