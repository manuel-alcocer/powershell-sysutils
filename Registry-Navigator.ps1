<#
.SYNOPSIS
    Interactive Windows Registry navigator. Works locally or over WinRM.

.DESCRIPTION
    Lightweight REPL to browse registry keys/values. Remote mode uses
    PowerShell Remoting (WinRM); each command is dispatched via
    Invoke-Command against a persistent PSSession.

.PARAMETER ComputerName
    Target host for remote mode. Omit to browse local machine.

.PARAMETER Credential
    Credential for the remote session.

.PARAMETER UseSSL
    Use HTTPS (WinRM 5986) instead of HTTP (5985).

.EXAMPLE
    # Local
    .\Registry-Navigator.ps1

.EXAMPLE
    # Remote (e.g. from 192.168.122.64 targeting 192.168.122.3)
    $cred = Get-Credential administrator
    .\Registry-Navigator.ps1 -ComputerName 192.168.122.3 -Credential $cred

.NOTES
    Prereqs for remote mode (on the *source* machine, once):
        Enable-PSRemoting -Force
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.122.3' -Force
    And on the *target* machine:
        Enable-PSRemoting -Force
#>
[CmdletBinding()]
param(
    [string]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$UseSSL
)

$script:Session = $null
$script:IsRemote = [bool]$ComputerName

# -----------------------------------------------------------------------------
# Remote-safe operations. Single script block dispatched on demand. Stateless:
# each call reopens the target key. Keeps wire protocol simple.
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
        'get' {
            $k = Open-Key $Hive $SubKey
            if (-not $k) { return @{ error = "Key not found" } }
            $names = $k.GetValueNames()
            $match = $names | Where-Object { $_ -ieq $Extra } | Select-Object -First 1
            if ($null -eq $match) { $k.Close(); return @{ error = "Value not found: $Extra" } }
            $kind = $k.GetValueKind($match)
            $data = $k.GetValue($match, $null, 'DoNotExpandEnvironmentNames')
            $k.Close()
            return @{ name = $match; kind = "$kind"; data = $data }
        }
        'find' {
            $results = New-Object System.Collections.Generic.List[object]
            $root = Open-Key $Hive $SubKey
            if (-not $root) { return @() }
            $pat = [regex]::new($Extra, 'IgnoreCase')
            $stack = New-Object System.Collections.Generic.Stack[object]
            $stack.Push(@{ Key = $root; Path = $SubKey; IsRoot = $true })
            $limit = 500
            while ($stack.Count -gt 0 -and $results.Count -lt $limit) {
                $cur = $stack.Pop()
                try {
                    foreach ($n in $cur.Key.GetValueNames()) {
                        if ($pat.IsMatch($n)) {
                            $results.Add([pscustomobject]@{
                                Path = $cur.Path; Kind = 'Value'; Name = $n
                            })
                            if ($results.Count -ge $limit) { break }
                        }
                    }
                    foreach ($sn in $cur.Key.GetSubKeyNames()) {
                        if ($pat.IsMatch($sn)) {
                            $results.Add([pscustomobject]@{
                                Path = $cur.Path; Kind = 'Key'; Name = $sn
                            })
                            if ($results.Count -ge $limit) { break }
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

function Invoke-Op {
    param([string]$Action, [string]$Hive = '', [string]$SubKey = '', [string]$Extra = '')
    if ($script:IsRemote) {
        return Invoke-Command -Session $script:Session -ScriptBlock $script:OpsBlock `
            -ArgumentList $Action, $Hive, $SubKey, $Extra
    }
    return & $script:OpsBlock $Action $Hive $SubKey $Extra
}

# -----------------------------------------------------------------------------
# Client-side navigation state and helpers
# -----------------------------------------------------------------------------
$script:Hive = $null    # e.g. 'LocalMachine'
$script:Path = ''       # e.g. 'SOFTWARE\Microsoft'

$HiveAliases = @{
    'HKLM' = 'LocalMachine'; 'HKEY_LOCAL_MACHINE' = 'LocalMachine'
    'HKCU' = 'CurrentUser';  'HKEY_CURRENT_USER'  = 'CurrentUser'
    'HKCR' = 'ClassesRoot';  'HKEY_CLASSES_ROOT'  = 'ClassesRoot'
    'HKU'  = 'Users';        'HKEY_USERS'         = 'Users'
    'HKCC' = 'CurrentConfig';'HKEY_CURRENT_CONFIG'= 'CurrentConfig'
}
$HiveShort = @{
    'LocalMachine' = 'HKLM'; 'CurrentUser' = 'HKCU'; 'ClassesRoot' = 'HKCR'
    'Users'        = 'HKU';  'CurrentConfig' = 'HKCC'
}

# -----------------------------------------------------------------------------
# Completion cache: caches current-location listing to serve Tab completions
# without remote round-trips per keystroke. Invalidated whenever cd changes.
# -----------------------------------------------------------------------------
$script:Cache = @{ Key = $null; Subkeys = @(); Values = @() }

function Clear-CompletionCache {
    $script:Cache = @{ Key = $null; Subkeys = @(); Values = @() }
}

function Get-CachedListing {
    if (-not $script:Hive) { return @{ Subkeys = @(); Values = @() } }
    $key = "$($script:Hive)|$($script:Path)"
    if ($script:Cache.Key -ne $key) {
        $r = Invoke-Op 'list' $script:Hive $script:Path
        if (-not $r -or $r.error) {
            $script:Cache = @{ Key = $key; Subkeys = @(); Values = @() }
        } else {
            $valNames = @()
            if ($r.values) { $valNames = @($r.values | ForEach-Object { $_.Name }) }
            $script:Cache = @{ Key = $key; Subkeys = @($r.subkeys); Values = $valNames }
        }
    }
    return $script:Cache
}

function Get-CommonPrefix {
    param([string[]]$Strings)
    if (-not $Strings -or $Strings.Count -eq 0) { return '' }
    if ($Strings.Count -eq 1) { return $Strings[0] }
    $min = ($Strings | Measure-Object -Property Length -Minimum).Minimum
    $prefix = ''
    for ($i = 0; $i -lt $min; $i++) {
        $c = $Strings[0][$i]
        foreach ($s in $Strings) {
            if ([char]::ToLower($s[$i]) -ne [char]::ToLower($c)) { return $prefix }
        }
        $prefix += $c
    }
    return $prefix
}

function Get-CdCompletions {
    param([string]$Prefix)
    $bs = $Prefix.LastIndexOf('\')
    if ($bs -lt 0) {
        if (-not $script:Hive) {
            $hives = 'HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC'
            return @($hives | Where-Object { $_.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase) } | Sort-Object)
        }
        $subs = (Get-CachedListing).Subkeys
        return @($subs | Where-Object { $_.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase) } | Sort-Object)
    }
    $parentPart = $Prefix.Substring(0, $bs)
    $last       = $Prefix.Substring($bs + 1)

    $parts = $parentPart.Split('\', 2)
    $first = $parts[0]
    if ($HiveAliases.ContainsKey($first.ToUpper())) {
        $hive = $HiveAliases[$first.ToUpper()]
        $path = if ($parts.Length -gt 1) { $parts[1] } else { '' }
    } else {
        if (-not $script:Hive) { return @() }
        $hive = $script:Hive
        $path = if ($script:Path) { "$($script:Path)\$parentPart" } else { $parentPart }
    }
    $r = Invoke-Op 'list' $hive $path
    if (-not $r -or $r.error) { return @() }
    $matches = @($r.subkeys | Where-Object { $_.StartsWith($last, [System.StringComparison]::OrdinalIgnoreCase) } | Sort-Object)
    return @($matches | ForEach-Object { "$parentPart\$_" })
}

function Get-ValueCompletions {
    param([string]$Prefix)
    if (-not $script:Hive) { return @() }
    $vals = (Get-CachedListing).Values
    return @($vals | Where-Object { $_.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase) } | Sort-Object)
}

function Get-Completions {
    param([string]$Buffer, [int]$Cursor)
    $head = $Buffer.Substring(0, $Cursor)
    $tokStart = $head.LastIndexOf(' ') + 1
    $tokPrefix = $head.Substring($tokStart)
    $firstSpace = $Buffer.IndexOf(' ')
    $isCommand = ($firstSpace -lt 0) -or ($Cursor -le $firstSpace)
    if ($isCommand) {
        $cmds = 'cat', 'cd', 'clear', 'cls', 'dir', 'exit', 'find', 'get', 'help', 'ls', 'pwd', 'quit', 'tree'
        $matches = @($cmds | Where-Object { $_.StartsWith($tokPrefix, [System.StringComparison]::OrdinalIgnoreCase) })
        return @{ Prefix = $tokPrefix; Matches = $matches; TokStart = $tokStart }
    }
    $cmd = $Buffer.Substring(0, $firstSpace).ToLower()
    $matches = switch ($cmd) {
        'cd'   { Get-CdCompletions $tokPrefix }
        'ls'   { Get-CdCompletions $tokPrefix }
        'dir'  { Get-CdCompletions $tokPrefix }
        'tree' { Get-CdCompletions $tokPrefix }
        'cat'  { Get-ValueCompletions $tokPrefix }
        'get'  { Get-ValueCompletions $tokPrefix }
        default { @() }
    }
    return @{ Prefix = $tokPrefix; Matches = @($matches); TokStart = $tokStart }
}

# -----------------------------------------------------------------------------
# Custom line reader with Tab completion, Backspace, arrows, Home/End, Ctrl+C.
# -----------------------------------------------------------------------------
function Read-InputLine {
    param([string]$Prompt)

    Write-Host -NoNewline $Prompt -ForegroundColor Cyan
    $promptLen = $Prompt.Length
    $buffer = New-Object System.Text.StringBuilder
    $cursor = 0
    $row = [Console]::CursorTop

    $redraw = {
        [Console]::SetCursorPosition($promptLen, $row)
        $text = $buffer.ToString()
        [Console]::Write($text)
        $winW = [Console]::WindowWidth
        $trail = $winW - $promptLen - $text.Length - 1
        if ($trail -gt 0) { [Console]::Write((' ' * $trail)) }
        $pos = $promptLen + $cursor
        if ($pos -ge $winW) { $pos = $winW - 1 }
        [Console]::SetCursorPosition($pos, $row)
    }

    while ($true) {
        $k = [Console]::ReadKey($true)

        if ($k.Modifiers -band [ConsoleModifiers]::Control -and $k.Key -eq [ConsoleKey]::C) {
            [Console]::SetCursorPosition($promptLen + $buffer.Length, $row)
            Write-Host '^C'
            return ''
        }

        switch ($k.Key) {
            ([ConsoleKey]::Enter) {
                [Console]::SetCursorPosition($promptLen + $buffer.Length, $row)
                Write-Host ''
                return $buffer.ToString()
            }
            ([ConsoleKey]::Backspace) {
                if ($cursor -gt 0) {
                    [void]$buffer.Remove($cursor - 1, 1)
                    $cursor--
                    & $redraw
                }
            }
            ([ConsoleKey]::Delete) {
                if ($cursor -lt $buffer.Length) {
                    [void]$buffer.Remove($cursor, 1)
                    & $redraw
                }
            }
            ([ConsoleKey]::LeftArrow) {
                if ($cursor -gt 0) { $cursor--; & $redraw }
            }
            ([ConsoleKey]::RightArrow) {
                if ($cursor -lt $buffer.Length) { $cursor++; & $redraw }
            }
            ([ConsoleKey]::Home) { $cursor = 0; & $redraw }
            ([ConsoleKey]::End)  { $cursor = $buffer.Length; & $redraw }
            ([ConsoleKey]::Escape) {
                [void]$buffer.Clear(); $cursor = 0; & $redraw
            }
            ([ConsoleKey]::Tab) {
                $c = Get-Completions $buffer.ToString() $cursor
                if (-not $c.Matches -or $c.Matches.Count -eq 0) { break }
                $common = Get-CommonPrefix $c.Matches
                if ($common.Length -gt $c.Prefix.Length) {
                    $insert = $common.Substring($c.Prefix.Length)
                    [void]$buffer.Insert($cursor, $insert)
                    $cursor += $insert.Length
                    if ($c.Matches.Count -eq 1) {
                        [void]$buffer.Insert($cursor, ' ')
                        $cursor++
                    }
                    & $redraw
                } elseif ($c.Matches.Count -eq 1) {
                    [void]$buffer.Insert($cursor, ' ')
                    $cursor++
                    & $redraw
                } else {
                    Write-Host ''
                    $line = ''
                    foreach ($m in $c.Matches) {
                        if (($line.Length + $m.Length + 2) -gt ([Console]::WindowWidth - 2)) {
                            Write-Host "  $line"
                            $line = ''
                        }
                        $line += $m + '  '
                    }
                    if ($line) { Write-Host "  $line" }
                    Write-Host -NoNewline $Prompt -ForegroundColor Cyan
                    [Console]::Write($buffer.ToString())
                    $row = [Console]::CursorTop
                    [Console]::SetCursorPosition($promptLen + $cursor, $row)
                }
            }
            default {
                $ch = $k.KeyChar
                if ($ch -and [int]$ch -ge 32 -and [int]$ch -ne 127) {
                    [void]$buffer.Insert($cursor, $ch)
                    $cursor++
                    & $redraw
                }
            }
        }
    }
}

function Format-Data {
    param($d)
    if ($null -eq $d)       { return '<null>' }
    if ($d -is [byte[]])    {
        $hex = (($d | Select-Object -First 24 | ForEach-Object { $_.ToString('X2') }) -join ' ')
        if ($d.Length -gt 24) { $hex += " ... ($($d.Length) bytes)" }
        return $hex
    }
    if ($d -is [array])     { return (($d | ForEach-Object { "$_" }) -join ' | ') }
    $s = "$d"
    if ($s.Length -gt 120) { return $s.Substring(0, 120) + '...' }
    return $s
}

function Show-Help {
@'
Commands:
  ls | dir            List subkeys and values at current location
  cd <name>           Enter subkey (supports ..)
  cd <HIVE>[\path]    Jump to absolute location (HKLM, HKCU, HKCR, HKU, HKCC)
  cd \                Go to hive root selector
  pwd                 Print current path
  cat | get <value>   Show value data and type (case-insensitive)
  find <regex>        Search keys/values at or below current location (max 500)
  tree [depth]        Show subkey tree (default depth 2)
  cls | clear         Clear screen
  help | ?            Show this help
  quit | exit         Exit
'@
}

function Get-PromptText {
    if (-not $script:Hive) { return '\' }
    $h = $HiveShort[$script:Hive]
    if ($script:Path) { return "$h\$($script:Path)" }
    return $h
}

function Do-Ls {
    if (-not $script:Hive) {
        Write-Host 'Hives:' -ForegroundColor Cyan
        foreach ($k in 'HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC') {
            Write-Host "  $k"
        }
        return
    }
    $r = Invoke-Op 'list' $script:Hive $script:Path
    if ($r.error) { Write-Host $r.error -ForegroundColor Red; return }
    if ($r.subkeys -and $r.subkeys.Count -gt 0) {
        Write-Host 'Subkeys:' -ForegroundColor Cyan
        foreach ($s in $r.subkeys) { Write-Host "  [$s]" -ForegroundColor Yellow }
    }
    if ($r.values -and $r.values.Count -gt 0) {
        Write-Host 'Values:' -ForegroundColor Cyan
        $r.values |
            Select-Object Name, Kind, @{ N = 'Data'; E = { Format-Data $_.Data } } |
            Format-Table -AutoSize |
            Out-Host
    }
    if ((-not $r.subkeys -or $r.subkeys.Count -eq 0) -and (-not $r.values -or $r.values.Count -eq 0)) {
        Write-Host '(empty)' -ForegroundColor DarkGray
    }
}

function Do-Cd {
    param([string]$arg)
    if ([string]::IsNullOrWhiteSpace($arg)) { return }
    $arg = $arg.Trim().TrimEnd('\', '/')

    if ($arg -eq '\' -or $arg -eq '/' -or $arg -eq '') {
        $script:Hive = $null; $script:Path = ''; return
    }

    $parts = $arg.Split('\', 2)
    $first = $parts[0]
    $rest  = if ($parts.Length -gt 1) { $parts[1] } else { '' }
    if ($HiveAliases.ContainsKey($first.ToUpper())) {
        $newHive = $HiveAliases[$first.ToUpper()]
        if (-not (Invoke-Op 'exists' $newHive $rest)) {
            Write-Host "Path not found: $first\$rest" -ForegroundColor Red; return
        }
        $script:Hive = $newHive; $script:Path = $rest
        return
    }

    if (-not $script:Hive) {
        Write-Host "Not at a hive. Use: cd HKLM  (or HKCU, HKCR, HKU, HKCC)" -ForegroundColor Red
        return
    }

    if ($arg -eq '..') {
        if (-not $script:Path) { $script:Hive = $null; return }
        $segs = $script:Path -split '\\'
        if ($segs.Count -le 1) { $script:Path = '' }
        else { $script:Path = ($segs[0..($segs.Count - 2)]) -join '\' }
        return
    }

    $candidate = if ($script:Path) { "$($script:Path)\$arg" } else { $arg }
    if (-not (Invoke-Op 'exists' $script:Hive $candidate)) {
        Write-Host "Subkey not found: $arg" -ForegroundColor Red; return
    }
    $script:Path = $candidate
}

function Do-Cat {
    param([string]$name)
    if (-not $script:Hive) { Write-Host 'Not at a hive.' -ForegroundColor Red; return }
    if ([string]::IsNullOrWhiteSpace($name)) { Write-Host 'Usage: cat <valueName>' -ForegroundColor Red; return }
    $r = Invoke-Op 'get' $script:Hive $script:Path $name.Trim()
    if ($r.error) { Write-Host $r.error -ForegroundColor Red; return }
    Write-Host "Name: $($r.name)"
    Write-Host "Kind: $($r.kind)"
    Write-Host 'Data:'
    $d = $r.data
    if ($d -is [byte[]]) {
        $line = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt $d.Length; $i++) {
            [void]$line.Append($d[$i].ToString('X2')).Append(' ')
            if ((($i + 1) % 16) -eq 0) { Write-Host "  $($line.ToString())"; [void]$line.Clear() }
        }
        if ($line.Length -gt 0) { Write-Host "  $($line.ToString())" }
    } elseif ($d -is [array]) {
        foreach ($item in $d) { Write-Host "  $item" }
    } else {
        Write-Host "  $d"
    }
}

function Do-Find {
    param([string]$pat)
    if (-not $script:Hive) { Write-Host 'Not at a hive.' -ForegroundColor Red; return }
    if ([string]::IsNullOrWhiteSpace($pat)) { Write-Host 'Usage: find <regex>' -ForegroundColor Red; return }
    Write-Host 'Searching (max 500 results)...' -ForegroundColor DarkGray
    $results = Invoke-Op 'find' $script:Hive $script:Path $pat
    if (-not $results -or $results.Count -eq 0) {
        Write-Host '(no matches)' -ForegroundColor DarkGray; return
    }
    $results | Format-Table -AutoSize | Out-Host
    Write-Host "$($results.Count) result(s)." -ForegroundColor DarkGray
}

function Do-Tree {
    param([string]$depthStr)
    if (-not $script:Hive) { Write-Host 'Not at a hive.' -ForegroundColor Red; return }
    $d = 2
    if ($depthStr) { [int]::TryParse($depthStr, [ref]$d) | Out-Null }

    function Walk-Tree {
        param($relative, $prefix, $lvl)
        if ($lvl -le 0) { return }
        $full = if ($relative) {
            if ($script:Path) { "$($script:Path)\$relative" } else { $relative }
        } else { $script:Path }
        $r = Invoke-Op 'list' $script:Hive $full
        if (-not $r -or $r.error) { return }
        foreach ($s in $r.subkeys) {
            Write-Host "$prefix[$s]"
            $nextRel = if ($relative) { "$relative\$s" } else { $s }
            Walk-Tree $nextRel "$prefix  " ($lvl - 1)
        }
    }
    Walk-Tree '' '' $d
}

# -----------------------------------------------------------------------------
# Session bootstrap
# -----------------------------------------------------------------------------
if ($script:IsRemote) {
    Write-Host "Connecting to $ComputerName via WinRM..." -ForegroundColor DarkGray
    $params = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
    if ($Credential) { $params.Credential = $Credential }
    if ($UseSSL)     { $params.UseSSL = $true }
    $script:Session = New-PSSession @params
    Write-Host "Connected: $ComputerName" -ForegroundColor Green
}

Write-Host ''
$header = if ($script:IsRemote) { "Registry Navigator [remote: $ComputerName]" } else { 'Registry Navigator [local]' }
Write-Host $header -ForegroundColor Green
Write-Host "Type 'help' for commands, 'quit' to exit."
Write-Host ''

$inputRedirected = [Console]::IsInputRedirected

try {
    while ($true) {
        $prompt = '[' + (Get-PromptText) + '] > '
        if ($inputRedirected) {
            Write-Host -NoNewline $prompt -ForegroundColor Cyan
            $line = Read-Host
        } else {
            $line = Read-InputLine $prompt
        }
        if ($null -eq $line) { break }
        $line = $line.Trim()
        if (-not $line) { continue }

        $space = $line.IndexOf(' ')
        if ($space -lt 0) { $cmd = $line; $rest = '' }
        else { $cmd = $line.Substring(0, $space); $rest = $line.Substring($space + 1).Trim() }

        switch ($cmd.ToLower()) {
            { $_ -in 'quit', 'exit', 'q' } { return }
            { $_ -in 'help', '?' }         { Show-Help }
            { $_ -in 'ls', 'dir' }         { Do-Ls }
            'cd'                           { Do-Cd $rest }
            'pwd'                          { Write-Host (Get-PromptText) }
            { $_ -in 'cat', 'get' }        { Do-Cat $rest }
            'find'                         { Do-Find $rest }
            'tree'                         { Do-Tree $rest }
            { $_ -in 'cls', 'clear' }      { Clear-Host }
            default { Write-Host "Unknown command: $cmd  (type 'help')" -ForegroundColor Red }
        }
    }
}
finally {
    if ($script:Session) {
        Remove-PSSession $script:Session -ErrorAction SilentlyContinue
    }
}
