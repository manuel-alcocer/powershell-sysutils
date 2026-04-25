<#
.SYNOPSIS
    WinForms GUI for Invoke-DllSuiteAnalysis. Pick directories, scan,
    open the resulting HTML report.

.DESCRIPTION
    Minimal one-screen UI for sysadmins who need to run the analysis
    interactively rather than from a CI pipeline. Loads the SysUtils
    module from a sibling folder (release zip layout) or from any
    installed copy. The actual scan runs on the GUI thread - good
    enough for typical 100-DLL suites; for very large scans use the
    headless DllSuite-Run.ps1 from a console.
#>

$ErrorActionPreference = 'Stop'

# Resolve and load the module
$bundled = Join-Path $PSScriptRoot '..\SysUtils\SysUtils.psd1'
try {
    if (Test-Path $bundled) {
        Import-Module $bundled -Force -ErrorAction Stop
    } else {
        Import-Module SysUtils -Force -ErrorAction Stop
    }
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Cannot load SysUtils module:`r`n$($_.Exception.Message)",
        'SysUtils DLL Suite', 'OK', 'Error') | Out-Null
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ---- Build the form ----
$form = New-Object System.Windows.Forms.Form
$form.Text          = 'SysUtils - DLL Suite Analysis'
$form.Size          = New-Object System.Drawing.Size 760, 560
$form.MinimumSize   = New-Object System.Drawing.Size 560, 420
$form.StartPosition = 'CenterScreen'
$form.Font          = New-Object System.Drawing.Font 'Segoe UI', 9

# Paths group
$grpPaths = New-Object System.Windows.Forms.GroupBox
$grpPaths.Text     = 'Directories to scan'
$grpPaths.Location = New-Object System.Drawing.Point 12, 12
$grpPaths.Size     = New-Object System.Drawing.Size 720, 220
$grpPaths.Anchor   = 'Top, Left, Right'

$lstPaths = New-Object System.Windows.Forms.ListBox
$lstPaths.Location      = New-Object System.Drawing.Point 12, 22
$lstPaths.Size          = New-Object System.Drawing.Size 580, 180
$lstPaths.Anchor        = 'Top, Bottom, Left, Right'
$lstPaths.SelectionMode = 'MultiExtended'
$lstPaths.HorizontalScrollbar = $true
$grpPaths.Controls.Add($lstPaths)

$btnAdd = New-Object System.Windows.Forms.Button
$btnAdd.Text     = 'Add folder...'
$btnAdd.Location = New-Object System.Drawing.Point 600, 22
$btnAdd.Size     = New-Object System.Drawing.Size 108, 28
$btnAdd.Anchor   = 'Top, Right'
$grpPaths.Controls.Add($btnAdd)

$btnRemove = New-Object System.Windows.Forms.Button
$btnRemove.Text     = 'Remove'
$btnRemove.Location = New-Object System.Drawing.Point 600, 56
$btnRemove.Size     = New-Object System.Drawing.Size 108, 28
$btnRemove.Anchor   = 'Top, Right'
$grpPaths.Controls.Add($btnRemove)

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text     = 'Clear'
$btnClear.Location = New-Object System.Drawing.Point 600, 90
$btnClear.Size     = New-Object System.Drawing.Size 108, 28
$btnClear.Anchor   = 'Top, Right'
$grpPaths.Controls.Add($btnClear)

$form.Controls.Add($grpPaths)

# Options group
$grpOpts = New-Object System.Windows.Forms.GroupBox
$grpOpts.Text     = 'Options'
$grpOpts.Location = New-Object System.Drawing.Point 12, 240
$grpOpts.Size     = New-Object System.Drawing.Size 720, 110
$grpOpts.Anchor   = 'Top, Left, Right'

$chkRecurse = New-Object System.Windows.Forms.CheckBox
$chkRecurse.Text     = 'Recurse into subdirectories'
$chkRecurse.Checked  = $true
$chkRecurse.Location = New-Object System.Drawing.Point 12, 24
$chkRecurse.AutoSize = $true
$grpOpts.Controls.Add($chkRecurse)

$chkStrict = New-Object System.Windows.Forms.CheckBox
$chkStrict.Text     = 'Strict (treat conflicts as failure)'
$chkStrict.Location = New-Object System.Drawing.Point 240, 24
$chkStrict.AutoSize = $true
$grpOpts.Controls.Add($chkStrict)

$lblOut = New-Object System.Windows.Forms.Label
$lblOut.Text     = 'Output directory:'
$lblOut.Location = New-Object System.Drawing.Point 12, 56
$lblOut.AutoSize = $true
$grpOpts.Controls.Add($lblOut)

$txtOut = New-Object System.Windows.Forms.TextBox
$txtOut.Location = New-Object System.Drawing.Point 130, 53
$txtOut.Size     = New-Object System.Drawing.Size 462, 22
$txtOut.Anchor   = 'Top, Left, Right'
$txtOut.Text     = (Join-Path $env:TEMP 'dll-suite-report')
$grpOpts.Controls.Add($txtOut)

$btnOut = New-Object System.Windows.Forms.Button
$btnOut.Text     = 'Browse...'
$btnOut.Location = New-Object System.Drawing.Point 600, 51
$btnOut.Size     = New-Object System.Drawing.Size 108, 26
$btnOut.Anchor   = 'Top, Right'
$grpOpts.Controls.Add($btnOut)

$form.Controls.Add($grpOpts)

# Status row
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text     = 'Ready.'
$lblStatus.Location = New-Object System.Drawing.Point 12, 360
$lblStatus.Size     = New-Object System.Drawing.Size 720, 22
$lblStatus.Anchor   = 'Top, Left, Right'
$lblStatus.ForeColor = [System.Drawing.Color]::DimGray
$form.Controls.Add($lblStatus)

# Action buttons
$btnScan = New-Object System.Windows.Forms.Button
$btnScan.Text      = 'Scan'
$btnScan.Location  = New-Object System.Drawing.Point 12, 392
$btnScan.Size      = New-Object System.Drawing.Size 130, 36
$btnScan.Font      = New-Object System.Drawing.Font 'Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold
$btnScan.BackColor = [System.Drawing.Color]::FromArgb(9, 105, 218)
$btnScan.ForeColor = [System.Drawing.Color]::White
$btnScan.FlatStyle = 'Flat'
$btnScan.Anchor    = 'Top, Left'
$form.Controls.Add($btnScan)

$btnOpenHtml = New-Object System.Windows.Forms.Button
$btnOpenHtml.Text     = 'Open HTML report'
$btnOpenHtml.Location = New-Object System.Drawing.Point 152, 392
$btnOpenHtml.Size     = New-Object System.Drawing.Size 160, 36
$btnOpenHtml.Enabled  = $false
$btnOpenHtml.Anchor   = 'Top, Left'
$form.Controls.Add($btnOpenHtml)

$btnOpenDir = New-Object System.Windows.Forms.Button
$btnOpenDir.Text     = 'Open output folder'
$btnOpenDir.Location = New-Object System.Drawing.Point 322, 392
$btnOpenDir.Size     = New-Object System.Drawing.Size 160, 36
$btnOpenDir.Enabled  = $false
$btnOpenDir.Anchor   = 'Top, Left'
$form.Controls.Add($btnOpenDir)

# ---- Wire events ----
$btnAdd.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Add a directory to scan'
    if ($dlg.ShowDialog() -eq 'OK' -and $dlg.SelectedPath) {
        if (-not $lstPaths.Items.Contains($dlg.SelectedPath)) {
            [void]$lstPaths.Items.Add($dlg.SelectedPath)
        }
    }
})

$btnRemove.Add_Click({
    $sel = @($lstPaths.SelectedItems)
    foreach ($it in $sel) { $lstPaths.Items.Remove($it) }
})

$btnClear.Add_Click({ $lstPaths.Items.Clear() })

$btnOut.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Pick output directory'
    if ($dlg.ShowDialog() -eq 'OK' -and $dlg.SelectedPath) {
        $txtOut.Text = $dlg.SelectedPath
    }
})

$script:lastReportHtml = $null
$script:lastOutputDir  = $null

$btnScan.Add_Click({
    if ($lstPaths.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'Add at least one directory to scan.',
            'SysUtils DLL Suite', 'OK', 'Information') | Out-Null
        return
    }
    $paths = @($lstPaths.Items)
    $outDir = $txtOut.Text.Trim()
    if (-not $outDir) {
        [System.Windows.Forms.MessageBox]::Show(
            'Pick an output directory.',
            'SysUtils DLL Suite', 'OK', 'Warning') | Out-Null
        return
    }

    $btnScan.Enabled       = $false
    $btnOpenHtml.Enabled   = $false
    $btnOpenDir.Enabled    = $false
    $form.Cursor           = [System.Windows.Forms.Cursors]::WaitCursor
    $lblStatus.ForeColor   = [System.Drawing.Color]::DimGray
    $lblStatus.Text        = ('Scanning {0} directories...' -f $paths.Count)
    $form.Refresh()

    try {
        $r = Invoke-DllSuiteAnalysis `
            -Path      $paths `
            -Recurse:$chkRecurse.Checked `
            -OutputDir $outDir `
            -Strict:$chkStrict.Checked `
            -Quiet

        $script:lastReportHtml = Join-Path $outDir 'report.html'
        $script:lastOutputDir  = $outDir

        $s = $r.Summary
        $msg = ('Scanned {0} files. Duplicates: {1}. Conflicts: {2}. Drift: {3}.' -f `
                $s.FilesScanned, $s.DuplicateGroups, $s.GuidConflicts, $s.DriftIssues)
        if ($s.DriftIssues -gt 0)         { $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(207, 34, 46) }
        elseif ($s.GuidConflicts -gt 0)   { $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(191, 135, 0) }
        else                              { $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(26, 127, 55) }
        $lblStatus.Text = $msg
        $btnOpenHtml.Enabled = (Test-Path $script:lastReportHtml)
        $btnOpenDir.Enabled  = (Test-Path $script:lastOutputDir)
    } catch {
        $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(207, 34, 46)
        $lblStatus.Text      = ('Error: {0}' -f $_.Exception.Message)
    } finally {
        $form.Cursor      = [System.Windows.Forms.Cursors]::Default
        $btnScan.Enabled  = $true
    }
})

$btnOpenHtml.Add_Click({
    if ($script:lastReportHtml -and (Test-Path $script:lastReportHtml)) {
        Start-Process -FilePath $script:lastReportHtml
    }
})

$btnOpenDir.Add_Click({
    if ($script:lastOutputDir -and (Test-Path $script:lastOutputDir)) {
        Start-Process -FilePath 'explorer.exe' -ArgumentList $script:lastOutputDir
    }
})

[void]$form.ShowDialog()
$form.Dispose()
