# SysUtils DLL Suite - Tools

End-user-facing wrappers around `Invoke-DllSuiteAnalysis` and
`New-DllSuiteReport` from the SysUtils module. Designed to be shipped
as a release zip alongside the module, or run directly from this repo
during development.

## Files

| File | Purpose |
|---|---|
| `DllSuite-GUI.ps1`  | WinForms launcher: pick directories, scan, open HTML. |
| `DllSuite-GUI.cmd`  | Double-clickable wrapper that starts the GUI without a console window. |
| `DllSuite-Run.ps1`  | Headless wrapper for CI/CD with proper exit codes. |
| `DllSuite-Run.cmd`  | Batch wrapper around the above so non-PowerShell agents can call it. |

The wrappers locate the module in this priority order:

1. `..\SysUtils\SysUtils.psd1` (release zip layout, where `Tools\` and
   `SysUtils\` are siblings).
2. Any installed `SysUtils` module (PSGallery / scoop / etc).

## Quick start

### Interactive

Double-click `DllSuite-GUI.cmd`.  Add the directories you want to scan
("Add folder..."), pick an output directory, hit **Scan**.  When the
scan finishes, click **Open HTML report**.

### Headless / CI

```cmd
:: Windows shell
DllSuite-Run.cmd -Path C:\Apps\Team1 C:\Apps\Team2 ^
                 -Recurse -Strict -OutputDir .\artifacts
```

```powershell
# PowerShell
.\DllSuite-Run.ps1 -Path C:\Apps\Team1, C:\Apps\Team2 `
                   -Recurse -Strict -OutputDir .\artifacts
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | OK (no issues, or issues found and `-Strict` not set) |
| 1 | Fatal error (bad path, module not loadable, ...) |
| 2 | Conflicts/drift detected AND `-Strict` was set |

## Output artifacts

`-OutputDir` receives three files:

- `report.json` (schema `dllsuite/1`) - structured data for dashboards.
- `report.html` - self-contained, double-clickable, what you mail to the dev teams.
- `summary.txt` - human-readable digest (greppable from the pipeline log).
