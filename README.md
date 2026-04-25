# powershell-sysutils

PowerShell sysadmin tools for Windows. The flagship is the **`SysUtils`**
module on the [PowerShell Gallery][gallery] (currently exporting
`Get-DllInfo`). The other three tools — process monitor and two registry
browsers — still ship as standalone `.ps1` scripts in this repo and will
move into the module in subsequent releases.

[gallery]: https://www.powershellgallery.com/packages/SysUtils

Built and tested against **Windows PowerShell 5.1** on Windows 10 /
Server 2016 and newer. No external dependencies.

## Quick start

```powershell
# From any Windows machine with PowerShell 5.1+:
Install-Module SysUtils -Force
Get-DllInfo C:\Windows\System32\scrrun.dll | ConvertTo-Json -Depth 12
```

That's it — `PSGallery` is registered by default, no `Register-PSRepository`
needed.

## Tools

### `Get-DllInfo` (module: `SysUtils`) — Read-only PE/COM/.NET inspector

Inspects DLL, OCX, EXE and SYS files without loading them into the process
(no `LoadLibrary`, no `DllMain` execution). Works cross-bitness — a 32-bit
DLL in `SysWOW64` can be inspected from a 64-bit PowerShell session and
vice versa.

Layered output, all opt-in via switches; emits a single `PSCustomObject`
suitable for `ConvertTo-Json` (Ansible-friendly):

| Switch | What it adds |
| ------ | ------------ |
| _(default)_ | PE header (architecture, subsystem, characteristics, sections, timestamp), version info, COM and .NET detection |
| `-IncludeImports` | IDT walk: per-module function lists, including import-by-ordinal |
| `-IncludeExports` | Full export table with forwarder detection (e.g. `kernel32 -> NTDLL.Rtl*`) |
| `-IncludeResources` | Recursive 3-level walk of the resource tree |
| `-IncludeTypeLib` | TypeLib reader via `oleaut32!LoadTypeLibEx` (REGKIND_NONE) — CoClasses, interfaces, methods, parameters, enums, aliases, IIDs/CLSIDs |
| `-IncludeDotNetTypes` | `Assembly.ReflectionOnlyLoadFrom` — `[ComVisible]` / `[Guid]` / `[ProgId]` per type, full type listing |
| `-IncludeSignature` | Authenticode signature info |
| `-IncludeHash` | SHA-256 of the file |
| `-Detailed` | Convenience: enables every `Include*` switch above |

For managed assemblies, the cheap path also reports a `PEKind` field that
disambiguates **AnyCPU** from real **x86** / **x64** / **AnyCPUPrefer32** /
**ManagedMixed** (which the raw `Machine` field cannot do alone).

```powershell
# One DLL, full report as JSON
Get-DllInfo C:\Windows\System32\scrrun.dll -Detailed | ConvertTo-Json -Depth 12

# Find every COM-registrable DLL under a directory
Get-ChildItem C:\Legacy -Include *.dll,*.ocx -Recurse |
    Get-DllInfo |
    Where-Object { $_.Com.IsComServer } |
    Select-Object Path, @{n='HasTLB';e={$_.Com.HasTypeLib}},
                  @{n='Arch';e={$_.PE.Architecture}}

# Audit which DLLs import a given API
Get-ChildItem C:\App -Filter *.dll |
    Get-DllInfo -IncludeImports |
    Where-Object { $_.Imports.Functions.Name -contains 'CreateRemoteThread' } |
    Select-Object Path
```

`Dll-Inspector.ps1` at the repo root is a thin wrapper that imports the
module and forwards every parameter to `Get-DllInfo`, so users who
`git clone` the repo can keep running `.\Dll-Inspector.ps1` unchanged.

### `Process-Monitor.ps1` — Procmon-lite for the console (standalone, not yet in module)

Live activity monitor for a binary (by name or PID). Subscribes to WMI
process creation/termination events and polls each tracked PID for loaded
modules and network connections. If Sysmon is installed on the target,
also tails its file/registry/DNS/image-load events. Follows child
processes automatically. Works locally or remotely via WinRM.

```powershell
# Follow every notepad.exe on the local machine
.\Process-Monitor.ps1 -Target notepad.exe

# Follow PID 1234 on a remote host
$c = Import-Clixml .\admin.xml
.\Process-Monitor.ps1 -Target 1234 -ComputerName host.example -Credential $c
```

### `Registry-Navigator.ps1` — Interactive registry REPL (standalone)

Lightweight REPL to browse registry keys and values. Local mode talks to
the local registry directly; remote mode dispatches each command via a
persistent `PSSession` over WinRM.

```powershell
# Local
.\Registry-Navigator.ps1

# Remote
$cred = Get-Credential administrator
.\Registry-Navigator.ps1 -ComputerName host.example -Credential $cred
```

### `Registry-TUI.ps1` — Full-screen registry browser (standalone)

Two-pane TUI (subkeys | values) using the Windows console API.
Arrow-key navigation, Enter to descend, Backspace to go up. Same remote
WinRM mode as `Registry-Navigator.ps1`.

```powershell
.\Registry-TUI.ps1
.\Registry-TUI.ps1 -ComputerName host.example -Credential (Get-Credential)
```

## Help

Every script ships full comment-based help:

```powershell
Get-Help .\Dll-Inspector.ps1 -Full
Get-Help .\Process-Monitor.ps1 -Examples
```

## Installation

### Option A — PowerShell Gallery (recommended)

`Get-DllInfo` lives in the `SysUtils` module. The `PSGallery` repository
is registered by default on every Windows with PowerShellGet, so a single
command on each server is enough:

```powershell
Install-Module SysUtils -Force
Get-DllInfo C:\Windows\System32\scrrun.dll
```

For the standalone scripts that haven't moved into the module yet
(`Process-Monitor.ps1`, `Registry-Navigator.ps1`, `Registry-TUI.ps1`),
fall back to `git clone` (Option B) or direct download (Option C).

### Option B — `git clone` on each server

The simplest path if `git` is installed on the targets. Includes both the
module and the standalone scripts. `git pull` to update.

```powershell
git clone https://github.com/manuel-alcocer/powershell-sysutils.git C:\Tools\powershell-sysutils
cd C:\Tools\powershell-sysutils

# Run a standalone script directly:
.\Dll-Inspector.ps1 -Path .\anything.dll

# Or import the module from the cloned tree (no Install-Module):
Import-Module .\SysUtils\SysUtils.psd1 -Force
Get-DllInfo .\anything.dll
```

### Option C — Direct download (no git on the target)

Pull individual scripts from `raw.githubusercontent.com`. Useful for one-off
runs or for bootstrapping.

```powershell
$base = 'https://raw.githubusercontent.com/manuel-alcocer/powershell-sysutils/main'
foreach ($s in 'Dll-Inspector.ps1','Process-Monitor.ps1','Registry-Navigator.ps1','Registry-TUI.ps1') {
    Invoke-WebRequest "$base/$s" -OutFile "C:\Tools\$s" -UseBasicParsing
}
```

### Option D — Ansible

Three patterns from a control node. Pick whichever fits your playbook.

`win_psmodule` — installs the module from PowerShell Gallery. Cleanest:

```yaml
- hosts: windows
  tasks:
    - name: Install SysUtils module
      community.windows.win_psmodule:
        name: SysUtils
        state: present
        accept_license: yes
```

`win_get_url` — pulls individual scripts over HTTP, no git required on the
target. Use this for the standalone scripts not yet in the module:

```yaml
- hosts: windows
  vars:
    repo_base: https://raw.githubusercontent.com/manuel-alcocer/powershell-sysutils/main
    install_dir: C:\Tools\powershell-sysutils
    scripts:
      - Dll-Inspector.ps1
      - Process-Monitor.ps1
      - Registry-Navigator.ps1
      - Registry-TUI.ps1
  tasks:
    - name: Ensure install dir exists
      ansible.windows.win_file:
        path: "{{ install_dir }}"
        state: directory

    - name: Download scripts
      ansible.windows.win_get_url:
        url: "{{ repo_base }}/{{ item }}"
        dest: "{{ install_dir }}\\{{ item }}"
        force: yes
      loop: "{{ scripts }}"
```

`win_command` — clone the repo if you have git for Windows on the
targets and want a versioned working tree:

```yaml
- name: Clone powershell-sysutils
  ansible.windows.win_command:
    cmd: git clone --depth 1 https://github.com/manuel-alcocer/powershell-sysutils.git C:\Tools\powershell-sysutils
    creates: C:\Tools\powershell-sysutils\.git
```

To call any script from a playbook and consume its output as structured
data, run it through `ConvertTo-Json` and parse on the control node:

```yaml
- name: Inspect a DLL
  ansible.windows.win_powershell:
    script: |
      C:\Tools\powershell-sysutils\Dll-Inspector.ps1 `
        -Path C:\Windows\System32\scrrun.dll -Detailed |
        ConvertTo-Json -Depth 12 -Compress
  register: dll_info
```

## Execution policy

If your servers refuse to run scripts because of `ExecutionPolicy`, run
them with the `Bypass` flag — it does not persist beyond the call:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Dll-Inspector.ps1 -Path foo.dll
```

## License

MIT — see [LICENSE](LICENSE).
