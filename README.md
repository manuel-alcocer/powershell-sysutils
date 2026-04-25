# powershell-sysutils

A small collection of standalone PowerShell sysadmin tools for Windows. Each
script is self-contained, ships its own `Get-Help` documentation, and can be
copied to any host without further setup.

Built and tested against **Windows PowerShell 5.1** on Windows 10 / Server 2016
and newer. None of the scripts require external modules or NuGet packages.

## Scripts

### `Dll-Inspector.ps1` — Read-only PE/COM/.NET inspector

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
.\Dll-Inspector.ps1 -Path C:\Windows\System32\scrrun.dll -Detailed |
    ConvertTo-Json -Depth 12

# Find every COM-registrable DLL under a directory
Get-ChildItem C:\Legacy -Include *.dll,*.ocx -Recurse |
    .\Dll-Inspector.ps1 |
    Where-Object { $_.Com.IsComServer } |
    Select-Object Path, @{n='HasTLB';e={$_.Com.HasTypeLib}},
                  @{n='Arch';e={$_.PE.Architecture}}

# Audit which DLLs import a given API
Get-ChildItem C:\App -Filter *.dll |
    .\Dll-Inspector.ps1 -IncludeImports |
    Where-Object { $_.Imports.Functions.Name -contains 'CreateRemoteThread' } |
    Select-Object Path
```

### `Process-Monitor.ps1` — Procmon-lite for the console

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

### `Registry-Navigator.ps1` — Interactive registry REPL

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

### `Registry-TUI.ps1` — Full-screen registry browser

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

### Option A — `git clone` on each server

The simplest path if `git` is installed on the targets. `git pull` to
update.

```powershell
git clone https://github.com/manuel-alcocer/powershell-sysutils.git C:\Tools\powershell-sysutils
cd C:\Tools\powershell-sysutils
.\Dll-Inspector.ps1 -Path .\anything.dll
```

### Option B — Direct download (no git on the target)

Pull a single script from `raw.githubusercontent.com`. Useful for one-off
runs or for bootstrapping.

```powershell
$base = 'https://raw.githubusercontent.com/manuel-alcocer/powershell-sysutils/main'
foreach ($s in 'Dll-Inspector.ps1','Process-Monitor.ps1','Registry-Navigator.ps1','Registry-TUI.ps1') {
    Invoke-WebRequest "$base/$s" -OutFile "C:\Tools\$s" -UseBasicParsing
}
```

### Option C — Ansible

Two simple patterns from a control node. Pick whichever your playbook
already uses.

`win_get_url` — pulls a single script over HTTP, no git required on the
target:

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
