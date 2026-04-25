@{
    RootModule        = 'SysUtils.psm1'
    ModuleVersion     = '1.3.1'
    GUID              = '4515655c-dd64-4d6f-a700-e2c9fa04f50a'

    Author            = 'Manuel Alcocer Jiménez'
    CompanyName       = 'Manuel Alcocer Jiménez'
    Copyright         = '(c) 2026 Manuel Alcocer Jiménez <manalcjim@outlook.com>. MIT License.'

    Description       = 'Read-only Windows PE / COM / .NET inspector for sysadmins. Parses DLL/OCX/EXE/SYS without LoadLibrary; reports PE headers, version info, COM TypeLibs (CoClasses, interfaces, methods), .NET assembly metadata (PEKind, CorFlags, AssemblyName, types) and Authenticode signatures. Cross-bitness inspection.'

    PowerShellVersion = '5.1'

    FunctionsToExport = @('Get-DllInfo','Get-DllGuidTable','Invoke-DllSuiteAnalysis')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('PE','DLL','OCX','COM','TypeLib','dotnet','Inspector','Sysadmin','Windows','PowerShell5')
            LicenseUri   = 'https://github.com/manuel-alcocer/powershell-sysutils/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/manuel-alcocer/powershell-sysutils'
            ReleaseNotes = @'
1.3.1 - Metadata-only: update Author, CompanyName and Copyright to the
full author name (Manuel Alcocer Jiménez) and add contact email in the
copyright line. No code changes.

1.3.0 - Get-DllGuidTable: add -Both switch.

The new -Both switch shows Type/Name/Guid/RegKey at once (4 columns),
complementing the existing default (Type/Name/Guid) and -RegKey
(Type/Name/RegKey) modes. The three are mutually exclusive via
ParameterSetName. Help adds an EXAMPLE showing how to avoid line
wrapping in narrow consoles when using -Both (Out-String -Width 250
and BufferSize tweak).

1.2.0 - Add Get-DllGuidTable cmdlet.

Flat (Type, Name, Guid, RegKey) view of every entry in a DLL's embedded
TypeLib (coclass / interface / dispatch / enum / record / union / alias
/ module). The RegKey column reports the registry path under which each
GUID is registered (HKCR\CLSID for CoClasses, HKCR\Interface for
interfaces and dispinterfaces; HKLM and HKCU plus 32-bit Wow6432Node
views are searched), or empty when not registered or not applicable.
Switch -RegKey swaps the default Format-Table display from Guid to
RegKey to avoid wrapping; -Kind filters by entry kind. Strictly
read-only: oleaut32!LoadTypeLibEx is called with REGKIND_NONE and
registry lookups go through Microsoft.Win32.RegistryKey directly.

1.1.0 - Add -IncludeComRegistration switch.

Cross-references the CoClasses declared in the DLL's embedded TypeLib
against HKCR\CLSID across HKLM/HKCU x64+x86 views to determine whether
a COM in-proc server is correctly registered, plus surfaces every CLSID
whose InprocServer32 points at the inspected DLL. Uses
Microsoft.Win32.RegistryKey directly (full HKCR\CLSID walk drops from
~20s to ~1s vs the PowerShell registry provider). Strictly read-only:
no regsvr32, no LoadLibrary, no admin needed. Per-CLSID statuses:
Registered / DeclaredOnly / PathMismatch / RegisteredOnly. Global
verdict: OK / Partial / Unregistered / NotApplicable.

1.0.0 - Initial release.

Get-DllInfo: read-only Windows PE inspector that parses DLL/OCX/EXE/SYS
files without LoadLibrary (so cross-bitness inspection works and DllMain is
never executed). Layered output controlled by switches:

  - default: PE header (architecture, subsystem, characteristics, sections,
    timestamp), version info, shallow COM detection, shallow .NET detection.
  - -IncludeImports: full IDT/ILT walk including import-by-ordinal.
  - -IncludeExports: full export table with forwarder detection.
  - -IncludeResources: recursive 3-level resource tree walk.
  - -IncludeTypeLib: TypeLib reader via oleaut32!LoadTypeLibEx (CoClasses,
    interfaces, methods, parameters, enums, aliases, IIDs/CLSIDs).
  - -IncludeDotNetTypes: ReflectionOnlyLoadFrom for [ComVisible]/[Guid]/
    [ProgId] per type.
  - -IncludeSignature: Authenticode signature.
  - -IncludeHash: SHA-256.
  - -Detailed: turns on every Include* switch.

For managed assemblies, PEKind disambiguates AnyCPU / AnyCPUPrefer32 /
x86 / x64 / ARM64 / ManagedMixed using Machine + PE32/PE32+ + CorFlags.
'@
        }
    }
}
