# PE / COFF / DllCharacteristics maps plus a handful of magic numbers used
# by the PE parser, TypeLib reader and .NET inspector. Module scope.

$script:MachineMap = @{
    0x014c = 'x86'
    0x0200 = 'IA64'
    0x8664 = 'x64'
    0x01c0 = 'ARM'
    0x01c2 = 'ARM-Thumb'
    0x01c4 = 'ARMNT'
    0xAA64 = 'ARM64'
    0x0EBC = 'EFI'
}

$script:SubsystemMap = @{
    0  = 'Unknown'
    1  = 'Native'
    2  = 'Windows GUI'
    3  = 'Windows CUI'
    5  = 'OS/2 CUI'
    7  = 'POSIX CUI'
    8  = 'Native Win9x driver'
    9  = 'Windows CE GUI'
    10 = 'EFI Application'
    11 = 'EFI Boot Service Driver'
    12 = 'EFI Runtime Driver'
    13 = 'EFI ROM'
    14 = 'Xbox'
    16 = 'Windows Boot Application'
}

$script:CharacteristicsMap = [ordered]@{
    0x0001 = 'RelocsStripped'
    0x0002 = 'ExecutableImage'
    0x0004 = 'LineNumsStripped'
    0x0008 = 'LocalSymsStripped'
    0x0010 = 'AggressiveWsTrim'
    0x0020 = 'LargeAddressAware'
    0x0080 = 'BytesReversedLo'
    0x0100 = '32BitMachine'
    0x0200 = 'DebugStripped'
    0x0400 = 'RemovableRunFromSwap'
    0x0800 = 'NetRunFromSwap'
    0x1000 = 'System'
    0x2000 = 'Dll'
    0x4000 = 'UpSystemOnly'
    0x8000 = 'BytesReversedHi'
}

$script:DllCharacteristicsMap = [ordered]@{
    0x0020 = 'HighEntropyVA'
    0x0040 = 'DynamicBase'         # ASLR
    0x0080 = 'ForceIntegrity'
    0x0100 = 'NxCompat'            # DEP
    0x0200 = 'NoIsolation'
    0x0400 = 'NoSEH'
    0x0800 = 'NoBind'
    0x1000 = 'AppContainer'
    0x2000 = 'WdmDriver'
    0x4000 = 'GuardCF'             # Control Flow Guard
    0x8000 = 'TerminalServerAware'
}

# Standard resource type IDs (numeric). TYPELIB is conventionally
# string-named (so it does not appear here); a few tools emit it as
# numeric 13 — we keep that slot intentionally empty.
$script:ResourceTypeMap = @{
    1  = 'CURSOR'
    2  = 'BITMAP'
    3  = 'ICON'
    4  = 'MENU'
    5  = 'DIALOG'
    6  = 'STRING'
    7  = 'FONTDIR'
    8  = 'FONT'
    9  = 'ACCELERATOR'
    10 = 'RCDATA'
    11 = 'MESSAGETABLE'
    12 = 'GROUP_CURSOR'
    14 = 'GROUP_ICON'
    16 = 'VERSION'
    17 = 'DLGINCLUDE'
    19 = 'PLUGPLAY'
    20 = 'VXD'
    21 = 'ANICURSOR'
    22 = 'ANIICON'
    23 = 'HTML'
    24 = 'MANIFEST'
}

# COMIMAGE_FLAGS
$script:CorFlagsMap = [ordered]@{
    0x00001 = 'ILOnly'
    0x00002 = 'Required32Bit'
    0x00004 = 'ILLibrary'
    0x00008 = 'StrongNameSigned'
    0x00010 = 'NativeEntryPoint'
    0x10000 = 'TrackDebugData'
    0x20000 = 'Preferred32Bit'
}

# 0x8000_0000_0000_0000 cannot be written as an int64 literal in PS 5.1
# (overflows). Build it via BitConverter once.
$script:OrdinalFlag64 = [BitConverter]::ToUInt64(
    [byte[]](0,0,0,0,0,0,0,0x80), 0)

# Data directory indices
$script:DD_EXPORT   = 0
$script:DD_IMPORT   = 1
$script:DD_RESOURCE = 2
$script:DD_SECURITY = 4
$script:DD_DEBUG    = 6
$script:DD_TLS      = 9
$script:DD_CLR      = 14

# The four self-registration entry points that a COM in-proc server must
# export. DllGetClassObject + DllRegisterServer is the minimum signal.
$script:ComSelfRegSymbols = @(
    'DllRegisterServer'
    'DllUnregisterServer'
    'DllGetClassObject'
    'DllCanUnloadNow'
    'DllInstall'
)
