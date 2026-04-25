# .NET assembly inspection. Cheap path reads CLR header + MetaData root from
# PE bytes (no AppDomain load). Deep path uses ReflectionOnlyLoadFrom for
# ComVisible / type enumeration.

function Get-DotNetCheapInfo {
    # Reads the CLR header and the MetaData root from PE bytes — does not
    # load anything into the AppDomain. Returns null when there is no CLR
    # data directory.
    param($Pe, [string]$FilePath)
    $clr = $Pe.DataDirectories[$script:DD_CLR]
    if (-not $clr -or $clr.Size -eq 0 -or $clr.Rva -eq 0) { return $null }

    $clrOff = ConvertTo-FileOffset -Rva $clr.Rva -Sections $Pe.Sections
    if ($null -eq $clrOff) { return $null }

    $br = $Pe.Reader
    $br.BaseStream.Position = $clrOff

    # IMAGE_COR20_HEADER
    $cb           = $br.ReadUInt32()
    $rtMaj        = $br.ReadUInt16()
    $rtMin        = $br.ReadUInt16()
    $mdRva        = $br.ReadUInt32()
    $mdSize       = $br.ReadUInt32()
    $corFlags     = $br.ReadUInt32()
    $entryToken   = $br.ReadUInt32()

    # MetaData root — runtime version string lives just after the BSJB header
    $rtVersion = $null
    if ($mdRva -ne 0) {
        $mdOff = ConvertTo-FileOffset -Rva $mdRva -Sections $Pe.Sections
        if ($null -ne $mdOff) {
            $br.BaseStream.Position = $mdOff
            $sig = $br.ReadUInt32()
            if ($sig -eq 0x424A5342) {   # 'BSJB'
                $null   = $br.ReadUInt16()    # iMajorVer
                $null   = $br.ReadUInt16()    # iMinorVer
                $null   = $br.ReadUInt32()    # iExtraData (reserved)
                $verLen = $br.ReadUInt32()    # padded to 4-byte boundary
                if ($verLen -gt 0 -and $verLen -lt 1024) {
                    $verBytes = $br.ReadBytes([int]$verLen)
                    $end = [Array]::IndexOf($verBytes, [byte]0)
                    if ($end -ge 0) { $verBytes = $verBytes[0..([Math]::Max($end - 1, 0))] }
                    if ($verBytes.Length -gt 0) {
                        $rtVersion = [Text.Encoding]::UTF8.GetString($verBytes)
                    }
                }
            }
        }
    }

    # Decode CorFlags into a string array
    $flagsDecoded = ConvertTo-Flags -Value $corFlags -Map $script:CorFlagsMap

    # PE kind: combines Machine + PE32/PE32+ + CorFlags
    $isILOnly    = ($corFlags -band 0x00001) -ne 0
    $is32Req     = ($corFlags -band 0x00002) -ne 0
    $is32Pref    = ($corFlags -band 0x20000) -ne 0
    $machine     = $Pe.Machine
    $peKind = if (-not $isILOnly) {
        'ManagedMixed'
    } elseif ($machine -eq 0x8664) {
        'x64'
    } elseif ($machine -eq 0xAA64) {
        'ARM64'
    } elseif ($is32Req -and $is32Pref) {
        'AnyCPUPrefer32'
    } elseif ($is32Req) {
        'x86'
    } else {
        'AnyCPU'
    }

    # AssemblyName.GetAssemblyName reads metadata only, doesn't load.
    $aname = $null
    try { $aname = [System.Reflection.AssemblyName]::GetAssemblyName($FilePath) } catch { }

    $asmName = $null; $asmVer = $null; $asmCulture = $null; $pkt = $null
    if ($aname) {
        $asmName    = $aname.Name
        $asmVer     = if ($aname.Version) { $aname.Version.ToString() } else { $null }
        $asmCulture = if ([string]::IsNullOrEmpty($aname.CultureName)) { 'neutral' } else { $aname.CultureName }
        $pktBytes   = $aname.GetPublicKeyToken()
        if ($pktBytes -and $pktBytes.Length -gt 0) {
            $pkt = -join ($pktBytes | ForEach-Object { '{0:x2}' -f $_ })
        } else {
            $pkt = ''   # not strong-name signed
        }
    }

    [pscustomobject]@{
        IsManaged         = $true
        RuntimeVersion    = $rtVersion
        CorHeaderVersion  = "$rtMaj.$rtMin"
        CorFlags          = ('0x{0:X}' -f $corFlags)
        CorFlagsDecoded   = $flagsDecoded
        PEKind            = $peKind
        AssemblyName      = $asmName
        Version           = $asmVer
        Culture           = $asmCulture
        PublicKeyToken    = $pkt
        EntryPointToken   = ('0x{0:X8}' -f $entryToken)
        HasMetaData       = ($null -ne $rtVersion)
        IsComVisible      = $null   # filled by deep path
        Types             = $null   # filled by deep path
    }
}

function Get-DotNetDeepInfo {
    # Calls ReflectionOnlyLoadFrom and reads ComVisible at the assembly
    # level plus a per-type listing with [ComVisible]/[Guid]/[ProgId].
    # Returns @{ IsComVisible; Types } or $null on failure (mixed-mode
    # assemblies, missing deps, etc.).
    param([string]$FilePath, [bool]$IncludeTypes)

    # A scriptblock cast to a delegate handles missing-dep failures.
    $resolver = [System.ResolveEventHandler]{
        param($sender, $args)
        try { [System.Reflection.Assembly]::ReflectionOnlyLoad($args.Name) }
        catch { $null }
    }

    $domain = [System.AppDomain]::CurrentDomain
    $domain.add_ReflectionOnlyAssemblyResolve($resolver)
    try {
        $asm = [System.Reflection.Assembly]::ReflectionOnlyLoadFrom($FilePath)

        # Assembly-level ComVisible (default is true for an assembly that
        # carries no [ComVisible] attribute, but we report null when the
        # attribute is absent so the caller can distinguish).
        $asmComVisible = $null
        foreach ($cad in [System.Reflection.CustomAttributeData]::GetCustomAttributes($asm)) {
            if ($cad.AttributeType.FullName -eq 'System.Runtime.InteropServices.ComVisibleAttribute') {
                if ($cad.ConstructorArguments.Count -gt 0) {
                    $asmComVisible = [bool]$cad.ConstructorArguments[0].Value
                }
                break
            }
        }

        $typesOut = $null
        if ($IncludeTypes) {
            $allTypes = $null
            try {
                $allTypes = $asm.GetTypes()
            } catch [System.Reflection.ReflectionTypeLoadException] {
                $allTypes = $_.Exception.Types | Where-Object { $null -ne $_ }
            }
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($t in $allTypes) {
                if (-not $t) { continue }
                $tcv = $null; $tguid = $null; $tprog = $null
                try {
                    foreach ($cad in [System.Reflection.CustomAttributeData]::GetCustomAttributes($t)) {
                        switch ($cad.AttributeType.FullName) {
                            'System.Runtime.InteropServices.ComVisibleAttribute' {
                                if ($cad.ConstructorArguments.Count -gt 0) {
                                    $tcv = [bool]$cad.ConstructorArguments[0].Value
                                }
                            }
                            'System.Runtime.InteropServices.GuidAttribute' {
                                if ($cad.ConstructorArguments.Count -gt 0) {
                                    $tguid = [string]$cad.ConstructorArguments[0].Value
                                }
                            }
                            'System.Runtime.InteropServices.ProgIdAttribute' {
                                if ($cad.ConstructorArguments.Count -gt 0) {
                                    $tprog = [string]$cad.ConstructorArguments[0].Value
                                }
                            }
                        }
                    }
                } catch { }

                [void]$list.Add([pscustomobject]@{
                    FullName     = $t.FullName
                    Namespace    = $t.Namespace
                    BaseType     = if ($t.BaseType) { $t.BaseType.FullName } else { $null }
                    IsClass      = [bool]$t.IsClass
                    IsInterface  = [bool]$t.IsInterface
                    IsEnum       = [bool]$t.IsEnum
                    IsValueType  = [bool]$t.IsValueType
                    IsAbstract   = [bool]$t.IsAbstract
                    IsSealed     = [bool]$t.IsSealed
                    IsPublic     = [bool]$t.IsPublic
                    IsComVisible = $tcv
                    Guid         = $tguid
                    ProgId       = $tprog
                })
            }
            $typesOut = $list.ToArray()
        }

        return @{
            IsComVisible = $asmComVisible
            Types        = $typesOut
        }
    } catch {
        return $null
    } finally {
        $domain.remove_ReflectionOnlyAssemblyResolve($resolver)
    }
}
