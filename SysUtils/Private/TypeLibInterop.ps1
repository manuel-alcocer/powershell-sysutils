# TypeLib reader. Uses oleaut32!LoadTypeLibEx via a C# helper because
# PowerShell's COM late-binding cannot QueryInterface for ITypeLib (the RCW
# comes back as System.__ComObject and refuses the cast). The C# helper
# returns plain CLR objects that serialize cleanly with ConvertTo-Json.

function Initialize-TypeLibInterop {
    if ('SysUtils.Interop.TypeLibReader' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using CT = System.Runtime.InteropServices.ComTypes;

namespace SysUtils.Interop {
    public class TypeLibInfo {
        public Guid LibId;
        public int MajorVersion;
        public int MinorVersion;
        public int Lcid;
        public int LibFlags;
        public string SysKind;
        public string Name;
        public string DocString;
        public int HelpContext;
        public string HelpFile;
        public TypeInfoEntry[] TypeInfos;
    }

    public class TypeInfoEntry {
        public string Kind;
        public string Name;
        public Guid Guid;
        public string DocString;
        public int HelpContext;
        public string HelpFile;
        public int TypeFlags;
        public string[] TypeFlagsDecoded;
        public ImplementedInterface[] Interfaces;   // COCLASS
        public ParentRef Parent;                     // INTERFACE / DISPATCH
        public MethodEntry[] Methods;                 // INTERFACE / DISPATCH
        public EnumMember[] Members;                  // ENUM / RECORD / UNION
        public string AliasOf;                         // ALIAS
    }

    public class ImplementedInterface {
        public string Name;
        public Guid Iid;
        public bool IsDefault;
        public bool IsSource;
        public bool IsRestricted;
        public bool IsDefaultVtable;
    }

    public class ParentRef {
        public string Name;
        public Guid Iid;
    }

    public class MethodEntry {
        public string Name;
        public int DispId;
        public string InvKind;
        public string FuncKind;
        public int FuncFlags;
        public string ReturnType;
        public ParamEntry[] Params;
    }

    public class ParamEntry {
        public string Name;
        public string Type;
        public bool IsIn;
        public bool IsOut;
        public bool IsRetVal;
        public bool IsOptional;
    }

    public class EnumMember {
        public string Name;
        public object Value;
        public int DispId;
        public string Kind;
    }

    public static class TypeLibReader {
        // REGKIND_NONE = 2: load metadata without touching the registry.
        [DllImport("oleaut32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, PreserveSig=false)]
        private static extern void LoadTypeLibEx(
            [MarshalAs(UnmanagedType.LPWStr)] string szFile,
            int regkind,
            [MarshalAs(UnmanagedType.Interface)] out CT.ITypeLib pptlib);

        public static TypeLibInfo Read(string path) {
            CT.ITypeLib t;
            try { LoadTypeLibEx(path, 2, out t); }
            catch { return null; }
            try { return ReadLib(t); }
            finally { Marshal.ReleaseComObject(t); }
        }

        private static TypeLibInfo ReadLib(CT.ITypeLib t) {
            var info = new TypeLibInfo();
            IntPtr pa;
            t.GetLibAttr(out pa);
            try {
                var la = (CT.TYPELIBATTR)Marshal.PtrToStructure(pa, typeof(CT.TYPELIBATTR));
                info.LibId        = la.guid;
                info.MajorVersion = la.wMajorVerNum;
                info.MinorVersion = la.wMinorVerNum;
                info.Lcid         = la.lcid;
                info.LibFlags     = (int)la.wLibFlags;
                info.SysKind      = la.syskind.ToString();
            } finally { t.ReleaseTLibAttr(pa); }

            string n, d, hf; int hc;
            t.GetDocumentation(-1, out n, out d, out hc, out hf);
            info.Name = n; info.DocString = d; info.HelpContext = hc; info.HelpFile = hf;

            int count = t.GetTypeInfoCount();
            var entries = new List<TypeInfoEntry>(count);
            for (int i = 0; i < count; i++) {
                CT.ITypeInfo ti;
                t.GetTypeInfo(i, out ti);
                try { entries.Add(ReadTypeInfo(ti)); }
                finally { Marshal.ReleaseComObject(ti); }
            }
            info.TypeInfos = entries.ToArray();
            return info;
        }

        private static TypeInfoEntry ReadTypeInfo(CT.ITypeInfo ti) {
            var entry = new TypeInfoEntry();
            string n, d, hf; int hc;
            ti.GetDocumentation(-1, out n, out d, out hc, out hf);
            entry.Name = n; entry.DocString = d; entry.HelpContext = hc; entry.HelpFile = hf;

            IntPtr pTA; ti.GetTypeAttr(out pTA);
            CT.TYPEATTR ta;
            try {
                ta = (CT.TYPEATTR)Marshal.PtrToStructure(pTA, typeof(CT.TYPEATTR));
            } finally { ti.ReleaseTypeAttr(pTA); }

            entry.Guid             = ta.guid;
            entry.Kind             = ta.typekind.ToString();
            entry.TypeFlags        = (int)ta.wTypeFlags;
            entry.TypeFlagsDecoded = DecodeTypeFlags((int)ta.wTypeFlags);

            switch (ta.typekind) {
                case CT.TYPEKIND.TKIND_COCLASS:
                    entry.Interfaces = ReadImpls(ti, ta.cImplTypes);
                    break;
                case CT.TYPEKIND.TKIND_INTERFACE:
                case CT.TYPEKIND.TKIND_DISPATCH:
                    if (ta.cImplTypes > 0) entry.Parent = ReadParent(ti);
                    entry.Methods = ReadMethods(ti, ta.cFuncs);
                    break;
                case CT.TYPEKIND.TKIND_ENUM:
                case CT.TYPEKIND.TKIND_RECORD:
                case CT.TYPEKIND.TKIND_UNION:
                    entry.Members = ReadMembers(ti, ta.cVars);
                    break;
                case CT.TYPEKIND.TKIND_ALIAS:
                    entry.AliasOf = TypeDescToString(ta.tdescAlias, ti, 0);
                    break;
            }
            return entry;
        }

        private static ImplementedInterface[] ReadImpls(CT.ITypeInfo ti, int count) {
            var arr = new ImplementedInterface[count];
            for (int k = 0; k < count; k++) {
                int hRef; ti.GetRefTypeOfImplType(k, out hRef);
                CT.ITypeInfo tiImpl; ti.GetRefTypeInfo(hRef, out tiImpl);
                CT.IMPLTYPEFLAGS flags; ti.GetImplTypeFlags(k, out flags);
                try {
                    string n, d, hf; int hc;
                    tiImpl.GetDocumentation(-1, out n, out d, out hc, out hf);
                    IntPtr pIA; tiImpl.GetTypeAttr(out pIA);
                    Guid iid;
                    try {
                        var ia = (CT.TYPEATTR)Marshal.PtrToStructure(pIA, typeof(CT.TYPEATTR));
                        iid = ia.guid;
                    } finally { tiImpl.ReleaseTypeAttr(pIA); }
                    int f = (int)flags;
                    arr[k] = new ImplementedInterface {
                        Name = n, Iid = iid,
                        IsDefault       = (f & 0x01) != 0,
                        IsSource        = (f & 0x02) != 0,
                        IsRestricted    = (f & 0x04) != 0,
                        IsDefaultVtable = (f & 0x08) != 0
                    };
                } finally { Marshal.ReleaseComObject(tiImpl); }
            }
            return arr;
        }

        private static ParentRef ReadParent(CT.ITypeInfo ti) {
            int hRef; ti.GetRefTypeOfImplType(0, out hRef);
            CT.ITypeInfo tiP; ti.GetRefTypeInfo(hRef, out tiP);
            try {
                string n, d, hf; int hc;
                tiP.GetDocumentation(-1, out n, out d, out hc, out hf);
                IntPtr pPA; tiP.GetTypeAttr(out pPA);
                try {
                    var pa = (CT.TYPEATTR)Marshal.PtrToStructure(pPA, typeof(CT.TYPEATTR));
                    return new ParentRef { Name = n, Iid = pa.guid };
                } finally { tiP.ReleaseTypeAttr(pPA); }
            } finally { Marshal.ReleaseComObject(tiP); }
        }

        private static MethodEntry[] ReadMethods(CT.ITypeInfo ti, int count) {
            int elemSize = Marshal.SizeOf(typeof(CT.ELEMDESC));
            var arr = new MethodEntry[count];
            for (int m = 0; m < count; m++) {
                IntPtr pFD; ti.GetFuncDesc(m, out pFD);
                try {
                    var fd = (CT.FUNCDESC)Marshal.PtrToStructure(pFD, typeof(CT.FUNCDESC));
                    var entry = new MethodEntry {
                        DispId    = fd.memid,
                        InvKind   = fd.invkind.ToString(),
                        FuncKind  = fd.funckind.ToString(),
                        FuncFlags = (int)fd.wFuncFlags
                    };
                    var names = new string[fd.cParams + 1];
                    int cNames; ti.GetNames(fd.memid, names, names.Length, out cNames);
                    entry.Name = names[0];
                    entry.ReturnType = TypeDescToString(fd.elemdescFunc.tdesc, ti, 0);

                    var pars = new ParamEntry[fd.cParams];
                    for (int p = 0; p < fd.cParams; p++) {
                        IntPtr edPtr = new IntPtr(fd.lprgelemdescParam.ToInt64() + p * elemSize);
                        var ed = (CT.ELEMDESC)Marshal.PtrToStructure(edPtr, typeof(CT.ELEMDESC));
                        int pf = (int)ed.desc.paramdesc.wParamFlags;
                        pars[p] = new ParamEntry {
                            Name       = (p + 1 < names.Length) ? names[p + 1] : ("p" + p),
                            Type       = TypeDescToString(ed.tdesc, ti, 0),
                            IsIn       = (pf & 0x01) != 0,
                            IsOut      = (pf & 0x02) != 0,
                            IsRetVal   = (pf & 0x08) != 0,
                            IsOptional = (pf & 0x10) != 0
                        };
                    }
                    entry.Params = pars;
                    arr[m] = entry;
                } finally { ti.ReleaseFuncDesc(pFD); }
            }
            return arr;
        }

        private static EnumMember[] ReadMembers(CT.ITypeInfo ti, int count) {
            var arr = new EnumMember[count];
            for (int v = 0; v < count; v++) {
                IntPtr pVD; ti.GetVarDesc(v, out pVD);
                try {
                    var vd = (CT.VARDESC)Marshal.PtrToStructure(pVD, typeof(CT.VARDESC));
                    var names = new string[1];
                    int cNames; ti.GetNames(vd.memid, names, 1, out cNames);
                    object val = null;
                    if (vd.varkind == CT.VARKIND.VAR_CONST && vd.desc.lpvarValue != IntPtr.Zero) {
                        try { val = Marshal.GetObjectForNativeVariant(vd.desc.lpvarValue); }
                        catch { }
                    }
                    arr[v] = new EnumMember {
                        Name   = names[0],
                        Value  = val,
                        DispId = vd.memid,
                        Kind   = vd.varkind.ToString()
                    };
                } finally { ti.ReleaseVarDesc(pVD); }
            }
            return arr;
        }

        private static string TypeDescToString(CT.TYPEDESC td, CT.ITypeInfo ti, int depth) {
            if (depth > 8) return "...";
            int vt = (int)td.vt;
            switch (vt) {
                case 2:  return "short";
                case 3:  return "long";
                case 4:  return "float";
                case 5:  return "double";
                case 6:  return "currency";
                case 7:  return "DATE";
                case 8:  return "BSTR";
                case 9:  return "IDispatch*";
                case 10: return "SCODE";
                case 11: return "VARIANT_BOOL";
                case 12: return "VARIANT";
                case 13: return "IUnknown*";
                case 14: return "DECIMAL";
                case 16: return "char";
                case 17: return "byte";
                case 18: return "ushort";
                case 19: return "ulong";
                case 20: return "int64";
                case 21: return "uint64";
                case 22: return "INT";
                case 23: return "UINT";
                case 24: return "void";
                case 25: return "HRESULT";
                case 26: {
                    if (td.lpValue != IntPtr.Zero) {
                        var inner = (CT.TYPEDESC)Marshal.PtrToStructure(td.lpValue, typeof(CT.TYPEDESC));
                        return TypeDescToString(inner, ti, depth + 1) + "*";
                    }
                    return "void*";
                }
                case 27: return "SAFEARRAY";
                case 28: return "CARRAY";
                case 29: {
                    // VT_USERDEFINED: lpValue is the HREFTYPE union member, only
                    // the low 32 bits are meaningful — on x64 the high 4 bytes
                    // come from uninitialized union storage. Mask explicitly.
                    int hRef = unchecked((int)(td.lpValue.ToInt64() & 0xFFFFFFFFL));
                    try {
                        CT.ITypeInfo tiU; ti.GetRefTypeInfo(hRef, out tiU);
                        try {
                            string n, d, hf; int hc;
                            tiU.GetDocumentation(-1, out n, out d, out hc, out hf);
                            return n;
                        } finally { Marshal.ReleaseComObject(tiU); }
                    } catch { return "UserDefined"; }
                }
                case 30: return "LPSTR";
                case 31: return "LPWSTR";
                case 36: return "RECORD";
                case 37: return "INT_PTR";
                case 38: return "UINT_PTR";
                default: return "VT_" + vt;
            }
        }

        private static string[] DecodeTypeFlags(int v) {
            var list = new List<string>();
            if ((v & 0x0001) != 0) list.Add("AppObject");
            if ((v & 0x0002) != 0) list.Add("CanCreate");
            if ((v & 0x0004) != 0) list.Add("Licensed");
            if ((v & 0x0008) != 0) list.Add("PreDeclId");
            if ((v & 0x0010) != 0) list.Add("Hidden");
            if ((v & 0x0020) != 0) list.Add("Control");
            if ((v & 0x0040) != 0) list.Add("Dual");
            if ((v & 0x0080) != 0) list.Add("NonExtensible");
            if ((v & 0x0100) != 0) list.Add("OleAutomation");
            if ((v & 0x0200) != 0) list.Add("Restricted");
            if ((v & 0x0400) != 0) list.Add("Aggregatable");
            if ((v & 0x0800) != 0) list.Add("Replaceable");
            if ((v & 0x1000) != 0) list.Add("Dispatchable");
            if ((v & 0x2000) != 0) list.Add("ReverseBind");
            if ((v & 0x4000) != 0) list.Add("Proxy");
            return list.ToArray();
        }
    }
}
'@
}

function Get-TypeLibInfoSafe {
    param([string]$FilePath)
    Initialize-TypeLibInterop
    try {
        return [SysUtils.Interop.TypeLibReader]::Read($FilePath)
    } catch {
        return $null
    }
}
