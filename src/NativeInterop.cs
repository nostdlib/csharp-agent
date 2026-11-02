using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
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
    internal delegate int EntryDelegate(ulong injectorVersion);

    internal static class NativeImports
    {
        [DllImport("kernel32.dll", EntryPoint = "VirtualProtect", SetLastError = true)]
        internal static extern bool ChangeMemoryProtection(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll", EntryPoint = "FlushInstructionCache", SetLastError = true)]
        internal static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);
    }
}