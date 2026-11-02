using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    internal class Kernel32
    {
        public delegate IntPtr GetProcAddressDelegate(IntPtr hModule, string lpProcName);
        public delegate uint GetSystemFirmwareTableDelegate(uint firmwareTableProviderSignature, uint firmwareTableID, byte[] firmwareTableBuffer, uint size);  
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate IntPtr LoadLibraryWDelegate(string lpLibFileName);
        public delegate void GetNativeSystemInfoDelegate(ref SYSTEM_INFO lpSystemInfo);

        // Read-only fields ensure immutability and prevent accidental overwriting
        public readonly GetProcAddressDelegate GetProcAddress;
        public readonly GetSystemFirmwareTableDelegate GetSystemFirmwareTable;
        public readonly LoadLibraryWDelegate LoadLibraryW;
        public readonly GetNativeSystemInfoDelegate GetNativeSystemInfo;
        public readonly IntPtr ModuleHandle;

        private static Kernel32 cachedKernel;

        private Kernel32(
            IntPtr moduleHandle,
            GetProcAddressDelegate getProcAddress,
            GetSystemFirmwareTableDelegate getSystemFirmwareTable,
            LoadLibraryWDelegate loadLibraryW,
            GetNativeSystemInfoDelegate getNativeSystemInfo)
        {
            ModuleHandle = moduleHandle;
            GetProcAddress = getProcAddress;
            GetSystemFirmwareTable = getSystemFirmwareTable;
            LoadLibraryW = loadLibraryW;
            GetNativeSystemInfo = getNativeSystemInfo;
        }

        /// <summary>
        /// Atomically resolves module and exports using the Factory Pattern.
        /// Fully compatible with .NET Framework 2.0+ via non-generic marshalling.
        /// </summary>
        public static bool TryCreateKernel32(out Kernel32 instance)
        {
            if (cachedKernel != null)
            {
                instance = cachedKernel;
                return true;
            }

            instance = null;

            IntPtr moduleHandle = PebWalker.ResolveModuleFromPeb("kernel32.dll");
            if (moduleHandle == IntPtr.Zero)
                return false;
            

            var getProcAddress = PebWalker.ResolveDelegate<GetProcAddressDelegate>("kernel32.dll", "GetProcAddress");
            var getSystemFirmwareTable = PebWalker.ResolveDelegate<GetSystemFirmwareTableDelegate>("kernel32.dll", "GetSystemFirmwareTable");
            var loadLibraryW = PebWalker.ResolveDelegate<LoadLibraryWDelegate>("kernel32.dll", "LoadLibraryW");
            var getNativeSystemInfo = PebWalker.ResolveDelegate<GetNativeSystemInfoDelegate>("kernel32.dll", "GetNativeSystemInfo");

            if (getProcAddress == null || getSystemFirmwareTable == null || loadLibraryW == null || getNativeSystemInfo == null)
                return false;
                
            cachedKernel = new Kernel32(
                moduleHandle,
                getProcAddress,
                getSystemFirmwareTable,
                loadLibraryW,
                getNativeSystemInfo
            );

            instance = cachedKernel;
            return true;
        }
    }
}