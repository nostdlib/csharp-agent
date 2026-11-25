#if DEBUG
using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    internal class User32
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public delegate int MessageBoxWDelegate(IntPtr hWnd, string text, string caption, uint type);

        public MessageBoxWDelegate MessageBoxW;
        public IntPtr ModuleHandle;

        private static User32 _cachedInstance;

        private User32(IntPtr moduleHandle, MessageBoxWDelegate messageBoxW)
        {
            ModuleHandle = moduleHandle;
            MessageBoxW = messageBoxW;
        }

        public static bool TryCreateUser32(out User32 instance)
        {
            if (_cachedInstance != null)
            {
                instance = _cachedInstance;
                return true;
            }

            instance = null;
            IntPtr moduleHandle = PebWalker.ResolveModuleFromPeb("user32.dll");
            if (moduleHandle == IntPtr.Zero)
            {
                Kernel32 k32;
                if (Kernel32.TryCreateKernel32(out k32) && k32 != null)
                {
                    moduleHandle = k32.LoadLibraryW("user32.dll");
                }
            }

            var messageBoxW = PebWalker.ResolveDelegate<MessageBoxWDelegate>("user32.dll", "MessageBoxW");
            if (messageBoxW == null)
                return false;

            _cachedInstance = new User32(moduleHandle, messageBoxW);
            instance = _cachedInstance;
            return true;
        }
    }
}
#endif