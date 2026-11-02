using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    internal class PebWalker
    {
        public static IntPtr IntPtrAdd(IntPtr p0, int p1)
        {
            return new IntPtr((IntPtr.Size == 8 ? p0.ToInt64() : p0.ToInt32()) + p1);
        }

        public static TDelegate ResolveDelegate<TDelegate>(string moduleName, string exportName) where TDelegate : class
        {
            IntPtr moduleHandle = ResolveModuleFromPeb(moduleName);

            if (moduleHandle == IntPtr.Zero)
                return null;

            IntPtr ptrExport = ResolveExportByHash(moduleHandle, HashString(exportName));
            if (ptrExport == IntPtr.Zero)
                return null;

            return Marshal.GetDelegateForFunctionPointer(ptrExport, typeof(TDelegate)) as TDelegate;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr GetTebDelegate();

        public static IntPtr GetTebAddress(){
            var processorArch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            byte[] asm;
            if (processorArch == "ARM64")
                // mov x0, x18; ret
                asm = new byte[] { 0xE0, 0x03, 0x12, 0xAA, 0xC0, 0x03, 0x5F, 0xD6 };
            else if (IntPtr.Size == 8)
                // mov rax, qword ptr gs:[0x30]; ret
                asm = new byte[] { 0x65, 0x48, 0xA1, 0x30, 0, 0, 0, 0, 0, 0, 0, 0xC3 };
            else
                // mov eax, dword ptr fs:[0x18]; ret
                asm = new byte[] { 0x64, 0xA1, 0x18, 0, 0, 0, 0xC3 };

            IntPtr ptr = Marshal.AllocHGlobal(asm.Length);
            Marshal.Copy(asm, 0, ptr, asm.Length);

            uint oldProtect = 0;
            bool success = false;

            try
            {
                success = NativeImports.ChangeMemoryProtection(ptr, (UIntPtr)asm.Length, 0x40, out oldProtect);
                if (!success)
                {
                    Marshal.FreeHGlobal(ptr);
                    return IntPtr.Zero;
                }

                if (processorArch == "ARM64")
                {
                    NativeImports.FlushInstructionCache(new IntPtr(-1), ptr, (UIntPtr)asm.Length);
                }

                var getTeb = (GetTebDelegate)Marshal.GetDelegateForFunctionPointer(ptr, typeof(GetTebDelegate));
                IntPtr tebAddress = getTeb();

                return tebAddress;
            }
            finally
            {
                if (success)
                {
                    NativeImports.ChangeMemoryProtection(ptr, (UIntPtr)asm.Length, oldProtect, out oldProtect);
                }
                Marshal.FreeHGlobal(ptr);
            }
        }

        public static IntPtr GetPebAddress()
        {
            IntPtr tebAddress = GetTebAddress();
            if (tebAddress == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr pebAddress = Marshal.ReadIntPtr(IntPtrAdd(tebAddress, IntPtr.Size == 8 ? 0x60 : 0x30));
            return pebAddress;
        }

        public static IntPtr ResolveModuleFromPeb(string moduleName)
        {
            IntPtr pebAddress = GetPebAddress();
            if (pebAddress == IntPtr.Zero)
                return IntPtr.Zero;

            return ResolveModuleFromPeb(pebAddress, moduleName);
        }

        public static IntPtr ResolveModuleFromPeb(IntPtr pebAddress, string moduleName)
        {
            int ldrOffset = IntPtr.Size == 8 ? 0x18 : 0x0C;
            IntPtr ldrPtr = Marshal.ReadIntPtr(IntPtrAdd(pebAddress, ldrOffset));
            if (ldrPtr == IntPtr.Zero) return IntPtr.Zero;

            int memOrderOffset = IntPtr.Size == 8 ? 0x20 : 0x14;
            IntPtr listHead = IntPtrAdd(ldrPtr, memOrderOffset);
            IntPtr listCurrent = Marshal.ReadIntPtr(listHead);

            while (listCurrent != listHead && listCurrent != IntPtr.Zero)
            {
                int inMemoryOrderLinksOffset = IntPtr.Size == 8 ? 0x10 : 0x08;
                IntPtr entryBase = IntPtrAdd(listCurrent, -inMemoryOrderLinksOffset);

                int dllBaseOffset = IntPtr.Size == 8 ? 0x30 : 0x18;
                IntPtr dllBase = Marshal.ReadIntPtr(IntPtrAdd(entryBase, dllBaseOffset));
                
                int lengthOffset = IntPtr.Size == 8 ? 0x58 : 0x2C;
                ushort nameLen = (ushort)Marshal.ReadInt16(IntPtrAdd(entryBase, lengthOffset));

                int bufferOffset = IntPtr.Size == 8 ? 0x60 : 0x30;
                IntPtr pwszBuffer = Marshal.ReadIntPtr(IntPtrAdd(entryBase, bufferOffset));

                if (pwszBuffer != IntPtr.Zero)
                {
                    string curModuleName = Marshal.PtrToStringUni(pwszBuffer, nameLen / 2);
                    if (!string.IsNullOrEmpty(curModuleName) && curModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        return dllBase;
                    }
                }
                listCurrent = Marshal.ReadIntPtr(listCurrent);
            }

            return IntPtr.Zero;
        }

        public static IntPtr ResolveExportByHash(IntPtr moduleBase, ulong targetHash)
        {
            if (moduleBase == IntPtr.Zero)
                return IntPtr.Zero;

            ushort e_magic = (ushort)Marshal.ReadInt16(moduleBase);
            if (e_magic != 0x5A4D)
                return IntPtr.Zero;

            int e_lfanew = Marshal.ReadInt32(IntPtrAdd(moduleBase, 0x3C));
            IntPtr ntHeaders = IntPtrAdd(moduleBase, e_lfanew);

            uint ntSignature = (uint)Marshal.ReadInt32(ntHeaders);
            if (ntSignature != 0x00004550) // IMAGE_NT_SIGNATURE
                return IntPtr.Zero;

            IntPtr optionalHeader = IntPtrAdd(ntHeaders, 24);
            ushort optionalMagic = (ushort)Marshal.ReadInt16(optionalHeader);

            uint exportRva = 0;
            uint exportSize = 0;

            if (optionalMagic == 0x10b) // IMAGE_NT_OPTIONAL_HDR32_MAGIC
            {
                int exportDirEntryOffset = 0x60;
                exportRva = (uint)Marshal.ReadInt32(IntPtrAdd(optionalHeader, exportDirEntryOffset));
                exportSize = (uint)Marshal.ReadInt32(IntPtrAdd(optionalHeader, exportDirEntryOffset + 4));
            }
            else if (optionalMagic == 0x20b) // IMAGE_NT_OPTIONAL_HDR64_MAGIC
            {
                int exportDirEntryOffset = 0x70;
                exportRva = (uint)Marshal.ReadInt32(IntPtrAdd(optionalHeader, exportDirEntryOffset));
                exportSize = (uint)Marshal.ReadInt32(IntPtrAdd(optionalHeader, exportDirEntryOffset + 4));
            }
            else
            {
                return IntPtr.Zero;
            }

            if (exportRva == 0)
                return IntPtr.Zero;

            IntPtr exportDir = IntPtrAdd(moduleBase, (int)exportRva);

            uint numberOfFunctions = (uint)Marshal.ReadInt32(IntPtrAdd(exportDir, 0x14));
            uint numberOfNames = (uint)Marshal.ReadInt32(IntPtrAdd(exportDir, 0x18));
            uint addressOfFunctionsRva = (uint)Marshal.ReadInt32(IntPtrAdd(exportDir, 0x1C));
            uint addressOfNamesRva = (uint)Marshal.ReadInt32(IntPtrAdd(exportDir, 0x20));
            uint addressOfOrdinalsRva = (uint)Marshal.ReadInt32(IntPtrAdd(exportDir, 0x24));

            IntPtr functions = IntPtrAdd(moduleBase, (int)addressOfFunctionsRva);
            IntPtr names = IntPtrAdd(moduleBase, (int)addressOfNamesRva);
            IntPtr ordinals = IntPtrAdd(moduleBase, (int)addressOfOrdinalsRva);

            for (uint i = 0; i < numberOfNames; i++)
            {
                uint nameRva = (uint)Marshal.ReadInt32(IntPtrAdd(names, (int)(i * 4)));
                string funcName = Marshal.PtrToStringAnsi(IntPtrAdd(moduleBase, (int)nameRva));

                if (!string.IsNullOrEmpty(funcName) && HashString(funcName) == targetHash)
                {
                    ushort ordinal = (ushort)Marshal.ReadInt16(IntPtrAdd(ordinals, (int)(i * 2)));
                    if (ordinal >= numberOfFunctions)
                        return IntPtr.Zero;

                    uint functionRva = (uint)Marshal.ReadInt32(IntPtrAdd(functions, ordinal * 4));

                    if (functionRva >= exportRva && functionRva < exportRva + exportSize)
                        return IntPtr.Zero;

                    return IntPtrAdd(moduleBase, (int)functionRva);
                }
            }

            return IntPtr.Zero;
        }

        public static IntPtr ResolveFromModuleByHash(string moduleName, ulong exportHash)
        {
            IntPtr moduleBase = ResolveModuleFromPeb(moduleName);
            return ResolveExportByHash(moduleBase, exportHash);
        }

        public static uint HashString(string str)
        {
            uint hash = 77777;
            foreach (char c in str)
            {
                char uc = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
                hash = ((hash << 5) + hash) + uc;
            }
            return hash;
        }
    }
}