using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
#if DEBUG
    // DEBUG-ONLY DIAGNOSTICS — the whole type is compiled out of every Release build
    // (#if DEBUG; every call site is guarded too), so no popup captions, no user32 bind,
    // nothing diag-shaped survives there. Debug builds (-debug assets) surface a blocking
    // MessageBox on EVERY decision/exit path — the LAST caption that appeared marks how
    // far the agent got; the step AFTER it is the one that died or the branch that quit.
    // The beacon loop stays SILENT on healthy idle iterations (an empty-body 200 is the
    // normal steady state) — only lifecycle steps, operator commands and fatal exits pop.
    //
    // Step vocabulary (call sites, all #if DEBUG-guarded):
    //   [1]…[9]      beacon lifecycle (Program/Beacon) — the last number shown marks how
    //                far a silent run got
    //   [exit] …     every fatal branch — the last [exit] names the death
    //   [cmd] 0x…    a delivered operator command
    //   [inj n]      ShellcodeRunner inject steps — the process-vanish marker is [inj 8]
    internal static class Diag
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

        // MB_SETFOREGROUND | MB_TOPMOST | MB_ICONINFORMATION — a diag box must never hide
        // behind the console it was launched from.
        private const uint Flags = 0x50040;

        internal static void Show(string step, string detail)
        {
            try { MessageBox(IntPtr.Zero, detail, "c2 diag " + step, Flags); }
            catch { } // a dead desktop / services session must never turn the diag into the crash
        }

        // Flatten the exception chain into one line: WebException buries the schannel
        // verdict (the whole diagnostic value on Win7) an InnerException or two deep.
        internal static string Describe(Exception ex)
        {
            var text = ex.Message;
            var inner = ex.InnerException;
            while (inner != null)
            {
                text += " -> " + inner.Message;
                inner = inner.InnerException;
            }
            return text;
        }

        // "0x…" hex for a native pointer/NTSTATUS — the inject-step popups print addresses.
        internal static string Hex(IntPtr p)
        {
            return "0x" + p.ToInt64().ToString("X");
        }
    }
#endif
}
