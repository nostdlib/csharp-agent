using System;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    // DIAGNOSTIC — POPUPS ON EVERY DECISION/EXIT PATH. Ship this build ONLY to a box you
    // are debugging by hand (the Win7 start-and-exit hunt); strip Diag.cs + the Diag.Show
    // call sites before a real op — every path here surfaces a blocking MessageBox on the
    // target desktop.
    //
    // Reading a run: the captions are numbered "[1] start" → "[9] …" plus "[exit] …" —
    // the LAST caption that appeared marks how far the agent got; the step AFTER it is the
    // one that died or the branch that quit. The beacon loop stays SILENT on healthy idle
    // iterations (an empty-body 200 is the normal steady state) — only lifecycle steps,
    // operator commands and fatal exits pop.
    //
    // P/Invoke binds by ImplMap and is untouched by the C2's identifier obfuscation, and
    // user32!MessageBoxW exists on every Windows the agent targets (Win7 included) — no
    // framework dependency beyond the one System reference.
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
}
