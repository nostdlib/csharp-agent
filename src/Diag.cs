using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace CSharpAgent
{
#if DEBUG
    // DEBUG-ONLY DIAGNOSTICS — the whole type is compiled out of every Release build
    // (#if DEBUG; every call site is guarded too), so no log strings, no log file, nothing
    // diag-shaped survives there. Debug builds append one line per step to
    // csharp-agent-debug-<pid>.log NEXT TO THE EXE (runtime entry) or in %TEMP% (the 0x0B
    // deserialization path loads this assembly from bytes — Location is empty there, so the
    // exe dir is unknowable). Every line flushes immediately: a native crash past the inject
    // kills the process without unwinding — the last line on disk IS the finding.
    //
    // Step vocabulary (call sites, all #if DEBUG-guarded):
    //   [1]…[9]      beacon lifecycle (Program/Beacon) — the last number shown marks how
    //                far a silent run got
    //   [exit] …     every fatal branch — the last [exit] names the death
    //   [cmd] 0x…    a delivered operator command
    //   [inj n]      ShellcodeRunner inject steps — the process-vanish marker is [inj 8]
    internal static class Diag
    {
        private static readonly string LogPath = ResolveLogPath();

        private static string ResolveLogPath()
        {
            var name = "csharp-agent-debug";
            try { name += "-" + Process.GetCurrentProcess().Id; }
            catch { }
            name += ".log";
            try
            {
                var exe = Assembly.GetExecutingAssembly().Location;
                if (exe != null && exe.Length > 0)
                {
                    var dir = Path.GetDirectoryName(exe);
                    if (dir != null && dir.Length > 0) return Path.Combine(dir, name);
                }
            }
            catch { }
            try { return Path.Combine(Path.GetTempPath(), name); }
            catch { return name; } // last resort — the working directory
        }

        // Kept the old name (Show) so the call sites read exactly like the popup build they
        // replaced — it writes a file line now, not a box.
        internal static void Show(string step, string detail)
        {
            try
            {
                File.AppendAllText(LogPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") +
                    " [" + step + "] " + detail.Replace("\n", " | ") + "\r\n");
            }
            catch { } // logging must never become the crash
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

        // "0x…" hex for a native pointer/NTSTATUS — the inject-step lines print addresses.
        internal static string Hex(IntPtr p)
        {
            return "0x" + p.ToInt64().ToString("X");
        }
    }
#endif
}
