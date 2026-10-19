# csharp-agent

The C# HTTP-beacon agent for the [C2](https://github.com/nostdlib) platform — the successor of
`CSharpShellcodeInjector`. It is a .NET Framework **2.0** class library (single `System` reference,
no LINQ, no unsafe code) whose COM-visible entry (`Program`, fired from its static constructor)
loads via the C2's insecure-deserialization chain, then turns the host process into an implant
that speaks the SAME beacon protocol as the
[jscript-agent](https://github.com/nostdlib/jscript-agent).

The infection chain it sits in:

```
JScript stager → (0x0B UpgradeNetFramework, deserialization) → csharp-agent → (0x0C UpgradeNative, injection) → PIC WebSocket agent
```

## Environment contract

The agent carries **no baked configuration**; the process environment the host left behind picks
the mode:

| Variable | Meaning |
|---|---|
| `H_URL` | The beacon endpoint — the HTTP relay root (`https://<relay>/`). Set ⇒ agent mode: the beacon loop parks the loading thread forever (see Host contract). |

`W_URL` (the relay the injected WebSocket agent connects back to) is read by the INJECTED agent
from the process environment — the `0x0C` payload's trailing env lines set it. The `0x0C` PIC
bytes ride the command itself (`[binLen:u32le][bytes][env lines]`): there is NO runtime
download and NO `A_URL` anywhere in this agent (2026-09-17 — the `C2Payload` download arm was
removed; the C2 fetches the bytes browser-side and embeds them).

`X-Client-Features` always ships `1000000000000000` — exactly ONE capability,
**UpgradeNative** (category 4). `X-Client-Id` is `2` (this breed; the JScript agent is `1`).

## Host contract

The entry never exits the process on its own:

- **Agent mode is a blocking takeover.** The beacon loop runs ON the thread that deserialized the
  assembly and never returns on its own. The JScript agent whose `0x0B` UpgradeNetFramework loaded us stays
  parked inside its dispatch — so exactly ONE agent beacons the shared MachineGuid session. When
  the beacon fails fatally AFTER the first successful POST, `Run` returns and the JScript agent
  underneath resumes beaconing as a fallback (the completed status already went out honestly —
  the agent WAS up). A failure on the FIRST POST takes the same quiet fatal: presence was
  never established and the owed reply never ships — the C2's delivery task sees no status
  at all (neither a false 0 nor a 1; its wait simply times out), and re-delivery of the
  upgrade remains the recovery path.
- **Owed first reply.** The `0x0B` command that loaded us parked a requester on the relay's
  response FIFO; the FIRST beacon POST carries an 8-byte reply frame — status 0, corrId 0
  (chain completed; id 0 = unmatched) — inside the standard length prefix, so the C2's
  delivery task observes success the moment the agent comes up. An unsolicited response
  body is dropped by the relay, so this is harmless for non-upgrade starts.
- **The injected agent rides the same process.** `UpgradeNative` injects the delivered PIC (embedded in the command) into
  the current process; the agent therefore STAYS resident afterwards (exiting would kill the
  injected agent). `Exit` (`0x0A`) is the explicit operator terminate: it kills the host process
  and everything in it.

## Beacon contract (v3)

Identical to the jscript-agent's contract (spoken against the HTTP relay's root):

- **`X-Device-Id` derives the canonical per-machine value**: the `MachineGuid` from the
  **32-bit registry view** (`RRF_SUBKEY_WOW6432KEY` — the Wow6432Node copy on 64-bit hosts,
  which is the only view the x86-re-hosted JScript breed can reach), falling back to the SMBIOS
  type-1 UUID (byte-identical to `Win32_ComputerSystemProduct.UUID`), omitted when neither
  resolves. The assembly's OWN host bitness never picks the view — a 64-bit host reading the
  native copy would mint a second agent row on the same target.
- **`X-Session-Id` is a random per-RUNTIME GUID** (`Guid.NewGuid()`, generated once per
  process): NOT identity — rows/queues stay keyed by the machine uuid — but a fresh value each
  launch lets the operator tell concurrent or succeeding runtimes on one machine apart (after a
  `0x0B` handover the same machine uuid's beacons carry OUR new key, making the JS→C# takeover
  visible in the C2's info panel).
- **POST** to `H_URL` with the full identity header set (API 1) on every request. Bodies are
  binary frame streams on both sides — a frame is `[u32le length][bytes]`, a body is
  consecutive frames. The request body carries every reply owed since the last POST
  (a reply frame is `[status:u32le][corrId:u32le]`), empty when none is pending.
- **TLS**: `ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072` (the int-cast
  form — `Tls12` doesn't exist on CLR 2.0) ADDS TLS 1.2 to the OS-default mask, never replaces
  it: Win10/11 keep negotiating 1.2 while stock Win7 falls back to its legacy TLS, which the
  relay edge accepts. A Tls12-ONLY mask bricks Win7 — the HTTPS connect dies before the first
  POST.
- Every successful answer is a `200` whose body is the same frame stream of queued commands —
  a command frame is `[opcode:byte][corrId:u32le][payload]`, batched up to 32 frames / 4 MiB;
  an empty body = nothing queued (re-POST immediately when the relay HELD the request — see
  the pacing note below). Any non-200 or transport failure (a redirect included — auto-follow
  is disabled) is fatal — the loop unwinds, no retry.
- The relay holds each request server-side for a random 25–35 s **while a C2 panel is
  attached**; detached, it answers an immediate empty 200. The agent detects an unheld
  answer (it returned faster than any hold could) and sleeps the hold window locally, so
  the request timeout (60 s) only ever bounds a STALLED relay.

### Commands

| Opcode | Command | Behavior |
|---|---|---|
| `0x0A` | Exit | Kills the host process (and any agent injected into it). No reply. |
| `0x0B` | UpgradeNetFramework | Replies status `2` (the deserialization upgrade is the JScript agent's — this breed is already native). |
| `0x0C` | UpgradeNative | Payload after the opcode: `[binLen:u32le][PIC binary][NAME=value env lines]` (same env-line style as the `0x0B` headers). The PIC bytes ride the command. `W_URL` (the relay the injected WebSocket agent reads from the process env) is **the only name the env lines may set — a whitelist, not an arbitrary-setenv primitive**: any other NAME is ignored, and lines containing non-ASCII bytes are rejected whole (ASCII best-fit would silently mangle them into a broken URL). A missing OR empty `W_URL` refuses the injection (status `1`) — the PIC exits the host process when its URL is absent or empty, so a W_URL-less 0x0C is a command that would kill the host on arrival. Replies `[status][corrId]`: `1` = failed / nothing to inject (a pre-injection failure — bad payload length, a refused W_URL, or an exception in the injection steps). A SUCCESSFUL injection sends NO reply: the PIC entry point never returns (every path ends in ExitProcess), so the C2's wait for a 0x0C status times out and success is observed by the WebSocket agent appearing on the relay; a `0` is reachable only from payloads that return (lab stubs). |
| other | unknown | Replies u32 `2`. |

### Operational notes

- **Detached-relay pacing.** The relay holds a poll only while a C2 panel is attached; with
  no panel attached it answers an immediate empty 200. The agent detects the unheld answer
  (it came back faster than any hold could have) and sleeps the hold window locally
  (25–35 s, jittered): the POST cadence stays ~1 per 30 s whether or not an operator is
  watching — the request rate never reveals operator presence, and neither the victim's
  CPU nor the relay ever sees a request storm.
- **Corrupted-payload boundary.** `0x0C` jumps into the delivered bytes by design; there is
  no managed containment for a fault INSIDE native payload code (on CLR4 an access
  violation is a corrupted-state exception no catch block survives). A corrupted or
  truncated PIC therefore dies loudly on the victim — payload integrity is the C2's
  responsibility upstream (it fetches, validates, and embeds the bytes; TLS guards the wire).
- **System proxy.** The beacon uses the machine's default (WinInet/IE) proxy — deliberate:
  enterprise egress usually requires it, and implant traffic blending into the host's own
  proxy usage is the posture this agent takes. The tradeoff: the identity headers are
  visible to that proxy's logs.

## Build

Old-style csproj targeting .NET Framework 2.0 (compilable by any VS 2017+ / Build Tools msbuild):

```
msbuild csharp-agent.csproj /p:Configuration=Release
```

The post-build step emits `bin/Release/csharp-agent.b64.txt` (base64 of the DLL) for ad-hoc
testing of the deserialization chain.

## Releases

CI builds **one image per (arch × CLR side)** and publishes the binaries — the C2 consumes
the **binaries**, not the source: its Agents-table **CSharp-Agent** rows (one per arch ×
framework tag) point at the rolling release assets
`releases/download/release/csharp-agent-<net2|net4>-<i386|x86_64|aarch64>.dll`, fetched via
the relay `/proxy` or directly, parsed with dnlib (entry detection + identifier
obfuscation) and embedded into the deserialization blob. The UpgradeNetFramework window picks the row
by the gadget's framework tag + the target's process arch; the Persistence Manager takes
the CLR-4 side for its arch. Every push to `main` recreates the rolling releases
(`build.yml`): **`release`** carries the plain assets, **`debug`** the debug-flavored
builds under the same names — the tag is the flavor (neither is a prerelease; the
plain `release` is pinned **Latest** so the panel's "latest release" listing and its
asset pickers stay on the plain flavor);
pushing a `v*` tag publishes a stable release (`release.yml`).

Each side × arch also ships a **self-running `.exe` sibling**
(`csharp-agent-<net2|net4>-<i386|x86_64|aarch64>.exe`): the same image compiled with
`OutputType=exe`, so the runtime entry point and the deserialization static ctor share one
guarded `Main` — run it directly with `H_URL` in the environment (e.g.
`set H_URL=https://<relay>/ && csharp-agent-net2-i386.exe`) to isolate the beacon/transport
from the delivery chain. The panel never fetches these; its rows name the `.dll` assets.

**Debug vs release:** the plain assets (`csharp-agent-<side>-<arch>.{dll,exe}` — the names
the C2 panel fetches, riding the rolling **`release`** tag) have **no diagnostics
compiled in at all**: every `Diag.*` call site is wrapped in `#if DEBUG`, so a release
binary carries no diag strings, no user32 bind, nothing to strip. The debug-flavored
builds (same names, on the rolling **`debug`** tag) pop
a blocking MessageBox on every decision/exit path — the LAST caption that appeared marks
how far the agent got; the step AFTER it is the one that died or quit. Vocabulary:
`[1]–[9]` beacon lifecycle, `[exit] …` fatal branches, `[cmd] 0x…` delivered commands,
`[inj n]` inject steps (`[inj 8] entry` = the last caption before a native payload
crash). Ship debug builds only to a box you are debugging by hand — the popups are
operator-visible by design.

## License

MIT — see [LICENSE](LICENSE). Usage is governed by [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and
[SECURITY.md](SECURITY.md).
