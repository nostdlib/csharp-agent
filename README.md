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
| `A_URL` | The direct download URL of the PIC agent bytes to inject — the `0x0C` UpgradeNative command carries only env lines, so the agent ALWAYS downloads the bytes from `A_URL` at runtime; when `H_URL` is absent it also drives the legacy one-shot path (the Persistence Manager's on-logon flow). |

`W_URL` (the relay the injected WebSocket agent connects back to) is read by the INJECTED agent
from the process environment — the `0x0C` payload's env lines set it.

`X-Client-Features` always ships `1000000000000000` — exactly ONE capability,
**UpgradeNative** (category 4). `X-Client-Id` is `2` (this breed; the JScript agent is `1`).

## Host contract

The entry never exits the process on its own:

- **Agent mode is a blocking takeover.** The beacon loop runs ON the thread that deserialized the
  assembly and never returns on its own. The JScript agent whose `0x0B` UpgradeNetFramework loaded us stays
  parked inside its dispatch — so exactly ONE agent beacons the shared MachineGuid session. When
  the beacon fails fatally AFTER the first successful POST, `Run` returns and the JScript agent
  underneath resumes beaconing as a fallback (the completed status already went out honestly —
  the agent WAS up). A failure on the FIRST POST instead throws: presence was never established,
  the exception unwinds the deserialization, and the JScript agent's `0x0B` handler reports
  status 1 (failed) — never the false status 0 a quiet return would produce.
- **Owed first reply.** The `0x0B` command that loaded us parked a requester on the relay's
  response FIFO; the FIRST beacon POST carries `00000000` (u32 status 0 — chain completed), so
  the C2's delivery task observes success the moment the agent comes up. An unsolicited response
  body is dropped by the relay, so this is harmless for non-upgrade starts.
- **The injected agent rides the same process.** `UpgradeNative` injects the delivered PIC (embedded in the command, or downloaded from `A_URL` on the legacy path) into
  the current process; the agent therefore STAYS resident afterwards (exiting would kill the
  injected agent). `Exit` (`0x0A`) is the explicit operator terminate: it kills the host process
  and everything in it.

## Beacon contract (v2)

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
- **POST** to `H_URL` with the full identity header set (API 1) on every request; body =
  hex(previous command's response), empty body when none is pending.
- **TLS**: `ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072` (the int-cast
  form — `Tls12` doesn't exist on CLR 2.0) ADDS TLS 1.2 to the OS-default mask, never replaces
  it: Win10/11 keep negotiating 1.2 while stock Win7 falls back to its legacy TLS, which the
  relay edge accepts. A Tls12-ONLY mask bricks Win7 — the HTTPS connect dies before the first
  POST. The A_URL download in `C2Payload` applies the same rule.
- Every successful answer is `200 text/plain`: body = hex(next command) in the shared binary
  protocol (`[opcode][payload]`), empty body = nothing queued (re-POST immediately). Any non-200
  or transport failure is fatal — the loop unwinds, no retry.
- The relay holds each request server-side for a random 20–30 s; the request timeout is 60 s.

### Commands

| Opcode | Command | Behavior |
|---|---|---|
| `0x0A` | Exit | Kills the host process (and any agent injected into it). No reply. |
| `0x0B` | UpgradeNetFramework | Replies status `2` (the deserialization upgrade is the JScript agent's — this breed is already native). |
| `0x0C` | UpgradeNative | Payload after the opcode: `NAME=value` env lines (same env-line style as the `0x0B` headers). `A_URL` names the PIC bytes to download (`C2Payload`) and `W_URL` the relay the injected WebSocket agent reads from the process env. Replies u32 as hex: `0` = injected, `1` = failed / nothing to inject. |
| other | unknown | Replies u32 `2`. |

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
framework tag) point at the rolling prerelease assets
`releases/download/preview/csharp-agent-<net2|net4>-<i386|x86_64|aarch64>.dll`, fetched via
the relay `/proxy` or directly, parsed with dnlib (entry detection + identifier
obfuscation) and embedded into the deserialization blob. The UpgradeNetFramework window picks the row
by the gadget's framework tag + the target's process arch; the Persistence Manager takes
the CLR-4 side for its arch. Every push to `main` recreates the `preview` prerelease
(`build.yml`); pushing a `v*` tag publishes a stable release (`release.yml`).

## License

MIT — see [LICENSE](LICENSE). Usage is governed by [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and
[SECURITY.md](SECURITY.md).
