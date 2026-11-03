# ntrshd — RSH daemon for Windows NT

Remote shell daemon (`rsh` and `rcp` server) for Windows NT. It runs
commands sent by `rsh` clients and copies files for `rcp`, so you can build
software on an NT machine from elsewhere — for example from an AI agent over
the `rsh` MCP server.

One plain-C source. It builds with the **NT 3.1, 3.5 and 4.0 SDKs** and runs
on **NT 3.1 and later**, on any CPU (x86, MIPS, Alpha, PowerPC).

> **No security of any kind.** Anyone who can reach the port can run any
> command as the account that runs ntrshd. Use it on a trusted LAN only.

## Build

From an SDK command prompt, in this folder:

```
nmake              (NT 3.5, NT 4.0, and the RISC SDKs)
nmake NT31=1       (NT 3.1 only)
```

The same `Makefile` works on every SDK and CPU: compile and link go through
`cl`, which calls the right linker (`link32` on NT 3.1, `link` on 3.5/4.0),
so nothing names the linker or the architecture.

The icon and version number live in `ntrshd.rc`, which `rc` builds into
`ntrshd.res`. NT 3.5 and 4.0 link that straight into the exe, so plain
`nmake` works there. NT 3.1's older `link32` can't take a `.res` directly, so
on NT 3.1 run `nmake NT31=1`, which converts the resource with `cvtres` first.

- NT 3.1: Win32 SDK, `cl386` 8.00
- NT 3.5 / 3.51: Visual C++ 2.0 (one binary runs 3.5 → 4.0)
- NT 4.0: Visual C++ 4.2 (full feature set — see below)

`nmake clean` removes the build output.

## Run

**Double-click `ntrshd.exe`** (or run it from a prompt). It opens a console
window and serves. That is the normal way to use it. The window is a live
**status display** — version, host name, IP address, and a table of the
connected clients with the command each is running — not a scroll of output.
The title bar shows `NTRSHD: N conn` (or `NTRSHD: IDLE`).

```
ntrshd [options]
  -p PORT      listen on this port instead of 514
  -t MINUTES   stop a command that prints nothing for this long
               (0 = never, the default)
  -g SECONDS   wait this long for a grandchild's last output (default 3)
  -e           send the command's exit code as a last line
  -q           quiet: plain scrolling log instead of the status window
  -d           extra debug detail in the log
  -v           show version
  -h           help
```

**One ntrshd per port.** If another ntrshd already serves the port (in
another window, or as the service), a new one says so and does not start.
To run a second one, give it its own port with `-p`.

### As a service

```
ntrshd -install                     install, auto-start on boot
ntrshd -install -p 2514             install with options
ntrshd -install -user .\me -pass XX run as a named account (see drives below)
ntrshd -remove                      stop and remove
```

The **same exe** is both the console program and the service. When the
Service Control Manager starts it, it detects that and runs as a service;
when you double-click it, it runs in a console. Installed, it auto-starts on
boot. As a service it writes a log to `ntrshd.log` next to the exe.

`-install` **copies the exe into the system folder** (`%SystemRoot%\System32`)
and registers *that* copy. So you can install while running it from a mapped
drive (say `T:`) and the service still starts at boot, when no mapped drive
exists yet. `-remove` deletes that copy again.

Start it after installing with `net start ntrshd` (or from Control Panel →
Services), stop with `net stop ntrshd`. If an ntrshd in a console window
already serves the port, the service does not start: `net start` reports
system error 1056.

## How it behaves

- **Protocol:** BSD `rsh`. Optional stderr channel (a port of `0` or none
  means stderr comes back with stdout), client user, server user, command,
  then the status byte.
- **Commands** run as `cmd /c <command>`, exactly as sent — no rewriting.
- **Many sessions at once**, each in its own thread and its own hidden
  process group, so one session cannot disturb another.
- **All output is delivered** before the connection closes, byte for byte
  (binary-safe), and the socket closes cleanly (FIN, never a reset).
- **Client goes away → the command is stopped** (`Ctrl+Break` to its group,
  then it is terminated if it does not stop).
- **stdin** is the client's input channel; commands that ignore stdin are
  unaffected.
- **At startup** it logs this machine's host name and IP address(es), like
  `ipconfig`, so you can see which address to point clients at.
- **Status window:** the console shows a live status screen — version, host,
  IP, and the running sessions with their commands — refreshed about once a
  second, with the connection count in the title bar. Command output is **not**
  echoed to the window; it goes only to the client. (This also means large
  output is no longer slowed by writing every line to the screen.) If some
  other program holds the port, the status line and the title bar say
  **NOT LISTENING**, and ntrshd tries again every 10 seconds.
- **Logging:** every event (connect, command, process id, bytes sent, exit
  code, and how the session ended) is written to `ntrshd.log` next to the exe,
  in both console and service mode. `-q` replaces the status window with a
  plain scrolling log in the console.
- **`Ctrl+C` or `Ctrl+Break` quits.** The first press stops accepting new
  connections and gives the running commands a few seconds to stop; press
  again to kill everything and exit at once (for when something is wedged).
  **Closing the window** quits at once: it kills the running commands and
  tells their clients.

## Capabilities by NT version

Built with its matching SDK for each target:

| Feature | NT 3.1 | NT 3.5 / 3.51 | NT 4.0+ |
|---|---|---|---|
| rsh, rcp, service, multi-session, stdin | yes | yes | yes |
| per-session hidden process group | yes | yes | yes |
| stop command on client disconnect | yes | yes | yes |
| sockets made non-inheritable (`SetHandleInformation`) | no¹ | no¹ | **yes** |

¹ NT 3.1 has no `SetHandleInformation`; the NT 3.5 import libraries predate
it too. On those, a sibling command can briefly inherit a session's socket,
but the clean `shutdown()` still ends the client's connection at once — the
socket handle is only freed when the sibling exits. On **NT 4.0 this is fully
fixed**: no socket is ever inherited. Build NT 4.0 targets (including MIPS,
Alpha, PowerPC) with the NT 4.0 SDK to get this.

## Mapped network drives

A command sees only the drives of the account that runs ntrshd. If you need
a user's mapped drive (say `T:`), the simplest way is to run ntrshd in that
user's session — for example from a login/startup item under autologon. A
service runs in its own logon; installed with `-user`, it runs as that
account, but interactively-mapped drives are not shared into it and must be
re-established there.

## Status

Builds clean under the NT 3.1, 3.5 and 4.0 SDKs, and passes functional tests
(rsh, rcp handshake, stderr channel and signal, half-close, empty command)
under Wine.

Validated on a **real NT 4.0 MIPS machine** (RM300, 4-way R4400): single
commands, 8 simultaneous sessions, ~800-line output delivered complete,
client-reset stops the running command, and rcp in both directions — all
pass. The 1000-session handle-leak soak is still a real-NT item to run.
