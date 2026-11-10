# ntrshd — RSH daemon for Windows NT

Remote shell daemon (`rsh` and `rcp` server) for Windows NT. It runs
commands sent by `rsh` clients and copies files for `rcp`, so you can build
software on an NT machine from elsewhere — for example from an AI agent over
the `rsh` MCP server.

One plain-C source. It builds with the **NT 3.1, 3.5 and 4.0 SDKs** and runs
on **NT 3.1 and later**, on any CPU (x86, MIPS, Alpha, PowerPC). Every build
has the same features.

security: open (+ +)

## Download

Each [release](https://github.com/tenox7/ntrshd/releases) has an exe for
every CPU and NT version, named `ntrshd-<cpu>-<nt>.exe`:

| CPU | NT 3.1 | NT 3.5 / 3.51 | NT 4.0 |
|---|---|---|---|
| x86 | `ntrshd-x86-nt31.exe` | `ntrshd-x86-nt35.exe` | `ntrshd-x86-nt40.exe` |
| MIPS | `ntrshd-mips-nt31.exe` | `ntrshd-mips-nt35.exe` | `ntrshd-mips-nt40.exe` |
| Alpha | `ntrshd-axp-nt31.exe` | `ntrshd-axp-nt35.exe` | `ntrshd-axp-nt40.exe` |
| PowerPC | none: NT 3.1 has no PowerPC | `ntrshd-ppc-nt35.exe` | `ntrshd-ppc-nt40.exe` |

Take the one for your CPU and NT version. Each one also runs on later NT
versions. You may rename it to `ntrshd.exe`; `-install` names its copy
`ntrshd.exe` anyway.

## Build

From an SDK command prompt, in this folder:

```
nmake
```

That's all, on every SDK (NT 3.1, 3.5, 4.0) and every CPU (x86, MIPS,
Alpha, PowerPC). The `Makefile` asks `cl` for its version and does the rest.
Compile and link go through `cl`, which calls the right linker (`link32` on
NT 3.1, `link` later), so nothing names the linker or the architecture.

The icon and version number live in `ntrshd.rc`, which `rc` builds into
`ntrshd.res`. NT 3.5 and later link that straight into the exe. NT 3.1's
`link32` can't take a `.res`, so on NT 3.1 the Makefile first converts it
with `cvtres` for the CPU in the `CPU` variable (`i386`, `MIPS` or `ALPHA`),
which the SDK's setenv sets. Without `CPU` it assumes `i386`.

Visual C++ 4.x marks an exe as made for Windows 4.0. The Makefile marks it
3.10 instead, as the older compilers do, so NT 3.5 starts it too.

The release exes were built on NT itself, each with its own compiler:

- NT 3.1: the Win32 SDK of 1993 (`cl386` 8.00, and its MIPS and Alpha
  compilers). The MIPS one ignores `/O2`, so that exe is not optimized.
- NT 3.5: Visual C++ 4.x on NT 3.51.
- NT 4.0: Visual C++ 4.x on NT 4.0.

Visual C++ 2.0 builds it too. `nmake clean` removes the build output.

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

Commands run in the folder ntrshd was started in.

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
boot.

`-install` **copies the exe into the system folder** (`%SystemRoot%\System32`)
as `ntrshd.exe` and registers *that* copy. So you can install while running
it from a mapped drive (say `T:`) and the service still starts at boot, when
no mapped drive exists yet. `-remove` deletes that copy again.

With `-user`, `-install` also gives that account the right to **log on as
a service**, as Control Panel → Services does when you set an account
there. Without that right, `net start` fails with system error 1069.

Start it after installing with `net start ntrshd` (or from Control Panel →
Services), stop with `net stop ntrshd`. If an ntrshd in a console window
already serves the port, the service does not start: `net start` reports
system error 1056.

## How it behaves

- **Protocol:** BSD `rsh`. Optional stderr channel (a port of `0` or none
  means stderr comes back with stdout), client user, server user, command,
  then the status byte.
- **Commands** run as `cmd /c <command>`, exactly as sent — no rewriting.
  The one exception is the rsh-mcp script, below.
- **rsh-mcp gets the exit status.** To learn a command's exit status from
  a Unix host, the [rsh-mcp](https://github.com/tenox7/rsh-mcp) server asks
  for `sh -s rsh-mcp-1` and writes a short script to it, with the command
  inside. NT has no `sh`, so ntrshd reads that script itself: it runs the
  command with `cmd /c` and no stdin, and ends the output with the exit
  code the way the script would. Several lines become one command line,
  joined with `&`, as if typed on one line.
  So rsh-mcp's `exec` works on NT as on Unix, with no options, and `-e` is
  not needed for it. Any other command, plain `sh` included, runs as
  before.
- **Each session is on its own.** Each command runs under a small helper:
  ntrshd itself, started as `ntrshd -session`. So Task Manager shows one
  more `ntrshd.exe` for each running command. The helper runs `cmd /c` in a
  hidden console of its own.
  - Nothing is inherited from ntrshd or from another session: no socket,
    no pipe. This holds on every NT version, NT 3.1 included.
  - A `Ctrl+C`, `Ctrl+Break` or closed console in one session reaches no
    other session, and not ntrshd.
- **Stopping a command:** the helper sends `Ctrl+Break` to every process in
  its console, waits 5 seconds, then kills what is left. This happens when:
  - the client sends a signal on the stderr channel (BSD `rsh` does on
    `Ctrl+C`);
  - the client resets the connection, or goes away;
  - the command prints nothing for longer than `-t`;
  - ntrshd quits.

  If ntrshd itself is killed, each helper kills its command too.
- **stdin** is the client's input channel; commands that ignore stdin are
  unaffected. When the client closes its sending side (FIN), that means
  "no more input", as in BSD `rsh`: the command keeps running. In an
  rsh-mcp script session the input was the script, so there a FIN means
  rsh-mcp gave up (its timeout, or a cancel), and the command is stopped.
- **All output is delivered** before the connection closes, byte for byte
  (binary-safe). At the end ntrshd sends its FIN at once, so the client sees
  the end of the output right away, then waits for the client to close too.
  It never closes with a reset, which could lose output.
- **Many clients at once.** Each connection gets its own thread at once.
  NT Workstation (not Server) keeps at most 5 connections waiting to be
  accepted and refuses more, so a burst of more than 5 connects in the same
  moment can see a few refused. NT Server takes up to 200. rsh-mcp tries a
  refused connect again.
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
  code) is written to `ntrshd.log` next to the exe, in both console and
  service mode. Each session's `done` line says how it ended: `end of
  output`, or `stopped:` and why (the client went away, the client sent a
  signal, no output for too long, rshd is quitting). `-d` adds more detail,
  such as how the client closed the connection. `-q` replaces the status
  window with a plain scrolling log in the console.
- **`Ctrl+C` or `Ctrl+Break` quits.** The first press stops accepting new
  connections and gives the running commands a few seconds to stop; press
  again to kill everything and exit at once (for when something is wedged).
  **Closing the window** quits at once: it kills the running commands and
  tells their clients.

## Mapped network drives

A command sees only the drives of the account that runs ntrshd. If you need
a user's mapped drive (say `T:`), the simplest way is to run ntrshd in that
user's session — for example from a login/startup item under autologon. A
service runs in its own logon; installed with `-user`, it runs as that
account, but interactively-mapped drives are not shared into it and must be
re-established there.

## Tested

Version 1.3.2, all 11 release exes, each on its own NT version (in LEMU, QEMU
for these machines):

| CPU | NT 3.1 | NT 3.51 | NT 4.0 |
|---|---|---|---|
| x86 | pass | pass | pass |
| MIPS | pass | pass | pass |
| Alpha | pass | pass | pass |
| PowerPC | — | pass | pass |

Each one was installed as a service with `ntrshd -install -user .\rshtest
-pass ...`, for a new account that did not have the right to log on as a
service yet. `-install` gave it the right, and `net start ntrshd` started the
service as that account. 1.3.1 got system error 1069 there (checked on NT 3.1
and NT 4.0 x86). `-install` as `.\Administrator`, which had the right already,
and as LocalSystem worked too.

Then each service ran: a command; the exit status through an rsh-mcp script;
`Ctrl+Break` from the client; a client reset; 4 sessions at once.

1.3.2 also runs as the boot service, as `.\Administrator`, on 15 NT machines
in LEMU: one for each of the 11 above, plus NT 3.51 and NT 4.0 on an SNI
RM200, and NT 4.0 on an RM300 with 2 and with 4 CPUs.

Version 1.3.1, the same code apart from `-install`, also passed 200 KB through
stdin, returned exactly. On NT 3.1 MIPS and Alpha it was also installed with
an option (`ntrshd -install -p 2514`).

Version 1.3, the same code apart from `-install`, also ran these, in a
console window:

- NT 4.0 Alpha: 2000 sessions, 8 at a time, while one 5-minute command
  ran. Every session ended with its full output, no connect was refused,
  and the long command's output came complete. ntrshd's handle count was
  the same after the first 1000 sessions and after the second.
- NT 4.0 MIPS: 10.7 MB of output exact, and three such at once.
- NT 3.1 x86: 8 sessions at once.

NT 3.5 itself was not tested. The `nt35` exes ran on NT 3.51. Every
function they use is in NT 3.5, and they are marked for NT 3.10.

Earlier versions also ran on a real NT 4.0 MIPS machine (RM300, 4-way
R4400), and the rsh, rcp, stderr channel and rsh-mcp tests also pass under
Wine.
