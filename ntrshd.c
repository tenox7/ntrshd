/*
 * ntrshd - remote shell daemon (rsh / rcp) for Windows NT
 *
 * One plain-C source that builds with the NT 3.1, 3.5 and 4.0 SDKs and
 * runs on NT 3.1 and later.  Double-clicked it opens a console and
 * serves; started by the Service Control Manager it runs as a service.
 * Install or remove the service with  ntrshd -install  /  ntrshd -remove.
 *
 * It speaks the BSD rsh protocol: optional stderr port, client user,
 * server user, command, then a status byte.  Each command runs as
 * "cmd /c <command>" in a hidden console of its own, under a small
 * helper (ntrshd itself, started as "ntrshd -session": see runHelper),
 * with stdout and (optionally) stderr piped back to the client.  Many
 * sessions run at once, fully independent: no shared buffers, no handles
 * inherited from one session into another, no shared console.
 *
 * For rsh-mcp (github.com/tenox7/rsh-mcp) it also runs the script that
 * rsh-mcp gives /bin/sh to get a command's exit status (see doScript).
 *
 * security: open (+ +)
 *
 * Build:  nmake
 *
 * Code style: ANSI C (C89).  Variables declared at the top of a block,
 * /x x/ comments, braces on the same line.
 */

/*
 * Older SDKs (NT 3.1, 3.5) need the target architecture and WIN32 named
 * before <windows.h>; the NT 4.0 headers work this out themselves.  Doing it
 * here keeps one Makefile for every SDK and every CPU, with no arch-specific
 * compiler flags.
 */
#if !defined(_X86_) && !defined(_MIPS_) && !defined(_ALPHA_) && !defined(_PPC_) && !defined(_IA64_)
# if defined(_M_IX86)
#  define _X86_ 1
# elif defined(_M_MRX000)
#  define _MIPS_ 1
# elif defined(_M_ALPHA)
#  define _ALPHA_ 1
# elif defined(_M_PPC)
#  define _PPC_ 1
# endif
#endif
#ifndef WIN32
# define WIN32
#endif

/*
 * ntrshd always links the multithreaded C library (libcmt).  /MT tells the
 * headers so, but the NT 3.1 Alpha compiler ignores /MT, and without _MT the
 * NT 3.1 headers leave out _beginthread and the thread-safe errno.
 */
#ifndef _MT
# define _MT 1
#endif

#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <process.h>

/*
 * Build-time target detection.  The SAME source builds with each SDK; the
 * few differences are keyed off the compiler version:
 *   _MSC_VER  800  = NT 3.1 SDK   (cl386 8.00)
 *   _MSC_VER  900  = Visual C++ 2.0 (NT 3.5)
 *   _MSC_VER 1000+ = Visual C++ 4.x (NT 4.0 and later)
 * It uses no API newer than NT 3.1, so every build runs on every NT.
 */

/*
 * The NT 3.1 winsvc.h declares the service main and control callbacks with
 * no calling convention (so __cdecl); NT 3.5 and later declare them WINAPI
 * (__stdcall).  SVCAPI matches whichever this SDK uses.
 */
#if defined(_MSC_VER) && _MSC_VER < 900
#define SVCAPI
#else
#define SVCAPI WINAPI
#endif

#define RSHD_VERSION "1.3.1"
#define RSH_PORT 514
#define FIELD_SIZE 256
#define CMD_SIZE 4096
#define SCRIPT_CMD "sh -s rsh-mcp-1"   /* rsh-mcp asks for this to run its script */
#define SCRIPT_END ") </dev/null 2>&1" /* the script's line right after the command */
#define MARK_SIZE 64
#define LINE_SIZE 1024
#define IO_SIZE 8192
#define EXTRA_SIZE 512         /* options after -install, passed on to the service */
#define STATUS_MS 500       /* console status-window refresh interval */
#define NO_ATTRS ((DWORD)0xFFFFFFFF)
#define IO_SECONDS 60          /* request / script / rcp read timeout */
#define RETRY_SECONDS 10
#define PROBE_SECONDS 3
#define MONITOR_MS 200         /* the input thread looks for the session's end this often */
#define STOP_WAIT_MS 5000      /* grace after CTRL_BREAK before TerminateProcess */
#define KILL_EXTRA_MS 2000     /* a stop this late: tell the helper to kill, then end it */
#define READY_MS 60000         /* the session helper must start the command within this */
#define CANCEL_MS 5000         /* a cancelled pipe read or write ends within this */
#define GRAND_GRACE_MS 3000    /* after cmd exits, wait this for a grandchild's output */
#define NOTE_MS 60000
#define DRAIN_MS 1000          /* graceful close: wait this long for the client to close too */
#define CLOSE_MS 10000         /* ... and never longer than this in all */
#define MAX_RUNNING 128
#define LISTEN_BACKLOG 200     /* winsock.h SOMAXCONN is only 5; NT Server honours up to 200 */
#define ACCEPT_FAILS 10
#define CLAIM_WAIT_MS 2000     /* wait this long for another ntrshd to let go of the port */
#define CLOSE_WAIT_MS 2000     /* window closed: give the sessions this long to finish */
#define HOLD_MS 60000          /* a startup error stays on a double-clicked window this long */
#define HELPER_FAIL 0x20000000L /* a session helper's exit code: it could not set up */

/* service identity */
#define SVC_NAME "ntrshd"
#define SVC_DISPLAY "RSH Daemon (ntrshd)"

/* why a command was stopped */
#define STOP_NONE 0
#define STOP_IDLE 1
#define STOP_SIGNAL 2
#define STOP_GONE 3
#define STOP_SHUTDOWN 4

/* how a command's output ended, for the log */
#define END_EOF 0              /* the command closed its output: it exited */
#define END_HELD 1             /* it exited, but a program it started still held the output */
#define END_STOPPED 2          /* it was stopped (see stopWhy) */

/* the listening port, as the status window shows it */
#define PORT_OPENING 0
#define PORT_LISTENING 1
#define PORT_TAKEN 2           /* another program answers on the port */
#define PORT_FAILED 3          /* bind or listen failed with portError */

/*
 * ntrshd's end of one of a command's pipes (see makePipe).  The buffer and
 * the OVERLAPPED live here, not on a stack, because a read or write in
 * flight uses them until it ends.
 */
typedef struct {
    HANDLE pipe;               /* overlapped named pipe end, or NULL when closed */
    OVERLAPPED ov;             /* ov.hEvent is set when a read or write ends */
    int pending;               /* a ReadFile or WriteFile is in flight */
    int eof;                   /* output: the command closed its end */
    DWORD len;                 /* stdin: bytes in buf */
    DWORD off;                 /* stdin: bytes of buf already written */
    char buf[IO_SIZE];
} PIPE;

typedef struct {
    SOCKET sock;               /* main channel: stdout to client, stdin from client */
    SOCKET errSock;            /* separate stderr channel, or INVALID_SOCKET */
    struct sockaddr_in peer;
    char ip[16];
    int id;
    HANDLE proc;               /* the session helper process (see runHelper) */
    DWORD pid;                 /* the helper's process id */
    DWORD cmdPid;              /* the command's (cmd.exe) process id */
    HANDLE stopEv;             /* tells the helper: CTRL_BREAK, then kill after a grace period */
    HANDLE killEv;             /* tells the helper: kill now */
    HANDLE wake;               /* wakes the session thread: a stop was asked for */
    HANDLE monitorDone;        /* signalled when the input thread has exited */
    PIPE out;                  /* the command's stdout (and stderr, with no separate channel) */
    PIPE err;                  /* the command's stderr, for the separate channel */
    PIPE in;                   /* the command's stdin */
    volatile int stopWhy;      /* STOP_xxx: why the command should stop */
    volatile int killNow;      /* stop it without the grace period */
    volatile int done;         /* tells the input thread to stop */
    int endWhy;                /* END_xxx, for the log */
    int sockWatch;             /* still worth watching sock for input/disconnect */
    int errWatch;              /* still worth watching errSock for a signal byte */
    int started;               /* the status byte was sent; output has begun */
    int slot;                  /* index in running[], or -1 */
    int limited;               /* the reads share one IO_SECONDS limit (request, script) */
    int leak;                  /* a cancelled pipe read or write never ended: never free */
    char last;                 /* last byte sent to the client (for note formatting) */
    DWORD limitStart;          /* when the limited reads began */
    DWORD startTick;           /* when the command started, for the status window */
    DWORD finTick;             /* when the FIN went out, for the log */
    DWORD inBytes;             /* stdin bytes from the client */
    char cmd[128];             /* the command line, for the status window */
    char marker[MARK_SIZE];    /* rsh-mcp script: the output ends with this and the exit code */
} CONN;

static CRITICAL_SECTION runLock;    /* guards running[] */
static CRITICAL_SECTION portLock;   /* guards nextErrPort and pipeSerial */
static CRITICAL_SECTION logLock;    /* guards log output */
static CONN *running[MAX_RUNNING];
static SOCKET listener = INVALID_SOCKET;
static char *comspec;
static char selfPath[MAX_PATH];     /* this exe: it is each command's session helper too */
static DWORD pipeSerial = 0;        /* numbers the pipes, for unique names */
static int nextErrPort = IPPORT_RESERVED - 1;
static int connCount = 0;
static int statusMode = 0;          /* console shows the live status window */
static int quietFlag = 0;           /* -q: plain scrolling log, no status window */
static DWORD upSince = 0;           /* when serving began, for the uptime line */
static char hostLabel[80] = "";     /* this host's name, for the status header */
static char ipLabel[96] = "";       /* this host's IP address(es), for the header */
static int debugFlag = 0;           /* -d: one log line per event, times in ms */
static int sendExit = 0;            /* send the exit code as a last line */
static DWORD idleLimit = 0;         /* stop a silent command after this long; 0 = never */
static DWORD grandGrace = GRAND_GRACE_MS;
static int rshPort = RSH_PORT;
static int asService = 0;
static FILE *logFile = NULL;
static volatile int runFlag = 1;
static HANDLE quitEvent = NULL;     /* set when a quit is asked for: wakes every wait */
static HANDLE portMutex = NULL;     /* owned while this process serves the port */
static int ownConsole = 0;          /* the console window is ours alone (double-clicked) */
static volatile int portState = PORT_OPENING;
static volatile int portError = 0;

static SERVICE_STATUS svcStatus;
static SERVICE_STATUS_HANDLE svcStatusHandle = 0;

/* -------- logging -------------------------------------------------------- */

static void logLine(const char *fmt, va_list ap) {
    char msg[LINE_SIZE];
    char ms[8];
    SYSTEMTIME now;

    _vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
    msg[sizeof(msg) - 1] = 0;
    GetLocalTime(&now);
    ms[0] = 0;
    if (debugFlag) {
        sprintf(ms, ".%03d", now.wMilliseconds);
    }
    EnterCriticalSection(&logLock);
    if (!asService && !statusMode) {
        printf("%02d:%02d:%02d%s %s\n", now.wHour, now.wMinute, now.wSecond, ms, msg);
        fflush(stdout);
    }
    if (logFile != NULL) {
        fprintf(logFile, "%04d-%02d-%02d %02d:%02d:%02d%s %s\n", now.wYear, now.wMonth,
                now.wDay, now.wHour, now.wMinute, now.wSecond, ms, msg);
        fflush(logFile);
    }
    LeaveCriticalSection(&logLock);
}

static void logMsg(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    logLine(fmt, ap);
    va_end(ap);
}

/* -d: more detail, one line per event */
static void logDebug(const char *fmt, ...) {
    va_list ap;

    if (!debugFlag) {
        return;
    }
    va_start(ap, fmt);
    logLine(fmt, ap);
    va_end(ap);
}

/* -------- socket helpers ------------------------------------------------- */

static int sendAll(SOCKET s, const char *buf, int len) {
    int n;

    while (len > 0) {
        n = send(s, buf, len, 0);
        if (n <= 0) {
            return 0;
        }
        buf += n;
        len -= n;
    }
    return 1;
}

static int sendByte(SOCKET s, char ch) {
    return sendAll(s, &ch, 1);
}

/* reports an error to the client: status byte 1, message, newline */
static void sendErr(CONN *c, const char *fmt, ...) {
    char msg[LINE_SIZE];
    va_list ap;

    msg[0] = 1;
    va_start(ap, fmt);
    _vsnprintf(msg + 1, sizeof(msg) - 3, fmt, ap);
    va_end(ap);
    msg[sizeof(msg) - 2] = 0;
    logMsg("[%d] %s", c->id, msg + 1);
    strcat(msg, "\n");
    sendAll(c->sock, msg, strlen(msg));
}

/* waits for the client at most IO_SECONDS.  While the request or the
   rsh-mcp script is read (c->limited), all of those reads together get
   IO_SECONDS, so a client that stops talking, or sends a byte a minute,
   cannot hold a connection for long. */
static int recvWait(CONN *c, char *buf, int len) {
    struct timeval tv;
    fd_set fds;
    DWORD ms;
    DWORD used;

    ms = IO_SECONDS * 1000;
    if (c->limited) {
        used = GetTickCount() - c->limitStart;
        if (used >= ms) {
            return -1;
        }
        ms -= used;
    }
    FD_ZERO(&fds);
    FD_SET(c->sock, &fds);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (select(0, &fds, NULL, NULL, &tv) != 1) {
        return -1;
    }
    return recv(c->sock, buf, len, 0);
}

/* starts (on) or ends the shared time limit for the reads that follow */
static void limitReads(CONN *c, int on) {
    c->limited = on;
    c->limitStart = GetTickCount();
}

/* reads up to the end character, which is dropped; fails when the connection
   closes, the time is up or the text does not fit */
static int readUntil(CONN *c, char *buf, int size, char end) {
    int len;
    char ch;

    len = 0;
    for (;;) {
        if (recvWait(c, &ch, 1) != 1) {
            return -1;
        }
        if (ch == end) {
            break;
        }
        if (len >= size - 1) {
            return -1;
        }
        buf[len++] = ch;
    }
    buf[len] = 0;
    return len;
}

/* reads the client's rcp status: 0 is fine, 1 and 2 carry a message;
   returns -1 when the connection is gone */
static int readResponse(CONN *c) {
    char msg[LINE_SIZE];
    char ch;

    if (recvWait(c, &ch, 1) != 1) {
        return -1;
    }
    if (ch == 0) {
        return 0;
    }
    if (readUntil(c, msg, sizeof(msg), '\n') < 0) {
        msg[0] = 0;
    }
    logMsg("[%d] client error: %s", c->id, msg);
    return ch;
}

static int nextReservedPort(void) {
    int port;

    EnterCriticalSection(&portLock);
    port = nextErrPort;
    nextErrPort--;
    if (nextErrPort < IPPORT_RESERVED / 2) {
        nextErrPort = IPPORT_RESERVED - 1;
    }
    LeaveCriticalSection(&portLock);
    return port;
}

/* a client that wants stderr on its own channel sends a port number:
   connect back to it from a reserved port */
static void setNoDelay(SOCKET s) {
    int on = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
}

static SOCKET connectBack(CONN *c, int port) {
    struct sockaddr_in addr;
    SOCKET s;
    int tries;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        logMsg("[%d] stderr channel: socket failed, error %d", c->id, WSAGetLastError());
        return INVALID_SOCKET;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    for (tries = 0; tries < IPPORT_RESERVED / 2; tries++) {
        addr.sin_port = htons((u_short)nextReservedPort());
        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            break;
        }
    }
    if (tries == IPPORT_RESERVED / 2) {
        logMsg("[%d] stderr channel: no free reserved port, error %d", c->id, WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }
    addr = c->peer;
    addr.sin_port = htons((u_short)port);
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        logMsg("[%d] stderr channel: connect to port %d failed, error %d", c->id, port, WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }
    setNoDelay(s);
    logMsg("[%d] stderr channel connected to port %d", c->id, port);
    return s;
}

/* the first half of a graceful close: the FIN goes out at once, so the
   client sees the end of the output without waiting for anything else */
static void sendFin(SOCKET s) {
    if (s != INVALID_SOCKET) {
        shutdown(s, 1);   /* SD_SEND: send FIN, keep reading */
    }
}

/* the second half: read what the client still sends until it closes too
   (or stays quiet for DRAIN_MS, or CLOSE_MS have passed), then close.
   Closing with unread data would send a reset (RST), and a reset can throw
   away output the client has not read yet. */
static void closeConn(CONN *c, SOCKET s, const char *name) {
    struct timeval tv;
    fd_set fds;
    char buf[256];
    int n;

    if (s == INVALID_SOCKET) {
        return;
    }
    shutdown(s, 1);
    for (;;) {
        FD_ZERO(&fds);
        FD_SET(s, &fds);
        tv.tv_sec = DRAIN_MS / 1000;
        tv.tv_usec = (DRAIN_MS % 1000) * 1000;
        if (select(0, &fds, NULL, NULL, &tv) != 1) {
            logDebug("[%d] %s: the client did not close it, closing", c->id, name);
            break;
        }
        n = recv(s, buf, sizeof(buf), 0);
        if (n == 0) {
            logDebug("[%d] %s: the client closed it %lu ms after the FIN", c->id, name, GetTickCount() - c->finTick);
            break;
        }
        if (n < 0) {
            logDebug("[%d] %s: the client reset it %lu ms after the FIN", c->id, name, GetTickCount() - c->finTick);
            break;
        }
        if (GetTickCount() - c->finTick >= CLOSE_MS) {
            logDebug("[%d] %s: the client keeps sending, closing", c->id, name);
            break;
        }
    }
    closesocket(s);
}

/* -------- small path helpers (used by rcp) ------------------------------- */

static void fixSlashes(char *path) {
    for (; *path != 0; path++) {
        if (*path == '/') {
            *path = '\\';
        }
    }
}

static void trimEnd(char *s) {
    int len;

    len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\r')) {
        len--;
        s[len] = 0;
    }
}

static char *baseName(char *path) {
    char *name;

    name = path;
    for (; *path != 0; path++) {
        if (*path == '\\' || *path == ':' || *path == '/') {
            name = path + 1;
        }
    }
    return name;
}

/* names sent by the client must stay inside the target directory */
static int isBadName(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return 1;
    }
    return strpbrk(name, "/\\:") != NULL;
}

static void joinPath(char *out, char *dir, char *name) {
    int len;

    strcpy(out, dir);
    len = strlen(out);
    if (len > 0 && out[len - 1] != '\\' && out[len - 1] != ':') {
        strcat(out, "\\");
    }
    strcat(out, name);
}

/* -------- the command's pipes -------------------------------------------- */

static void dropHandle(HANDLE h) {
    if (h != NULL) {
        CloseHandle(h);
    }
}

/*
 * Makes one of a command's pipes.  ntrshd's end is a named pipe opened for
 * overlapped I/O, so a read or write never blocks a thread: it is waited
 * for together with other events, and closing the handle cancels it (NT
 * before 4.0 has no CancelIo).  The command's end, *theirs, is a plain
 * handle with the access an anonymous pipe's end has.  toCommand: ntrshd
 * writes and the command reads (stdin); else the command writes (stdout,
 * stderr).  Nothing is inheritable: the session helper copies the
 * command's end out of ntrshd (see runHelper).  What is made before a
 * failure is freed by endCommand.
 */
static int makePipe(PIPE *p, HANDLE *theirs, int toCommand) {
    char name[64];
    DWORD serial;
    HANDLE h;

    EnterCriticalSection(&portLock);
    serial = ++pipeSerial;
    LeaveCriticalSection(&portLock);
    sprintf(name, "\\\\.\\pipe\\ntrshd-%lu-%lu", GetCurrentProcessId(), serial);
    p->ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (p->ov.hEvent == NULL) {
        return 0;
    }
    h = CreateNamedPipe(name, (toCommand ? PIPE_ACCESS_OUTBOUND : PIPE_ACCESS_INBOUND) | FILE_FLAG_OVERLAPPED,
                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, IO_SIZE, IO_SIZE, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    p->pipe = h;
    h = CreateFile(name, toCommand ? (GENERIC_READ | FILE_WRITE_ATTRIBUTES) : (GENERIC_WRITE | FILE_READ_ATTRIBUTES),
                   0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    *theirs = h;
    return 1;
}

static int isOpen(PIPE *p) {
    return p->pipe != NULL && !p->eof;
}

/* closes ntrshd's end of a pipe.  A read or write still in flight is
   cancelled by the close and ends at once; wait for that, since it writes
   into p->buf and p->ov.  0 if it did not end (never seen). */
static int closePipe(PIPE *p) {
    int ok;

    ok = 1;
    if (p->pipe != NULL) {
        CloseHandle(p->pipe);
        p->pipe = NULL;
    }
    if (p->pending) {
        ok = WaitForSingleObject(p->ov.hEvent, CANCEL_MS) == WAIT_OBJECT_0;
        p->pending = 0;
    }
    p->eof = 1;
    return ok;
}

static int freePipe(PIPE *p) {
    if (!closePipe(p)) {
        return 0;               /* keep the event: the read or write may still set it */
    }
    if (p->ov.hEvent != NULL) {
        CloseHandle(p->ov.hEvent);
        p->ov.hEvent = NULL;
    }
    return 1;
}

/* takes what the command wrote: returns how many bytes are now in p->buf,
   0 while a read waits, -1 at end-of-file (or when the pipe is closed) */
static int readPipe(PIPE *p) {
    DWORD n;

    for (;;) {
        if (!isOpen(p)) {
            return -1;
        }
        if (p->pending) {
            if (WaitForSingleObject(p->ov.hEvent, 0) != WAIT_OBJECT_0) {
                return 0;
            }
            p->pending = 0;
            if (!GetOverlappedResult(p->pipe, &p->ov, &n, FALSE)) {
                p->eof = 1;     /* ERROR_BROKEN_PIPE: every writer has closed it */
                return -1;
            }
        } else if (!ReadFile(p->pipe, p->buf, IO_SIZE, &n, &p->ov)) {
            if (GetLastError() == ERROR_IO_PENDING) {
                p->pending = 1;
                return 0;
            }
            p->eof = 1;
            return -1;
        }
        if (n > 0) {
            return (int)n;
        }
        /* the command wrote zero bytes: read again */
    }
}

/* -------- starting a command --------------------------------------------- */

/*
 * Starts "cmd /c command" under a session helper (see runHelper) and waits
 * until the command runs.  The helper starts with nothing inherited and
 * copies what it needs out of ntrshd: the command's ends of the pipes, the
 * stop and kill events and the ready semaphore.  Once the command runs,
 * the helper releases the semaphore by the command's process id.  On
 * failure why says what went wrong; what was made is freed by endCommand.
 */
static BOOL startCommand(CONN *c, char *command, char *why, int whySize) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE inEnd, outEnd, errEnd;
    HANDLE ready;
    HANDLE waits[2];
    const char *shell;
    const char *q;
    char *line;
    DWORD code;
    DWORD r;
    LONG before;
    BOOL ok;
    int sep;

    why[0] = 0;
    sep = c->errSock != INVALID_SOCKET;
    inEnd = outEnd = errEnd = NULL;
    pi.hProcess = NULL;
    shell = comspec != NULL ? comspec : "cmd";
    q = strchr(shell, ' ') != NULL ? "\"" : "";
    line = (char *)malloc(strlen(selfPath) + strlen(shell) + strlen(command) + 160);
    ready = CreateSemaphore(NULL, 0, 0x7FFFFFFF, NULL);
    c->stopEv = CreateEvent(NULL, TRUE, FALSE, NULL);
    c->killEv = CreateEvent(NULL, TRUE, FALSE, NULL);
    ok = line != NULL && ready != NULL && c->stopEv != NULL && c->killEv != NULL
         && makePipe(&c->out, &outEnd, 0) && makePipe(&c->in, &inEnd, 1)
         && (!sep || makePipe(&c->err, &errEnd, 0));
    if (!ok) {
        _snprintf(why, whySize - 1, "cannot make the command's pipes, error %lu", GetLastError());
    } else {
        sprintf(line, "\"%s\" -session %lu %lu %lu %lu %lu %lu %lu %lu %s%s%s /c %s",
                selfPath, GetCurrentProcessId(), (DWORD)inEnd, (DWORD)outEnd, (DWORD)errEnd,
                (DWORD)c->stopEv, (DWORD)c->killEv, (DWORD)ready, (DWORD)STOP_WAIT_MS,
                q, shell, q, command);
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        ok = CreateProcess(selfPath, line, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
        if (!ok) {
            pi.hProcess = NULL;
            _snprintf(why, whySize - 1, "cannot start the session helper %s, error %lu", selfPath, GetLastError());
        }
    }
    if (ok) {
        CloseHandle(pi.hThread);
        waits[0] = ready;
        waits[1] = pi.hProcess;
        r = WaitForMultipleObjects(2, waits, FALSE, READY_MS);
        ok = r == WAIT_OBJECT_0;
        if (ok) {
            /* the wait took one off the count the helper released: put it
               back and read the rest, which is the command's process id */
            ReleaseSemaphore(ready, 1, &before);
            c->cmdPid = (DWORD)before + 1;
        } else if (r == WAIT_OBJECT_0 + 1) {
            if (!GetExitCodeProcess(pi.hProcess, &code)) {
                code = HELPER_FAIL | GetLastError();
            }
            if (code & HELPER_FAIL) {
                _snprintf(why, whySize - 1, "the session helper could not set up, error %lu", code & ~HELPER_FAIL);
            } else {
                _snprintf(why, whySize - 1, "cannot start %s, error %lu", shell, code);
            }
        } else {
            TerminateProcess(pi.hProcess, CONTROL_C_EXIT);
            _snprintf(why, whySize - 1, "the session helper did not start the command within %d s", READY_MS / 1000);
        }
    }
    why[whySize - 1] = 0;
    /* the helper has its own copies by now: the pipes reach end-of-file
       only when the command and what it started have closed theirs */
    dropHandle(inEnd);
    dropHandle(outEnd);
    dropHandle(errEnd);
    dropHandle(ready);
    if (line != NULL) {
        free(line);
    }
    if (!ok) {
        dropHandle(pi.hProcess);
        return FALSE;
    }
    c->proc = pi.hProcess;
    c->pid = pi.dwProcessId;
    logMsg("[%d] started cmd, process id %lu (session helper %lu)", c->id, c->cmdPid, c->pid);
    return TRUE;
}

/* -------- running-command table (for shutdown) --------------------------- */

/* puts the session on the list of running commands, which the status window
   and the quit use; 0 when the list is full */
static int addRunning(CONN *c) {
    int i;

    EnterCriticalSection(&runLock);
    for (i = 0; i < MAX_RUNNING; i++) {
        if (running[i] == NULL) {
            running[i] = c;
            c->slot = i;
            break;
        }
    }
    LeaveCriticalSection(&runLock);
    return i < MAX_RUNNING;
}

static void dropRunning(CONN *c) {
    EnterCriticalSection(&runLock);
    if (c->slot >= 0 && running[c->slot] == c) {
        running[c->slot] = NULL;
    }
    c->slot = -1;
    LeaveCriticalSection(&runLock);
}

/* asks for a command to stop; its session thread wakes up and tells the
   helper (see copyOutput) */
static void stopCommand(CONN *c, int why) {
    if (c->stopWhy == STOP_NONE) {
        c->stopWhy = why;
    }
    if (c->wake != NULL) {
        SetEvent(c->wake);
    }
}

static int stopAll(int why) {
    int count;
    int i;

    count = 0;
    EnterCriticalSection(&runLock);
    for (i = 0; i < MAX_RUNNING; i++) {
        if (running[i] != NULL) {
            stopCommand(running[i], why);
            count++;
        }
    }
    LeaveCriticalSection(&runLock);
    return count;
}

/* stops every running command at once, without the grace period */
static void killAll(void) {
    int i;

    EnterCriticalSection(&runLock);
    for (i = 0; i < MAX_RUNNING; i++) {
        if (running[i] != NULL) {
            running[i]->killNow = 1;
            stopCommand(running[i], STOP_SHUTDOWN);
        }
    }
    LeaveCriticalSection(&runLock);
}

static int countRunning(void) {
    int i;
    int n;

    n = 0;
    EnterCriticalSection(&runLock);
    for (i = 0; i < MAX_RUNNING; i++) {
        if (running[i] != NULL) {
            n++;
        }
    }
    LeaveCriticalSection(&runLock);
    return n;
}

/* After a quit is requested, wait up to graceMs for the running commands to
   stop: each session's helper sends CTRL_BREAK and kills its command after a
   grace period (see runHelper).  A second Ctrl+C makes the handler end the
   process without waiting; the helpers then kill their commands at once. */
static void drainCommands(DWORD graceMs) {
    DWORD start;

    start = GetTickCount();
    while (countRunning() > 0 && GetTickCount() - start < graceMs) {
        Sleep(100);
    }
}

/* -------- the output path ------------------------------------------------ */

/* a message for the client once its output has started: on the stderr
   channel if it has one, else on a line of its own after the output */
static void sendNote(CONN *c, const char *text) {
    char msg[LINE_SIZE + 16];

    if (c->errSock != INVALID_SOCKET) {
        _snprintf(msg, sizeof(msg) - 1, "rshd: %s\n", text);
        msg[sizeof(msg) - 1] = 0;
        sendAll(c->errSock, msg, strlen(msg));
        return;
    }
    _snprintf(msg, sizeof(msg) - 1, "%srshd: %s\n", c->last == '\n' ? "" : "\n", text);
    msg[sizeof(msg) - 1] = 0;
    sendAll(c->sock, msg, strlen(msg));
}

static void reportStop(CONN *c) {
    char text[LINE_SIZE];

    switch (c->stopWhy) {
    case STOP_IDLE:
        sprintf(text, "no output for %lu minute%s, command stopped",
                idleLimit / 60000, idleLimit == 60000 ? "" : "s");
        break;
    case STOP_SIGNAL:
        strcpy(text, "command stopped as the client asked");
        break;
    case STOP_SHUTDOWN:
        strcpy(text, "server shutting down, command stopped");
        break;
    default:
        logMsg("[%d] client went away, command stopped", c->id);
        return;
    }
    logMsg("[%d] %s", c->id, text);
    sendNote(c, text);
}

static DWORD minMs(DWORD a, DWORD b) {
    return a < b ? a : b;
}

/* how long until limit ms have passed since since; 0 if they have */
static DWORD leftMs(DWORD since, DWORD limit, DWORD now) {
    DWORD used;

    used = now - since;
    return used >= limit ? 0 : limit - used;
}

/*
 * Copies all of the command's output to the client, then returns.
 *
 * The pipes are read with overlapped ReadFile, so this thread sleeps until
 * the command writes, it ends, or a stop is asked for: no polling, and
 * every byte is sent before the end-of-file (ERROR_BROKEN_PIPE) behind it.
 * send() blocks while the client reads slowly, which holds the command
 * back: flow control without a busy loop.  The pipes reach end-of-file
 * when the command and all it started have closed them; ntrshd and the
 * helper keep no copies.  A program the command started can keep them open
 * after it exits, so once the command has exited and the pipes have been
 * quiet for grandGrace, stop waiting.  For rsh-mcp and -e the exit code
 * comes after the output, so there the end also waits for the exit.
 *
 * A stop (signal, client gone, -t, quit) goes to the helper, which sends
 * CTRL_BREAK and kills the command after a grace period.  If that takes too
 * long the helper is told to kill at once, and if even that fails, the
 * helper itself is ended.
 */
static DWORD copyOutput(CONN *c) {
    HANDLE waits[4];
    PIPE *p;
    SOCKET dest;
    DWORD total;
    DWORD quiet;
    DWORD noted;
    DWORD exitAt;
    DWORD stopAt;
    DWORD silent;
    DWORD waitMs;
    DWORD now;
    int needExit;
    int exited;
    int stage;      /* 0 running, 1 told to stop, 2 told to kill, 3 helper ended */
    int sent;
    int nw;
    int n;
    int i;

    total = 0;
    quiet = GetTickCount();
    noted = quiet;
    exitAt = 0;
    stopAt = 0;
    exited = 0;
    stage = 0;
    needExit = c->marker[0] != 0 || sendExit;
    c->endWhy = END_EOF;
    for (;;) {
        /* send what the pipes hold now, and start the reads that wait */
        sent = 0;
        for (i = 0; i < 2; i++) {
            p = (i == 0) ? &c->out : &c->err;
            dest = (i == 0) ? c->sock : c->errSock;
            n = readPipe(p);
            if (n <= 0) {
                continue;
            }
            sent = 1;
            quiet = GetTickCount();
            noted = quiet;
            if (c->stopWhy == STOP_GONE) {
                continue;           /* no one to send it to: drop it */
            }
            if (!sendAll(dest, p->buf, n)) {
                logMsg("[%d] cannot send to the client, error %d: it is gone", c->id, WSAGetLastError());
                stopCommand(c, STOP_GONE);
                continue;
            }
            total += (DWORD)n;
            c->last = p->buf[n - 1];
        }
        if (sent) {
            continue;
        }

        now = GetTickCount();
        if (!exited && WaitForSingleObject(c->proc, 0) == WAIT_OBJECT_0) {
            exited = 1;
            exitAt = now;
            logDebug("[%d] the command exited", c->id);
        }
        silent = exited ? minMs(now - quiet, now - exitAt) : 0;

        /* a stop goes to the helper; escalate if it does not manage */
        if (c->stopWhy != STOP_NONE && !exited) {
            if (stage == 0) {
                stage = 1;
                stopAt = now;
                SetEvent(c->stopEv);
                logDebug("[%d] told the helper to stop the command", c->id);
            }
            if (stage == 1 && (c->killNow || now - stopAt >= STOP_WAIT_MS + KILL_EXTRA_MS)) {
                stage = 2;
                SetEvent(c->killEv);
                if (c->killNow) {
                    logDebug("[%d] told the helper to kill the command now", c->id);
                } else {
                    logMsg("[%d] the command did not stop, killing it", c->id);
                }
            }
            if (stage == 2 && now - stopAt >= STOP_WAIT_MS + 2 * KILL_EXTRA_MS) {
                stage = 3;
                TerminateProcess(c->proc, CONTROL_C_EXIT);
                logMsg("[%d] the session helper does not answer, ending it", c->id);
            }
        }

        /* the end of the output */
        if (!isOpen(&c->out) && !isOpen(&c->err)) {
            if (!needExit || exited) {
                logDebug("[%d] end of output", c->id);
                break;
            }
        } else if (exited && (silent >= grandGrace || c->stopWhy == STOP_SHUTDOWN || c->stopWhy == STOP_GONE)) {
            c->endWhy = END_HELD;
            break;
        }

        if (!exited && c->stopWhy == STOP_NONE) {
            if (idleLimit != 0 && now - quiet >= idleLimit) {
                stopCommand(c, STOP_IDLE);
                continue;
            }
            if (now - noted >= NOTE_MS) {
                noted = now;
                logMsg("[%d] still running, no output for %lu seconds", c->id, (now - quiet) / 1000);
            }
        }

        /* sleep until the command writes or ends, a stop comes, or the next
           deadline */
        nw = 0;
        if (c->out.pending) {
            waits[nw++] = c->out.ov.hEvent;
        }
        if (c->err.pending) {
            waits[nw++] = c->err.ov.hEvent;
        }
        waits[nw++] = c->wake;
        if (!exited) {
            waits[nw++] = c->proc;
        }
        waitMs = INFINITE;
        if (!exited && c->stopWhy == STOP_NONE) {
            waitMs = leftMs(noted, NOTE_MS, now);
            if (idleLimit != 0) {
                waitMs = minMs(waitMs, leftMs(quiet, idleLimit, now));
            }
        }
        if (exited) {
            waitMs = minMs(waitMs, silent < grandGrace ? grandGrace - silent : 0);
        }
        if (!exited && (stage == 1 || stage == 2)) {
            waitMs = minMs(waitMs, leftMs(stopAt, STOP_WAIT_MS + stage * KILL_EXTRA_MS, now));
        }
        if (WaitForMultipleObjects(nw, waits, FALSE, waitMs) == WAIT_FAILED) {
            logMsg("[%d] wait failed, error %lu", c->id, GetLastError());
            Sleep(MONITOR_MS);
        }
    }
    if (c->stopWhy != STOP_NONE) {
        c->endWhy = END_STOPPED;
        reportStop(c);
    }
    return total;
}

/* -------- the input thread ----------------------------------------------- */

/* the command gets no more input: end-of-file on its stdin */
static void closeStdin(CONN *c) {
    if (!closePipe(&c->in)) {
        c->leak = 1;
    }
}

/* writes the rest of c->in.buf to the command's stdin.  When the pipe is
   full the write stays in flight (c->in.pending) and the thread goes on
   watching the client, which TCP flow control holds back meanwhile. */
static void writeStdin(CONN *c) {
    DWORD n;

    while (c->in.pipe != NULL && c->in.off < c->in.len) {
        if (!WriteFile(c->in.pipe, c->in.buf + c->in.off, c->in.len - c->in.off, &n, &c->in.ov)) {
            if (GetLastError() == ERROR_IO_PENDING) {
                c->in.pending = 1;
                return;
            }
            logDebug("[%d] the command closed its stdin; more input is dropped", c->id);
            closeStdin(c);
            return;
        }
        c->in.off += n;
    }
}

/* a stdin write in flight: 1 once it (and what is left) is written, 0 if
   it still waits */
static int stdinWritten(CONN *c) {
    DWORD n;

    if (WaitForSingleObject(c->in.ov.hEvent, 0) != WAIT_OBJECT_0) {
        return 0;
    }
    c->in.pending = 0;
    if (!GetOverlappedResult(c->in.pipe, &c->in.ov, &n, FALSE)) {
        logDebug("[%d] the command closed its stdin; more input is dropped", c->id);
        closeStdin(c);
        return 1;
    }
    c->in.off += n;
    writeStdin(c);
    return !c->in.pending;
}

/* a byte on the stderr channel is a signal; 1 if one came */
static int readSignal(CONN *c) {
    char sig;

    if (recv(c->errSock, &sig, 1, 0) == 1) {
        logMsg("[%d] client sent signal %d", c->id, (unsigned char)sig);
        stopCommand(c, STOP_SIGNAL);
        return 1;
    }
    c->errWatch = 0;            /* the client closed the stderr channel */
    return 0;
}

/* looks for a signal without waiting */
static int pollSignal(CONN *c) {
    struct timeval tv;
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(c->errSock, &fds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    return select(0, &fds, NULL, NULL, &tv) == 1 && readSignal(c);
}

/*
 * Watches the client while the command runs.  Bytes on the main socket
 * become the command's stdin.  A byte on the stderr channel is a signal
 * (BSD rsh sends one on Ctrl+C) and stops the command.  A reset means the
 * client is gone, and stops it too.  A graceful close (FIN) means no more
 * input, as in BSD rsh, except in an rsh-mcp script session: there the
 * input was the script, read before the command started, so a FIN means
 * rsh-mcp gave up (its timeout, or a cancel) and the command is stopped.
 *
 * Writes to stdin are overlapped, so a command that does not read its
 * stdin cannot block this thread.  When a stop is asked for, stdin is
 * closed, so a batch file asking "Terminate batch job (Y/N)?" ends.  The
 * thread ends when told to (c->done), when the client is gone, or when
 * there is nothing left to watch, and signals monitorDone.
 */
static void __cdecl monitorThread(void *arg) {
    CONN *c;
    struct timeval tv;
    fd_set fds;
    int n;

    c = (CONN *)arg;
    while (!c->done) {
        if (c->stopWhy != STOP_NONE && c->in.pipe != NULL) {
            closeStdin(c);
        }
        if (c->in.pending && !stdinWritten(c)) {
            if (c->errWatch && pollSignal(c)) {
                break;
            }
            WaitForSingleObject(c->in.ov.hEvent, MONITOR_MS);
            continue;
        }
        if (!c->sockWatch && !c->errWatch) {
            break;
        }
        FD_ZERO(&fds);
        if (c->sockWatch) {
            FD_SET(c->sock, &fds);
        }
        if (c->errWatch) {
            FD_SET(c->errSock, &fds);
        }
        tv.tv_sec = 0;
        tv.tv_usec = MONITOR_MS * 1000L;
        if (select(0, &fds, NULL, NULL, &tv) <= 0) {
            continue;
        }
        if (c->sockWatch && FD_ISSET(c->sock, &fds)) {
            n = recv(c->sock, c->in.buf, IO_SIZE, 0);
            if (n > 0) {
                c->inBytes += (DWORD)n;
                c->in.len = (DWORD)n;
                c->in.off = 0;
                writeStdin(c);
            } else if (c->done) {
                break;                  /* the session is over and the client closes */
            } else if (n == 0 && c->marker[0] == 0) {
                logDebug("[%d] the client closed its input after %lu bytes: end-of-file on stdin", c->id, c->inBytes);
                closeStdin(c);
                c->sockWatch = 0;
            } else {
                logMsg(n == 0 ? "[%d] the client closed the connection" : "[%d] connection reset by the client", c->id);
                stopCommand(c, STOP_GONE);
                break;
            }
        }
        if (c->errWatch && FD_ISSET(c->errSock, &fds) && readSignal(c)) {
            break;
        }
    }
    closeStdin(c);
    SetEvent(c->monitorDone);
}

/* -------- exec --------------------------------------------------------- */

/* how the command's output ended, for the log */
static void endText(CONN *c, char *text) {
    switch (c->endWhy) {
    case END_HELD:
        sprintf(text, "it exited, a program it started still held the output after %lu s", grandGrace / 1000);
        break;
    case END_STOPPED:
        switch (c->stopWhy) {
        case STOP_IDLE:
            strcpy(text, "stopped: no output for too long");
            break;
        case STOP_SIGNAL:
            strcpy(text, "stopped: the client sent a signal");
            break;
        case STOP_SHUTDOWN:
            strcpy(text, "stopped: rshd is quitting");
            break;
        default:
            strcpy(text, "stopped: the client went away");
            break;
        }
        break;
    default:
        strcpy(text, "end of output");
        break;
    }
}

/* the end of the output: the exit code line for rsh-mcp or -e, and the log
   line that says how the command ended */
static void logExit(CONN *c, DWORD total) {
    char line[MARK_SIZE + 64];
    char how[128];
    DWORD code;

    endText(c, how);
    if (WaitForSingleObject(c->proc, 1000) != WAIT_OBJECT_0 || !GetExitCodeProcess(c->proc, &code)) {
        logMsg("[%d] done, %lu bytes sent, cmd still running (%s)", c->id, total, how);
        return;
    }
    if (c->marker[0] != 0) {
        sprintf(line, "%s%lu__\n", c->marker, code);
        sendAll(c->sock, line, strlen(line));
    } else if (sendExit) {
        sprintf(line, "%srshd: exit code %lu\n", c->last == '\n' ? "" : "\n", code);
        sendAll(c->sock, line, strlen(line));
    }
    if (code > 0xFFFF) {
        logMsg("[%d] done, %lu bytes sent, exit code 0x%08lx (%s)", c->id, total, code, how);
    } else {
        logMsg("[%d] done, %lu bytes sent, exit code %lu (%s)", c->id, total, code, how);
    }
}

/* frees what the command used; the input thread must have ended */
static void endCommand(CONN *c) {
    dropRunning(c);
    if (!freePipe(&c->out)) {
        c->leak = 1;
    }
    if (!freePipe(&c->err)) {
        c->leak = 1;
    }
    if (!freePipe(&c->in)) {
        c->leak = 1;
    }
    dropHandle(c->stopEv);
    c->stopEv = NULL;
    dropHandle(c->killEv);
    c->killEv = NULL;
    dropHandle(c->proc);
    c->proc = NULL;
}

/* ends the command at once: the session cannot go on */
static void killCommand(CONN *c) {
    if (c->proc == NULL) {
        return;
    }
    SetEvent(c->killEv);
    if (WaitForSingleObject(c->proc, STOP_WAIT_MS) != WAIT_OBJECT_0) {
        TerminateProcess(c->proc, CONTROL_C_EXIT);
    }
}

/* shows the command in the status window and puts it on the quit list
   before it starts; 0 if too many commands run already */
static int addCommand(CONN *c, char *command) {
    _snprintf(c->cmd, sizeof(c->cmd) - 1, "%s", command);
    c->cmd[sizeof(c->cmd) - 1] = 0;
    c->startTick = GetTickCount();
    if (!addRunning(c)) {
        logMsg("[%d] %d commands run already, refusing another", c->id, MAX_RUNNING);
        return 0;
    }
    return 1;
}

/* the command runs and the client has its status byte: serve it to the end
   (connThread then ends the connection and waits for the input thread) */
static void serveCommand(CONN *c) {
    c->monitorDone = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (c->monitorDone == NULL || _beginthread(monitorThread, 0, c) == (unsigned long)-1L) {
        logMsg("[%d] cannot start the input thread: the command gets no input", c->id);
        if (c->monitorDone != NULL) {
            CloseHandle(c->monitorDone);
            c->monitorDone = NULL;
        }
        closeStdin(c);
    }
    logExit(c, copyOutput(c));
}

static void doExec(CONN *c, char *command) {
    char why[LINE_SIZE];

    if (!addCommand(c, command)) {
        sendErr(c, "rshd: too many commands running, try again later");
        return;
    }
    if (!startCommand(c, command, why, sizeof(why))) {
        sendErr(c, "rshd: %s", why);
        return;
    }
    if (!sendByte(c->sock, 0)) {
        logMsg("[%d] client went away before the output started", c->id);
        killCommand(c);
        return;
    }
    c->started = 1;
    serveCommand(c);
}

/* -------- rsh-mcp scripts ------------------------------------------------ */

/*
 * rsh-mcp gets a command's exit status from a Unix host by asking for
 * SCRIPT_CMD and writing this script to its stdin:
 *
 *     shift
 *     (
 *     the command, one line or more
 *     ) </dev/null 2>&1
 *     echo MARKER$?__
 *     exit
 *
 * NT has no sh, so ntrshd reads the script itself.  It joins the command's
 * lines with & into one command line, as if they were typed on one line
 * (no spaces around &, so "set X=1" sets "1", not "1 "), runs that with
 * cmd /c and no stdin, and ends the output with MARKER<exit code>__ as the
 * echo line would.  rsh-mcp sends the script only after the status byte,
 * so that byte goes first here, and a problem after it is reported as
 * text.
 */

static void trimCr(char *s) {
    int len;

    len = strlen(s);
    if (len > 0 && s[len - 1] == '\r') {
        s[len - 1] = 0;
    }
}

static int isBlank(char *s, int len) {
    int i;

    for (i = 0; i < len; i++) {
        if (s[i] != ' ' && s[i] != '\t') {
            return 0;
        }
    }
    return 1;
}

/* the start of the last line before end (each line ends in \n), or NULL */
static char *lastLine(char *text, char *end) {
    char *p;

    if (end <= text) {
        return NULL;
    }
    p = end - 1;
    while (p > text && p[-1] != '\n') {
        p--;
    }
    return p;
}

/* if the last two lines of body are SCRIPT_END and "echo MARKER$?__", keeps
   MARKER, cuts both lines off and returns 1 */
static int scriptEnds(CONN *c, char *body, char *end) {
    char *echoLine;
    char *endLine;
    int endLen;
    int len;

    echoLine = lastLine(body, end);
    endLine = (echoLine != NULL) ? lastLine(body, echoLine) : NULL;
    if (endLine == NULL) {
        return 0;
    }
    endLen = strlen(SCRIPT_END);
    if (echoLine - endLine != endLen + 1 || strncmp(endLine, SCRIPT_END, endLen) != 0) {
        return 0;
    }
    len = (int)(end - echoLine) - 1;    /* the echo line without its \n */
    if (len <= 9 || len - 9 >= MARK_SIZE) {
        return 0;
    }
    if (strncmp(echoLine, "echo ", 5) != 0 || strncmp(echoLine + len - 4, "$?__", 4) != 0) {
        return 0;
    }
    memcpy(c->marker, echoLine + 5, len - 9);
    c->marker[len - 9] = 0;
    *endLine = 0;
    return 1;
}

/* reads the script: the command's lines into body, each ending in \n, and
   the marker into c->marker; 0 if it does not arrive whole and in time, or
   does not fit */
static int readScript(CONN *c, char *body, int size) {
    char line[CMD_SIZE];
    int used;
    int len;
    int n;

    for (n = 0; ; n++) {
        if (n == 4 || readUntil(c, line, sizeof(line), '\n') < 0) {
            return 0;
        }
        trimCr(line);
        if (strcmp(line, "(") == 0) {
            break;
        }
    }
    used = 0;
    body[0] = 0;
    for (;;) {
        if (readUntil(c, line, sizeof(line), '\n') < 0) {
            return 0;
        }
        trimCr(line);
        if (strcmp(line, "exit") == 0 && scriptEnds(c, body, body + used)) {
            return 1;
        }
        len = strlen(line);
        if (used + len + 2 > size) {
            return 0;
        }
        memcpy(body + used, line, len);
        used += len;
        body[used++] = '\n';
        body[used] = 0;
    }
}

/* joins the lines of body with & into one command line, leaving out blank
   ones; 0 if nothing is left or it does not fit */
static int joinLines(char *body, char *command, int size) {
    char *line;
    char *next;
    int used;
    int len;

    used = 0;
    command[0] = 0;
    for (line = body; *line != 0; line = next + 1) {
        next = strchr(line, '\n');
        len = (int)(next - line);
        if (isBlank(line, len)) {
            continue;
        }
        if (used + len + 2 > size) {
            return 0;
        }
        if (used > 0) {
            command[used++] = '&';
        }
        memcpy(command + used, line, len);
        used += len;
        command[used] = 0;
    }
    return used > 0;
}

static void doScript(CONN *c) {
    char body[CMD_SIZE];
    char command[CMD_SIZE];
    char text[LINE_SIZE];
    int whole;

    if (!sendByte(c->sock, 0)) {
        logMsg("[%d] client went away before its script came", c->id);
        return;
    }
    c->started = 1;
    limitReads(c, 1);
    whole = readScript(c, body, sizeof(body));
    limitReads(c, 0);
    if (!whole) {
        logMsg("[%d] the rsh-mcp script did not arrive whole, or is too long", c->id);
        sendNote(c, "the rsh-mcp script did not arrive whole, or is too long");
        return;
    }
    if (!joinLines(body, command, sizeof(command))) {
        logMsg("[%d] the rsh-mcp script has no command, or it is too long", c->id);
        sendNote(c, "the rsh-mcp script has no command, or it is too long");
        return;
    }
    logMsg("[%d] rsh-mcp script: %s", c->id, command);
    if (!addCommand(c, command)) {
        sendNote(c, "too many commands running, try again later");
        return;
    }
    if (!startCommand(c, command, text, sizeof(text))) {
        logMsg("[%d] %s", c->id, text);
        sendNote(c, text);
        return;
    }
    closeStdin(c);   /* the script was the input: the command gets none */
    serveCommand(c);
}

/* -------- rcp ------------------------------------------------------------ */

/* parses "Cmode size name", returns the name or NULL */
static char *parseFileLine(char *line, DWORD *size) {
    char *p;

    p = line + 1;
    while (*p >= '0' && *p <= '7') {
        p++;
    }
    if (*p != ' ') {
        return NULL;
    }
    p++;
    if (*p < '0' || *p > '9') {
        return NULL;
    }
    *size = 0;
    while (*p >= '0' && *p <= '9') {
        *size = *size * 10 + (DWORD)(*p - '0');
        p++;
    }
    if (*p != ' ' || p[1] == 0) {
        return NULL;
    }
    return p + 1;
}

/* receives size bytes into the file, then the sender's status byte;
   -1 connection broke, 0 write error, 1 ok */
static int recvToFile(CONN *c, HANDLE file, DWORD size) {
    char buf[IO_SIZE];
    DWORD written;
    DWORD done;
    int want;
    int n;
    int ok;

    ok = 1;
    for (done = 0; done < size; done += (DWORD)n) {
        want = IO_SIZE;
        if (size - done < (DWORD)want) {
            want = (int)(size - done);
        }
        n = recvWait(c, buf, want);
        if (n <= 0) {
            return -1;
        }
        if (!WriteFile(file, buf, (DWORD)n, &written, NULL) || written != (DWORD)n) {
            ok = 0;
        }
    }
    if (readResponse(c) < 0) {
        return -1;
    }
    return ok;
}

/* receives one file announced by a "C" line; returns 0 to stop */
static int sinkFile(CONN *c, char *line, char *target, int targetIsDir) {
    char path[CMD_SIZE + LINE_SIZE];
    HANDLE file;
    DWORD size;
    char *name;
    int result;

    name = parseFileLine(line, &size);
    if (name == NULL) {
        sendErr(c, "rcp: bad file line: %s", line);
        return 0;
    }
    if (targetIsDir && isBadName(name)) {
        sendErr(c, "rcp: %s: bad file name", name);
        return 1;
    }
    strcpy(path, target);
    if (targetIsDir) {
        joinPath(path, target, name);
    }
    file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        sendErr(c, "rcp: %s: cannot create, error %lu", path, GetLastError());
        return 1;
    }
    if (!sendByte(c->sock, 0)) {
        CloseHandle(file);
        return 0;
    }
    result = recvToFile(c, file, size);
    CloseHandle(file);
    switch (result) {
    case -1:
        logMsg("[%d] connection lost while receiving %s", c->id, path);
        return 0;
    case 0:
        sendErr(c, "rcp: %s: write failed", path);
        return 1;
    }
    logMsg("[%d] received %s, %lu bytes", c->id, path, size);
    return sendByte(c->sock, 0);
}

/* "rcp -t target": the client sends files and we store them */
static void rcpSink(CONN *c, char *target, int mustBeDir) {
    char line[LINE_SIZE];
    DWORD attrs;
    int targetIsDir;

    attrs = GetFileAttributes(target);
    targetIsDir = attrs != NO_ATTRS && (attrs & FILE_ATTRIBUTE_DIRECTORY);
    if (mustBeDir && !targetIsDir) {
        sendErr(c, "rcp: %s: Not a directory", target);
        return;
    }
    if (!sendByte(c->sock, 0)) {
        return;
    }
    for (;;) {
        if (readUntil(c, line, sizeof(line), '\n') < 0) {
            return;
        }
        switch (line[0]) {
        case 'C':
            if (!sinkFile(c, line, target, targetIsDir)) {
                return;
            }
            break;
        case 'D':
            sendErr(c, "rcp: directories are not supported");
            break;
        case 'E':
        case 'T':
            if (!sendByte(c->sock, 0)) {
                return;
            }
            break;
        default:
            logMsg("[%d] client error: %s", c->id, line + 1);
            return;
        }
    }
}

/* a standard rcp client sends a zero byte when it is ready to receive, some
   do not, so only wait a moment for it */
static void skipReadyByte(CONN *c) {
    struct timeval tv;
    fd_set fds;
    char ch;

    FD_ZERO(&fds);
    FD_SET(c->sock, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (select(0, &fds, NULL, NULL, &tv) == 1) {
        recv(c->sock, &ch, 1, 0);
    }
}

/* sends size bytes and the status byte, padding with zeros if the file got
   shorter so the client stays in step */
static int sendFromFile(CONN *c, HANDLE file, DWORD size) {
    char buf[IO_SIZE];
    DWORD done;
    DWORD want;
    DWORD n;
    int readOk;

    readOk = 1;
    for (done = 0; done < size; done += want) {
        want = IO_SIZE;
        if (size - done < want) {
            want = size - done;
        }
        if (!ReadFile(file, buf, want, &n, NULL)) {
            n = 0;
        }
        if (n < want) {
            memset(buf + n, 0, want - n);
            readOk = 0;
        }
        if (!sendAll(c->sock, buf, (int)want)) {
            return 0;
        }
    }
    if (!readOk) {
        sendErr(c, "rcp: read error");
        return 0;
    }
    return sendByte(c->sock, 0);
}

/* "rcp -f path": we send one file to the client */
static void rcpSource(CONN *c, char *path) {
    char line[CMD_SIZE + 64];
    HANDLE file;
    DWORD attrs;
    DWORD size;

    skipReadyByte(c);
    attrs = GetFileAttributes(path);
    if (attrs == NO_ATTRS) {
        sendErr(c, "rcp: %s: No such file or directory", path);
        return;
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        sendErr(c, "rcp: %s: Not a plain file", path);
        return;
    }
    file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        sendErr(c, "rcp: %s: cannot open, error %lu", path, GetLastError());
        return;
    }
    size = GetFileSize(file, NULL);
    if (size == NO_ATTRS) {
        CloseHandle(file);
        sendErr(c, "rcp: %s: cannot get size", path);
        return;
    }
    sprintf(line, "C0644 %lu %s\n", size, baseName(path));
    if (!sendAll(c->sock, line, strlen(line)) || readResponse(c) != 0 || !sendFromFile(c, file, size)) {
        CloseHandle(file);
        return;
    }
    CloseHandle(file);
    readResponse(c);
    logMsg("[%d] sent %s, %lu bytes", c->id, path, size);
}

/* handles "rcp -t path" and "rcp -f path", returns 0 for anything else */
static int doRcp(CONN *c, char *command) {
    char *p;
    int sink;
    int source;
    int mustBeDir;

    if (strncmp(command, "rcp ", 4) != 0) {
        return 0;
    }
    sink = 0;
    source = 0;
    mustBeDir = 0;
    p = command + 4;
    for (;;) {
        while (*p == ' ') {
            p++;
        }
        if (*p != '-') {
            break;
        }
        for (p++; *p != 0 && *p != ' '; p++) {
            switch (*p) {
            case 't':
                sink = 1;
                break;
            case 'f':
                source = 1;
                break;
            case 'd':
                mustBeDir = 1;
                break;
            default:
                break;
            }
        }
    }
    if (sink == source || *p == 0) {
        return 0;
    }
    trimEnd(p);
    fixSlashes(p);
    if (!sendByte(c->sock, 0)) {
        return 1;
    }
    if (sink) {
        logMsg("[%d] rcp: receiving into %s", c->id, p);
        rcpSink(c, p, mustBeDir);
        return 1;
    }
    logMsg("[%d] rcp: sending %s", c->id, p);
    rcpSource(c, p);
    return 1;
}

/* -------- a connection --------------------------------------------------- */

/* rsh request: stderr port, client user, server user, command, each ending
   in a zero byte; the stderr channel is connected before the rest arrives.
   The whole request must arrive within IO_SECONDS. */
static void handleConn(CONN *c) {
    char errPort[FIELD_SIZE];
    char localUser[FIELD_SIZE];
    char remoteUser[FIELD_SIZE];
    char command[CMD_SIZE];
    int port;

    limitReads(c, 1);
    if (readUntil(c, errPort, sizeof(errPort), 0) < 0) {
        logMsg("[%d] no request: the client closed, timed out or sent too much", c->id);
        return;
    }
    port = atoi(errPort);
    if (port != 0) {
        c->errSock = connectBack(c, port);
        if (c->errSock == INVALID_SOCKET) {
            sendErr(c, "rshd: cannot connect to stderr port %d", port);
            return;
        }
        c->errWatch = 1;
    }
    if (readUntil(c, localUser, sizeof(localUser), 0) < 0 ||
        readUntil(c, remoteUser, sizeof(remoteUser), 0) < 0 ||
        readUntil(c, command, sizeof(command), 0) < 0) {
        sendErr(c, "rshd: bad request: cut short, too slow, or a field too long");
        return;
    }
    limitReads(c, 0);
    logMsg("[%d] %s@%s: %s", c->id, localUser, c->ip, command);
    if (command[0] == 0) {
        sendErr(c, "rshd: no command");
        return;
    }
    if (strcmp(command, SCRIPT_CMD) == 0) {
        doScript(c);
        return;
    }
    if (!doRcp(c, command)) {
        doExec(c, command);
    }
}

/* an exception while serving one client must not end the daemon */
static void internalError(CONN *c, DWORD code) {
    char text[LINE_SIZE];

    sprintf(text, "internal error %08lx, rshd keeps running", code);
    if (c->proc != NULL) {
        stopCommand(c, STOP_GONE);
        killCommand(c);
    }
    if (c->started) {
        logMsg("[%d] %s", c->id, text);
        sendNote(c, text);
        return;
    }
    sendErr(c, "rshd: %s", text);
}

static void __cdecl connThread(void *arg) {
    unsigned char *ip;
    CONN *c;

    c = (CONN *)arg;
    ip = (unsigned char *)&c->peer.sin_addr;
    sprintf(c->ip, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    logMsg("[%d] connection from %s port %d", c->id, c->ip, ntohs(c->peer.sin_port));
    c->wake = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (c->wake == NULL) {
        logMsg("[%d] cannot make an event, error %lu, dropping the connection", c->id, GetLastError());
        closesocket(c->sock);
        free(c);
        return;
    }
    setNoDelay(c->sock);
    __try {
        handleConn(c);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        internalError(c, GetExceptionCode());
    }
    /* the FIN goes out first, so the client sees the end of the output at
       once; then the input thread must end before what it uses is freed */
    c->done = 1;
    c->finTick = GetTickCount();
    sendFin(c->errSock);
    sendFin(c->sock);
    if (c->monitorDone != NULL) {
        WaitForSingleObject(c->monitorDone, INFINITE);
        CloseHandle(c->monitorDone);
        c->monitorDone = NULL;
    }
    endCommand(c);
    closeConn(c, c->errSock, "stderr channel");
    closeConn(c, c->sock, "connection");
    logMsg("[%d] connection closed", c->id);
    dropHandle(c->wake);
    if (c->leak) {
        logMsg("[%d] a cancelled pipe read or write never ended; its memory is kept", c->id);
        return;
    }
    free(c);
}

/* hands the connection to a thread of its own and returns at once, so the
   accepting thread is ready for the next one (see acceptLoop) */
static void startConn(SOCKET s, struct sockaddr_in *peer, int id) {
    CONN *c;

    c = (CONN *)malloc(sizeof(CONN));
    if (c == NULL) {
        logMsg("[%d] out of memory, dropping the connection", id);
        closesocket(s);
        return;
    }
    memset(c, 0, sizeof(CONN));
    c->sock = s;
    c->errSock = INVALID_SOCKET;
    c->peer = *peer;
    c->id = id;
    c->slot = -1;
    c->sockWatch = 1;
    c->last = '\n';
    if (_beginthread(connThread, 0, c) == (unsigned long)-1L) {
        logMsg("[%d] cannot start a thread", id);
        closesocket(s);
        free(c);
    }
}

/* -------- the listener --------------------------------------------------- */

/* sleeps, but wakes at once when a quit is asked for */
static void quitWait(DWORD ms) {
    if (quitEvent == NULL || WaitForSingleObject(quitEvent, ms) == WAIT_FAILED) {
        Sleep(ms);
    }
}

/* closes the listening socket once, whichever thread comes first; this
   also wakes the main thread out of accept() */
static void closeListener(void) {
    SOCKET s;

    s = (SOCKET)InterlockedExchange((LONG *)&listener, (LONG)INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
}

static SOCKET bindListener(int port, int reuse) {
    struct sockaddr_in addr;
    SOCKET s;
    int on;
    int err;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    on = 1;
    if (reuse) {
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((u_short)port);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(s, LISTEN_BACKLOG) != 0) {
        err = WSAGetLastError();
        closesocket(s);
        WSASetLastError(err);
        return INVALID_SOCKET;
    }
    return s;
}

static int portAnswers(int port) {
    struct sockaddr_in addr;
    struct timeval tv;
    fd_set okFds;
    fd_set badFds;
    u_long on;
    SOCKET s;
    int answers;
    int n;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        return 0;
    }
    on = 1;
    ioctlsocket(s, FIONBIO, &on);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        closesocket(s);
        return 1;
    }
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(s);
        return 0;
    }
    FD_ZERO(&okFds);
    FD_SET(s, &okFds);
    FD_ZERO(&badFds);
    FD_SET(s, &badFds);
    tv.tv_sec = PROBE_SECONDS;
    tv.tv_usec = 0;
    n = select(0, NULL, &okFds, &badFds, &tv);
    answers = n == 0 || (n > 0 && FD_ISSET(s, &okFds));
    closesocket(s);
    return answers;
}

static SOCKET openListener(int port) {
    SOCKET s;
    int err;

    s = bindListener(port, 0);
    err = WSAGetLastError();
    if (s == INVALID_SOCKET && err == WSAEADDRINUSE) {
        if (portAnswers(port)) {
            portState = PORT_TAKEN;
            logMsg("port %d is in use by another program (another rsh server, or a program an old ntrshd started)", port);
            return INVALID_SOCKET;
        }
        logMsg("port %d is held only by connections that are closing, reusing it", port);
        s = bindListener(port, 1);
        err = WSAGetLastError();
    }
    if (s != INVALID_SOCKET) {
        portState = PORT_LISTENING;
        logMsg("listening on port %d", port);
        return s;
    }
    portError = err;
    portState = PORT_FAILED;
    logMsg("cannot listen on port %d, error %d", port, err);
    return INVALID_SOCKET;
}

static SOCKET startListener(int port) {
    SOCKET s;

    for (;;) {
        if (!runFlag) {
            return INVALID_SOCKET;
        }
        s = openListener(port);
        if (s != INVALID_SOCKET) {
            return s;
        }
        logMsg("trying again in %d seconds", RETRY_SECONDS);
        quitWait(RETRY_SECONDS * 1000);
    }
}

static void acceptLoop(int port) {
    struct sockaddr_in peer;
    SOCKET s;
    int fails;
    int len;

    /* NT Workstation keeps at most 5 connections waiting for accept() and
       refuses the rest.  Above the session threads, this thread takes each
       connection as soon as it comes, even on one busy CPU; it sleeps in
       accept() the rest of the time.  New threads start at normal priority. */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    fails = 0;
    for (;;) {
        if (!runFlag) {
            return;
        }
        if (listener == INVALID_SOCKET) {
            listener = startListener(port);
            if (listener == INVALID_SOCKET) {
                return;
            }
            if (!runFlag) {
                return;   /* a quit came while the port was opening; serve() closes it */
            }
            logMsg("waiting for connections");
        }
        len = sizeof(peer);
        s = accept(listener, (struct sockaddr *)&peer, &len);
        if (!runFlag) {
            if (s != INVALID_SOCKET) {
                closesocket(s);
            }
            return;
        }
        if (s == INVALID_SOCKET) {
            fails++;
            logMsg("accept failed, error %d", WSAGetLastError());
            if (fails >= ACCEPT_FAILS) {
                logMsg("the listening socket looks broken, opening it again");
                closeListener();
                fails = 0;
            }
            quitWait(1000);
            continue;
        }
        fails = 0;
        connCount++;
        startConn(s, &peer, connCount);
    }
}

static void serve(int port) {
    while (runFlag) {
        __try {
            acceptLoop(port);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            logMsg("internal error %08lx while accepting, starting over", GetExceptionCode());
        }
        closeListener();
        if (runFlag) {
            quitWait(1000);
        }
    }
}

/* -------- one ntrshd per port -------------------------------------------- */

/*
 * Two ntrshd on one port would fight over it, so each one owns a named
 * mutex for its port while it serves.  Windows lets go of the mutex when
 * the owner ends, however it ends.  Wait a moment for it, in case the other
 * ntrshd was just told to quit.  The calling thread owns the mutex, so the
 * same thread must call releasePort.
 */
static int claimPort(int port) {
    char name[32];
    DWORD r;

    sprintf(name, "ntrshd-port-%d", port);
    portMutex = CreateMutex(NULL, FALSE, name);
    if (portMutex == NULL) {
        /* access denied: an ntrshd under another account (the service) made
           it; any other failure: let the port check decide */
        return GetLastError() != ERROR_ACCESS_DENIED;
    }
    r = WaitForSingleObject(portMutex, CLAIM_WAIT_MS);
    if (r == WAIT_TIMEOUT) {
        CloseHandle(portMutex);
        portMutex = NULL;
        return 0;
    }
    return 1;   /* ours; WAIT_ABANDONED means the last owner died holding it */
}

static void releasePort(void) {
    if (portMutex != NULL) {
        ReleaseMutex(portMutex);
        CloseHandle(portMutex);
        portMutex = NULL;
    }
}

/* -------- console control ------------------------------------------------ */

/* stops accepting and tells every running command to stop; each session's
   helper sends CTRL_BREAK, then kills its command after a grace period
   (see runHelper) */
static void requestQuit(void) {
    runFlag = 0;
    if (quitEvent != NULL) {
        SetEvent(quitEvent);
    }
    stopAll(STOP_SHUTDOWN);
    closeListener();
}

/*
 * Ctrl+C or Ctrl+Break quits.  The first press is graceful: it stops
 * accepting and tells every running command to stop, and the main thread
 * waits for them (see drainCommands).  A second press kills every command
 * and exits at once, for when something is wedged.
 *
 * Closing the window, logging off and shutting down quit at once, from
 * inside this handler.  It must not return TRUE for those: NT 3.x and 4.0
 * then keep the window and ask the user to End Task the program, and newer
 * Windows kill the process as soon as the handler returns.  So kill the
 * commands, give the sessions a moment to tell their clients, and exit.
 */
static BOOL WINAPI onCtrl(DWORD type) {
    if (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        logMsg("%s: killing all commands and quitting",
               type == CTRL_CLOSE_EVENT ? "window closed" : "logoff or shutdown");
        requestQuit();
        killAll();
        drainCommands(CLOSE_WAIT_MS);
        ExitProcess(0);
        return FALSE;   /* not reached */
    }
    if (runFlag) {
        logMsg("quitting: stopping commands (press Ctrl+C again to kill now)");
        requestQuit();
        return TRUE;   /* handled: the main thread drains, then the process exits */
    }
    /* a second interrupt: do not wait, kill everything and let the process end */
    logMsg("second interrupt: killing all commands now");
    killAll();
    return FALSE;
}

/* -------- service plumbing ----------------------------------------------- */

static void reportStatus(DWORD state, DWORD exitCode, DWORD wait) {
    static DWORD checkpoint = 1;

    if (!asService || svcStatusHandle == 0) {
        return;
    }
    svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    svcStatus.dwServiceSpecificExitCode = 0;
    svcStatus.dwCurrentState = state;
    svcStatus.dwWin32ExitCode = exitCode;
    svcStatus.dwWaitHint = wait;
    svcStatus.dwControlsAccepted = (state == SERVICE_START_PENDING)
        ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) {
        svcStatus.dwCheckPoint = 0;
    } else {
        svcStatus.dwCheckPoint = checkpoint++;
    }
    SetServiceStatus(svcStatusHandle, &svcStatus);
}

static void SVCAPI serviceCtrl(DWORD code) {
    switch (code) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        requestQuit();
        return;
    default:
        break;
    }
    reportStatus(svcStatus.dwCurrentState, NO_ERROR, 0);
}

static void openLogFile(void) {
    char path[MAX_PATH + 16];
    char *name;

    if (GetModuleFileName(NULL, path, MAX_PATH) == 0) {
        return;
    }
    path[MAX_PATH - 1] = 0;
    name = baseName(path);
    *name = 0;
    strcat(path, "ntrshd.log");
    logFile = fopen(path, "a");
}

/* logs this host's name and its IPv4 address(es), like ipconfig; uses only
   Winsock 1.1 calls, so it works on every NT version */
static void logLocalAddresses(void) {
    char name[256];
    struct hostent *he;
    struct in_addr addr;
    int i;
    int found;

    if (gethostname(name, sizeof(name)) != 0) {
        logMsg("cannot get this host's name, error %d", WSAGetLastError());
        return;
    }
    he = gethostbyname(name);
    if (he == NULL || he->h_addrtype != AF_INET) {
        logMsg("host name: %s (no IP address found, error %d)", name, WSAGetLastError());
        return;
    }
    logMsg("host name: %s", name);
    _snprintf(hostLabel, sizeof(hostLabel) - 1, "%s", name);
    hostLabel[sizeof(hostLabel) - 1] = 0;
    found = 0;
    ipLabel[0] = 0;
    for (i = 0; he->h_addr_list[i] != NULL; i++) {
        char *s;
        char piece[96];
        memcpy(&addr, he->h_addr_list[i], sizeof(addr));
        s = inet_ntoa(addr);
        logMsg("  IP address: %s", s);
        _snprintf(piece, sizeof(piece) - 1, "%s%s", ipLabel[0] != 0 ? " " : "", s);
        piece[sizeof(piece) - 1] = 0;
        if (strlen(ipLabel) + strlen(piece) < sizeof(ipLabel)) {
            strcat(ipLabel, piece);
        }
        found = 1;
    }
    if (!found) {
        logMsg("  IP address: none");
        strcpy(ipLabel, "none");
    }
}

static int beginServe(void) {
    WSADATA wsa;
    int err;

    comspec = getenv("COMSPEC");
    if (GetModuleFileName(NULL, selfPath, sizeof(selfPath)) == 0) {
        logMsg("cannot find my own path, error %lu", GetLastError());
        return 0;
    }
    selfPath[sizeof(selfPath) - 1] = 0;
    /* a program that cannot load or crashes must fail at once, not pop up a
       box that would hang the client; commands inherit this mode */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    err = WSAStartup(MAKEWORD(1, 1), &wsa);
    if (err != 0) {
        logMsg("winsock did not start, error %d", err);
        return 0;
    }
    logMsg("winsock %d.%d started: %s", LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion), wsa.szDescription);
    upSince = GetTickCount();
    logLocalAddresses();
    return 1;
}

static void SVCAPI serviceMain(DWORD argc, LPTSTR *argv) {
    (void)argc;
    (void)argv;
    asService = 1;
    svcStatusHandle = RegisterServiceCtrlHandler(SVC_NAME, serviceCtrl);
    if (svcStatusHandle == 0) {
        return;
    }
    reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    openLogFile();
    logMsg("ntrshd %s service starting", RSHD_VERSION);
    if (!claimPort(rshPort)) {
        logMsg("another ntrshd is already serving port %d (in a console window?); the service will not start", rshPort);
        reportStatus(SERVICE_STOPPED, ERROR_SERVICE_ALREADY_RUNNING, 0);
        return;
    }
    if (beginServe()) {
        reportStatus(SERVICE_RUNNING, NO_ERROR, 0);
        serve(rshPort);
        /* stopping: the running commands get their grace period */
        reportStatus(SERVICE_STOP_PENDING, NO_ERROR, STOP_WAIT_MS + 4000);
        drainCommands(STOP_WAIT_MS + 2000);
    }
    releasePort();
    logMsg("ntrshd service stopped");
    reportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

/* -------- install / remove ----------------------------------------------- */

static void doInstall(char *user, char *password, char *extra) {
    SC_HANDLE scm;
    SC_HANDLE svc;
    char myPath[MAX_PATH];
    char sysDir[MAX_PATH];
    char binPath[MAX_PATH + 16];
    char image[MAX_PATH + EXTRA_SIZE + 32];

    if (GetModuleFileName(NULL, myPath, sizeof(myPath)) == 0) {
        printf("cannot find my own path, error %lu\n", GetLastError());
        return;
    }
    myPath[sizeof(myPath) - 1] = 0;
    if (GetSystemDirectory(sysDir, sizeof(sysDir)) == 0) {
        printf("cannot find the system directory, error %lu\n", GetLastError());
        return;
    }
    sprintf(binPath, "%s\\%s.exe", sysDir, SVC_NAME);
    /* A service the SCM starts at boot has no mapped drives (those live in an
       interactive logon), so install from a local path: copy the exe into the
       system directory and register that copy, not wherever we were run from. */
    if (lstrcmpi(myPath, binPath) != 0) {
        if (!CopyFile(myPath, binPath, FALSE)) {
            printf("cannot copy exe to %s, error %lu\n", binPath, GetLastError());
            return;
        }
        printf("copied exe to %s\n", binPath);
    }
    /* NT 3.1's service controller cannot start a quoted path ("net start"
       fails with system error 2), so quote it only when it has a space */
    if (strchr(binPath, ' ') != NULL) {
        sprintf(image, "\"%s\"%s", binPath, extra);
    } else {
        sprintf(image, "%s%s", binPath, extra);
    }
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        printf("OpenSCManager failed, error %lu (need administrator rights)\n", GetLastError());
        return;
    }
    svc = CreateService(scm, SVC_NAME, SVC_DISPLAY, SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                        image, NULL, NULL, NULL, user, password);
    if (svc == NULL) {
        printf("CreateService failed, error %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return;
    }
    printf("%s installed (auto-start on boot).\n", SVC_DISPLAY);
    printf("  binary: %s\n", image);
    if (user != NULL) {
        printf("  account: %s\n", user);
    } else {
        printf("  account: LocalSystem (no access to mapped network drives)\n");
    }
    printf("Start it now with:  net start %s\n", SVC_NAME);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static void doRemove(void) {
    SC_HANDLE scm;
    SC_HANDLE svc;
    SERVICE_STATUS st;
    char sysDir[MAX_PATH];
    char binPath[MAX_PATH];

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        printf("OpenSCManager failed, error %lu (need administrator rights)\n", GetLastError());
        return;
    }
    svc = OpenService(scm, SVC_NAME, SERVICE_ALL_ACCESS);
    if (svc == NULL) {
        printf("%s is not installed (error %lu)\n", SVC_NAME, GetLastError());
        CloseServiceHandle(scm);
        return;
    }
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        printf("stopping %s", SVC_DISPLAY);
        Sleep(500);
        while (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOP_PENDING) {
            printf(".");
            Sleep(500);
        }
        printf("\n");
    }
    if (DeleteService(svc)) {
        printf("%s removed.\n", SVC_DISPLAY);
    } else {
        printf("DeleteService failed, error %lu\n", GetLastError());
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    /* remove the copy -install put in the system directory (best effort:
       it may be the very exe running this -remove, which cannot delete itself) */
    if (GetSystemDirectory(sysDir, sizeof(sysDir)) != 0) {
        sprintf(binPath, "%s\\%s.exe", sysDir, SVC_NAME);
        if (DeleteFile(binPath)) {
            printf("deleted %s\n", binPath);
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            printf("could not delete %s, error %lu (delete it by hand)\n", binPath, GetLastError());
        }
    }
}

/* -------- command line --------------------------------------------------- */

static void usage(void) {
    printf("ntrshd %s - remote shell daemon (rsh/rcp) for Windows NT\n\n", RSHD_VERSION);
    printf("usage: ntrshd [options]\n");
    printf("  (no options)   open a console and serve; the SCM runs it as a service\n");
    printf("  -install       install as an auto-start service\n");
    printf("     -user NAME    run the service as this account (DOMAIN\\user or .\\user)\n");
    printf("     -pass PASS    that account's password\n");
    printf("     other options after -install are passed to the service\n");
    printf("  -remove        stop and remove the service\n");
    printf("  -p PORT        listen on this port instead of %d\n", RSH_PORT);
    printf("  -t MINUTES     stop a command silent this long (0 = never, default)\n");
    printf("  -g SECONDS     wait this long for a grandchild's last output (default %d)\n", GRAND_GRACE_MS / 1000);
    printf("  -e             send the command's exit code as a last line\n");
    printf("  -q             quiet: plain scrolling log instead of the status window\n");
    printf("  -d             extra debug detail in the log\n");
    printf("  -v             show version and exit\n");
    printf("  -h             this help\n");
}

/* parses options, performs -install/-remove/-h/-v and exits for those;
   returns 1 if the daemon should start, 0 for a bad option */
static int parseArgs(int argc, char **argv) {
    char extra[EXTRA_SIZE];
    char *user;
    char *password;
    int minutes;
    int seconds;
    int i;
    int x;

    for (i = 1; i < argc; i++) {
        if (lstrcmpi(argv[i], "-install") == 0) {
            extra[0] = 0;
            user = NULL;
            password = NULL;
            for (x = i + 1; x < argc; x++) {
                if (lstrcmpi(argv[x], "-user") == 0 && x + 1 < argc) {
                    user = argv[++x];
                } else if (lstrcmpi(argv[x], "-pass") == 0 && x + 1 < argc) {
                    password = argv[++x];
                } else if (strlen(extra) + strlen(argv[x]) + 2 <= sizeof(extra)) {
                    strcat(extra, " ");
                    strcat(extra, argv[x]);
                } else {
                    printf("the options after -install are too long\n");
                    exit(1);
                }
            }
            doInstall(user, password, extra);
            exit(0);
        }
        if (lstrcmpi(argv[i], "-remove") == 0) {
            doRemove();
            exit(0);
        }
        if (lstrcmpi(argv[i], "-h") == 0 || strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "/?") == 0) {
            usage();
            exit(0);
        }
        if (lstrcmpi(argv[i], "-v") == 0) {
            printf("ntrshd %s\n", RSHD_VERSION);
            exit(0);
        }
        if (strcmp(argv[i], "-q") == 0) {
            quietFlag = 1;
            continue;
        }
        if (strcmp(argv[i], "-d") == 0) {
            debugFlag = 1;
            continue;
        }
        if (strcmp(argv[i], "-e") == 0) {
            sendExit = 1;
            continue;
        }
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            rshPort = atoi(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            i++;
            minutes = atoi(argv[i]);
            if (argv[i][0] < '0' || argv[i][0] > '9' || minutes > 10000) {
                return 0;
            }
            idleLimit = (DWORD)minutes * 60000;
            continue;
        }
        if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
            i++;
            seconds = atoi(argv[i]);
            if (argv[i][0] < '0' || argv[i][0] > '9' || seconds > 3600) {
                return 0;
            }
            grandGrace = (DWORD)seconds * 1000;
            continue;
        }
        return 0;
    }
    if (rshPort < 1 || rshPort > 65535) {
        return 0;
    }
    return 1;
}

/*
 * A console-subsystem program double-clicked or run from a shell has a valid
 * standard output handle; a service started by the SCM has none.  This lets
 * a double-click open the console at once, without the delay of asking the
 * SCM first.  If the guess is wrong, the service dispatcher below still falls
 * back to console mode.
 */
static int looksInteractive(void) {
    HANDLE h;

    h = GetStdHandle(STD_OUTPUT_HANDLE);
    return h != NULL && h != INVALID_HANDLE_VALUE;
}

static void showSettings(void) {
    char dir[MAX_PATH];
    DWORD n;

    n = GetCurrentDirectory(sizeof(dir), dir);
    if (n == 0 || n >= sizeof(dir)) {
        strcpy(dir, "?");
    }
    logMsg("ntrshd %s for Windows NT", RSHD_VERSION);
    logMsg("port %d, commands run in %s", rshPort, dir);
    if (comspec != NULL) {
        logMsg("commands run as: %s /c <command>", comspec);
    } else {
        logMsg("COMSPEC is not set, commands run with cmd from the path");
    }
    if (idleLimit != 0) {
        logMsg("a command silent for %lu minute%s is stopped", idleLimit / 60000, idleLimit == 60000 ? "" : "s");
    }
    logMsg("each command runs in a hidden console of its own");
    if (debugFlag) {
        logMsg("debug log: one line per event");
    }
    logMsg("Ctrl+C or Ctrl+Break quits; commands get a moment to stop, press again to kill now");
    logMsg("security: open (+ +)");
}

/* -------- console status window ----------------------------------------- */

/* writes one line at the given row, padded to the window width so it fully
   overwrites what was there before; no scrolling, no cursor movement */
static void putLine(HANDLE h, int row, int w, const char *s) {
    char buf[256];
    COORD at;
    DWORD done;
    int n;

    n = lstrlen(s);
    if (n > w) {
        n = w;
    }
    memcpy(buf, s, n);
    while (n < w) {
        buf[n++] = ' ';
    }
    at.X = 0;
    at.Y = (SHORT)row;
    WriteConsoleOutputCharacter(h, buf, (DWORD)w, at, &done);
}

static void clearScreen(HANDLE h) {
    CONSOLE_SCREEN_BUFFER_INFO sbi;
    CONSOLE_CURSOR_INFO ci;
    COORD home;
    DWORD cells;
    DWORD done;

    if (!GetConsoleScreenBufferInfo(h, &sbi)) {
        return;
    }
    cells = (DWORD)sbi.dwSize.X * (DWORD)sbi.dwSize.Y;
    home.X = 0;
    home.Y = 0;
    FillConsoleOutputCharacter(h, ' ', cells, home, &done);
    SetConsoleCursorPosition(h, home);
    if (GetConsoleCursorInfo(h, &ci)) {
        ci.bVisible = FALSE;
        SetConsoleCursorInfo(h, &ci);
    }
}

static void setTitle(int ns) {
    char title[64];

    if (portState == PORT_OPENING) {
        strcpy(title, "NTRSHD: STARTING");
    } else if (portState != PORT_LISTENING) {
        strcpy(title, "NTRSHD: NOT LISTENING");
    } else if (ns <= 0) {
        strcpy(title, "NTRSHD: IDLE");
    } else {
        _snprintf(title, sizeof(title) - 1, "NTRSHD: %d conn", ns);
        title[sizeof(title) - 1] = 0;
    }
    SetConsoleTitle(title);
}

/* redraws the whole status window: header plus one row per running command */
static void drawStatus(void) {
    HANDLE h;
    CONSOLE_SCREEN_BUFFER_INFO sbi;
    CONN *c;
    int w, row, i, ns;
    DWORD up, e;
    char line[256];
    static int prevRows = 0;
    struct {
        int id;
        char ip[16];
        char cmd[128];
        DWORD t;
    } snap[64];

    h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!GetConsoleScreenBufferInfo(h, &sbi)) {
        return;   /* output is redirected, not a console: nothing to draw */
    }
    w = sbi.dwSize.X;
    if (w < 24) {
        w = 24;
    }
    if (w > 200) {
        w = 200;
    }

    /* snapshot the running table under the lock, then render without it held */
    ns = 0;
    EnterCriticalSection(&runLock);
    for (i = 0; i < MAX_RUNNING && ns < 64; i++) {
        c = running[i];
        if (c == NULL) {
            continue;
        }
        snap[ns].id = c->id;
        _snprintf(snap[ns].ip, sizeof(snap[ns].ip) - 1, "%s", c->ip);
        snap[ns].ip[sizeof(snap[ns].ip) - 1] = 0;
        _snprintf(snap[ns].cmd, sizeof(snap[ns].cmd) - 1, "%s", c->cmd);
        snap[ns].cmd[sizeof(snap[ns].cmd) - 1] = 0;
        snap[ns].t = c->startTick;
        ns++;
    }
    LeaveCriticalSection(&runLock);
    setTitle(ns);

    row = 0;
    up = (GetTickCount() - upSince) / 1000;
    _snprintf(line, sizeof(line) - 1, "ntrshd %s - RSH daemon for Windows NT", RSHD_VERSION);
    line[sizeof(line) - 1] = 0;
    putLine(h, row++, w, line);
    _snprintf(line, sizeof(line) - 1, "host %s   IP %s", hostLabel, ipLabel);
    line[sizeof(line) - 1] = 0;
    putLine(h, row++, w, line);
    if (portState == PORT_LISTENING) {
        _snprintf(line, sizeof(line) - 1, "port %d   up %lu:%02lu:%02lu   sessions %d",
                  rshPort, up / 3600, (up / 60) % 60, up % 60, ns);
    } else if (portState == PORT_TAKEN) {
        _snprintf(line, sizeof(line) - 1, "port %d: NOT LISTENING - another program has it; retry every %d s",
                  rshPort, RETRY_SECONDS);
    } else if (portState == PORT_FAILED) {
        _snprintf(line, sizeof(line) - 1, "port %d: NOT LISTENING - error %d; retry every %d s",
                  rshPort, portError, RETRY_SECONDS);
    } else {
        _snprintf(line, sizeof(line) - 1, "port %d: opening", rshPort);
    }
    line[sizeof(line) - 1] = 0;
    putLine(h, row++, w, line);
    putLine(h, row++, w, "security: open (+ +)");
    putLine(h, row++, w, "");
    putLine(h, row++, w, " ID   FROM             TIME    COMMAND");
    for (i = 0; i < ns; i++) {
        e = (GetTickCount() - snap[i].t) / 1000;
        _snprintf(line, sizeof(line) - 1, " %-4d %-15s %2lu:%02lu   %s",
                  snap[i].id, snap[i].ip, e / 60, e % 60, snap[i].cmd);
        line[sizeof(line) - 1] = 0;
        putLine(h, row++, w, line);
    }
    if (ns == 0) {
        putLine(h, row++, w, " (no commands running)");
    }
    putLine(h, row++, w, "");
    putLine(h, row++, w, "Ctrl+C / Ctrl+Break: quit (press again to kill now)");
    /* erase rows left over from a frame that had more sessions */
    for (i = row; i < prevRows; i++) {
        putLine(h, i, w, "");
    }
    prevRows = row;
}

static void statusThread(void *arg) {
    (void)arg;
    while (runFlag) {
        if (statusMode) {
            drawStatus();              /* full window, also sets the title */
        } else {
            setTitle(countRunning());  /* -q mode: keep only the title current */
        }
        Sleep(STATUS_MS);
    }
}

/* true when ntrshd got a console window of its own (double-clicked, or
   started with "start"): it is still empty, with the cursor in the top left
   corner.  Run from a prompt, the cursor is below the command line. */
static int consoleIsOurs(void) {
    CONSOLE_SCREEN_BUFFER_INFO sbi;

    if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &sbi)) {
        return 0;
    }
    return sbi.dwCursorPosition.X == 0 && sbi.dwCursorPosition.Y == 0;
}

/* a console window of its own closes the moment ntrshd exits, so after a
   startup error keep it open until a key is pressed (at most HOLD_MS), or
   the message is gone before anyone can read it */
static void holdWindow(void) {
    INPUT_RECORD rec;
    HANDLE in;
    DWORD start;
    DWORD r;
    DWORD n;

    if (!ownConsole) {
        return;
    }
    in = GetStdHandle(STD_INPUT_HANDLE);
    if (in == NULL || in == INVALID_HANDLE_VALUE) {
        return;
    }
    printf("\nPress any key to close this window.\n");
    fflush(stdout);
    FlushConsoleInputBuffer(in);
    start = GetTickCount();
    while (GetTickCount() - start < HOLD_MS) {
        r = WaitForSingleObject(in, 500);
        if (r == WAIT_TIMEOUT) {
            continue;
        }
        if (r != WAIT_OBJECT_0 || !ReadConsoleInput(in, &rec, 1, &n)) {
            return;
        }
        if (n == 1 && rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) {
            return;
        }
    }
}

static int runConsole(void) {
    HANDLE h;
    CONSOLE_CURSOR_INFO ci;

    ownConsole = consoleIsOurs();   /* first, before anything is printed */
    openLogFile();
    if (!claimPort(rshPort)) {
        logMsg("another ntrshd is already serving port %d (another window, or the service)", rshPort);
        logMsg("this one will not start; a second ntrshd needs its own port: -p PORT");
        holdWindow();
        return 1;
    }
    SetConsoleCtrlHandler(onCtrl, TRUE);
    if (!beginServe()) {
        holdWindow();
        return 1;
    }
    h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!quietFlag) {
        statusMode = 1;
        clearScreen(h);
    }
    showSettings();
    _beginthread(statusThread, 0, NULL);
    serve(rshPort);
    releasePort();                 /* not listening any more: another ntrshd may start */
    drainCommands(STOP_WAIT_MS + 2000);
    statusMode = 0;
    if (!quietFlag) {
        Sleep(STATUS_MS);          /* let the status thread stop painting */
        clearScreen(h);            /* wipe the status screen so the prompt is clean */
        if (GetConsoleCursorInfo(h, &ci)) {
            ci.bVisible = TRUE;    /* clearScreen hid the cursor; show it again */
            SetConsoleCursorInfo(h, &ci);
        }
    }
    return 0;
}

/* -------- the session helper --------------------------------------------- */

static char *skipBlanks(char *p) {
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return p;
}

/* skips a command line's first word, which may be in quotes, and the
   blanks after it */
static char *skipWord(char *p) {
    p = skipBlanks(p);
    if (*p == '"') {
        for (p++; *p != 0 && *p != '"'; p++) {
        }
        if (*p == '"') {
            p++;
        }
    } else {
        while (*p != 0 && *p != ' ' && *p != '\t') {
            p++;
        }
    }
    return skipBlanks(p);
}

static DWORD readNumber(char **p) {
    DWORD n;

    n = 0;
    *p = skipBlanks(*p);
    while (**p >= '0' && **p <= '9') {
        n = n * 10 + (DWORD)(**p - '0');
        (*p)++;
    }
    return n;
}

/* one of ntrshd's handles, given by its value there, as one of ours */
static HANDLE fromParent(HANDLE parent, DWORD value, BOOL inherit) {
    HANDLE h;

    if (value == 0 || !DuplicateHandle(parent, (HANDLE)value, GetCurrentProcess(), &h, 0, inherit, DUPLICATE_SAME_ACCESS)) {
        return NULL;
    }
    return h;
}

/* the helper outlives the CTRL_BREAK it sends its own console, and the
   logoff of whoever is logged on (a service must); a close or a shutdown
   ends it as usual */
static BOOL WINAPI helperCtrl(DWORD type) {
    return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_LOGOFF_EVENT;
}

/*
 * The session helper, "ntrshd -session ..." (see startCommand).  ntrshd
 * starts it in a new hidden console with nothing inherited, and it runs
 * the command in that console.  This gives each session:
 *
 *  - a console of its own, so a Ctrl+C, a Ctrl+Break or a closed console
 *    in one session reaches neither another session nor ntrshd;
 *  - a way to stop the command and what it started: CTRL_BREAK to every
 *    process on the console, then TerminateProcess after a grace period.
 *    ntrshd cannot do that itself (a console signal reaches only the
 *    sender's own console, and NT has no AttachConsole), and as a service
 *    it has no console at all;
 *  - no stray handles: the helper copies the handles it needs out of
 *    ntrshd with DuplicateHandle, by their values on its command line, so
 *    nothing else of ntrshd's (its sockets, other sessions' pipes) is ever
 *    inherited, on any NT version (SetHandleInformation came in 3.51);
 *  - a command that dies with ntrshd, should ntrshd itself end.
 *
 * Command line:  -session PID IN OUT ERR STOP KILL READY GRACE COMMAND
 * PID is ntrshd's process id; IN, OUT and ERR are the command's pipe ends
 * (ERR 0 when stderr goes with stdout); STOP and KILL are events; READY is
 * a semaphore, released by the command's process id once it runs; GRACE
 * is in milliseconds; COMMAND is the rest of the line, run as it is.  The
 * exit code is the command's.  If the command never ran it is the error:
 * HELPER_FAIL plus the error if the helper could not get its handles, the
 * error alone if the command could not start.
 */
static DWORD runHelper(void) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE parent;
    HANDLE in, out, err;
    HANDLE stopEv, killEv, ready;
    HANDLE waits[4];
    DWORD value[6];
    DWORD pid;
    DWORD grace;
    DWORD code;
    DWORD r;
    char *p;
    int i;

    SetConsoleCtrlHandler(helperCtrl, TRUE);
    p = skipWord(GetCommandLine());     /* ntrshd */
    p = skipWord(p);                    /* -session */
    pid = readNumber(&p);
    for (i = 0; i < 6; i++) {
        value[i] = readNumber(&p);
    }
    grace = readNumber(&p);
    p = skipBlanks(p);
    parent = OpenProcess(PROCESS_DUP_HANDLE | SYNCHRONIZE, FALSE, pid);
    if (parent == NULL) {
        return HELPER_FAIL | GetLastError();
    }
    in = fromParent(parent, value[0], TRUE);
    out = fromParent(parent, value[1], TRUE);
    err = fromParent(parent, value[2], TRUE);
    stopEv = fromParent(parent, value[3], FALSE);
    killEv = fromParent(parent, value[4], FALSE);
    ready = fromParent(parent, value[5], FALSE);
    if (in == NULL || out == NULL || (value[2] != 0 && err == NULL)
        || stopEv == NULL || killEv == NULL || ready == NULL || *p == 0) {
        return HELPER_FAIL | GetLastError();
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in;
    si.hStdOutput = out;
    si.hStdError = err != NULL ? err : out;
    if (!CreateProcess(NULL, p, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        return GetLastError();
    }
    CloseHandle(pi.hThread);
    /* the command has its own copies: without ours the pipes reach
       end-of-file as soon as it, and what it started, closes them */
    CloseHandle(in);
    CloseHandle(out);
    if (err != NULL) {
        CloseHandle(err);
    }
    if (!ReleaseSemaphore(ready, (LONG)pi.dwProcessId, NULL)) {
        ReleaseSemaphore(ready, 1, NULL);
    }
    CloseHandle(ready);

    waits[0] = pi.hProcess;
    waits[1] = killEv;
    waits[2] = parent;
    waits[3] = stopEv;
    r = WaitForMultipleObjects(4, waits, FALSE, INFINITE);
    if (r != WAIT_OBJECT_0) {
        /* stop: CTRL_BREAK to everything on this console, a grace period,
           then kill.  Kill, or ntrshd gone: the same without the grace. */
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0);
        if (r == WAIT_OBJECT_0 + 3) {
            r = WaitForMultipleObjects(3, waits, FALSE, grace);
        }
        if (r != WAIT_OBJECT_0) {
            TerminateProcess(pi.hProcess, CONTROL_C_EXIT);
        }
    }
    WaitForSingleObject(pi.hProcess, CANCEL_MS);
    if (!GetExitCodeProcess(pi.hProcess, &code)) {
        code = CONTROL_C_EXIT;
    }
    return code;
}

int main(int argc, char **argv) {
    SERVICE_TABLE_ENTRY dispatch[2];

    if (argc > 1 && strcmp(argv[1], "-session") == 0) {
        return (int)runHelper();
    }
    InitializeCriticalSection(&runLock);
    InitializeCriticalSection(&portLock);
    InitializeCriticalSection(&logLock);
    quitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (!parseArgs(argc, argv)) {
        usage();
        return 1;
    }

    if (looksInteractive()) {
        return runConsole();
    }

    /* no console: probably the SCM starting us as a service */
    dispatch[0].lpServiceName = SVC_NAME;
    dispatch[0].lpServiceProc = serviceMain;
    dispatch[1].lpServiceName = NULL;
    dispatch[1].lpServiceProc = NULL;
    if (StartServiceCtrlDispatcher(dispatch)) {
        return 0;
    }
    /* not started by the SCM after all: run as a console program */
    return runConsole();
}
