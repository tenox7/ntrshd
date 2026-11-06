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
 * "cmd /c <command>" in its own hidden process group, with stdout and
 * (optionally) stderr piped back to the client.  Many sessions run at
 * once, fully independent: no shared buffers, no handles inherited from
 * one session into another, no shared console signal.
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

#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <process.h>

/*
 * Build-time target detection.  The SAME source picks the right APIs for
 * each SDK, keyed off the compiler version:
 *   _MSC_VER  800  = NT 3.1 SDK   (cl386 8.00)
 *   _MSC_VER  900  = Visual C++ 2.0 (NT 3.5)
 *   _MSC_VER 1000+ = Visual C++ 4.x (NT 4.0 and later)
 * SetHandleInformation exists on NT 3.51+, so only the NT 4.0 build uses
 * it to make sockets non-inheritable.  Older builds get "lesser" handling
 * (a graceful shutdown still sends FIN even if a sibling inherited a copy).
 */
#if defined(_MSC_VER) && _MSC_VER >= 1000
#define HAVE_SETHANDLEINFO 1
#else
#define HAVE_SETHANDLEINFO 0
#endif

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

#define RSHD_VERSION "1.2"
#define RSH_PORT 514
#define FIELD_SIZE 256
#define CMD_SIZE 4096
#define SCRIPT_CMD "sh -s rsh-mcp-1"   /* rsh-mcp asks for this to run its script */
#define SCRIPT_END ") </dev/null 2>&1" /* the script's line right after the command */
#define MARK_SIZE 64
#define LINE_SIZE 1024
#define IO_SIZE 8192
#define STATUS_MS 500       /* console status-window refresh interval */
#define NO_ATTRS ((DWORD)0xFFFFFFFF)
#define IO_SECONDS 60          /* handshake / rcp read timeout */
#define RETRY_SECONDS 10
#define PROBE_SECONDS 3
#define POLL_MS 50
#define STOP_WAIT_MS 5000      /* grace after CTRL_BREAK before TerminateProcess */
#define GRAND_GRACE_MS 3000    /* after cmd exits, wait this for a grandchild's output */
#define NOTE_MS 60000
#define DRAIN_MS 1000          /* graceful close: read client out for up to this */
#define MAX_RUNNING 128
#define LISTEN_BACKLOG 200     /* winsock.h SOMAXCONN is only 5; NT Server honours up to 200 */
#define ACCEPT_FAILS 10
#define CLAIM_WAIT_MS 2000     /* wait this long for another ntrshd to let go of the port */
#define CLOSE_WAIT_MS 2000     /* window closed: give the sessions this long to finish */
#define HOLD_MS 60000          /* a startup error stays on a double-clicked window this long */

/* service identity */
#define SVC_NAME "ntrshd"
#define SVC_DISPLAY "RSH Daemon (ntrshd)"

/* why a command was stopped */
#define STOP_NONE 0
#define STOP_IDLE 1
#define STOP_SIGNAL 2
#define STOP_GONE 3
#define STOP_SHUTDOWN 4

/* the listening port, as the status window shows it */
#define PORT_OPENING 0
#define PORT_LISTENING 1
#define PORT_TAKEN 2           /* another program answers on the port */
#define PORT_FAILED 3          /* bind or listen failed with portError */

typedef struct {
    SOCKET sock;               /* main channel: stdout to client, stdin from client */
    SOCKET errSock;            /* separate stderr channel, or INVALID_SOCKET */
    struct sockaddr_in peer;
    char ip[16];
    int id;
    HANDLE proc;               /* child cmd.exe process */
    DWORD pid;                 /* == process group id (CREATE_NEW_PROCESS_GROUP) */
    HANDLE outPipe;            /* rshd reads child stdout here */
    HANDLE errPipe;            /* rshd reads child stderr here (separate channel), or NULL */
    HANDLE inPipe;             /* rshd writes child stdin here, or NULL */
    HANDLE monitorDone;        /* signalled when the monitor thread has exited */
    int stopWhy;
    int done;                  /* tells the monitor thread to stop */
    int sockWatch;             /* still worth watching sock for input/disconnect */
    int errWatch;              /* still worth watching errSock for a signal byte */
    int started;               /* the status byte was sent; output has begun */
    char last;                 /* last byte sent to the client (for note formatting) */
    DWORD startTick;           /* when the command started, for the status window */
    char cmd[128];             /* the command line, for the status window */
    char marker[MARK_SIZE];    /* rsh-mcp script: the output ends with this and the exit code */
} CONN;

static CRITICAL_SECTION spawnLock;  /* serialises CreateProcess + inheritable handles */
static CRITICAL_SECTION runLock;    /* guards running[] */
static CRITICAL_SECTION portLock;   /* guards nextErrPort */
static CRITICAL_SECTION logLock;    /* guards log output */
static CONN *running[MAX_RUNNING];
static SOCKET listener = INVALID_SOCKET;
static char *comspec;
static int nextErrPort = IPPORT_RESERVED - 1;
static int connCount = 0;
static int statusMode = 0;          /* console shows the live status window */
static int quietFlag = 0;           /* -q: plain scrolling log, no status window */
static DWORD upSince = 0;           /* when serving began, for the uptime line */
static char hostLabel[80] = "";     /* this host's name, for the status header */
static char ipLabel[96] = "";       /* this host's IP address(es), for the header */
static int debugFlag = 0;           /* extra per-event detail */
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

static void logMsg(const char *fmt, ...) {
    char msg[LINE_SIZE];
    SYSTEMTIME now;
    va_list ap;

    va_start(ap, fmt);
    _vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
    va_end(ap);
    msg[sizeof(msg) - 1] = 0;
    GetLocalTime(&now);
    EnterCriticalSection(&logLock);
    if (!asService && !statusMode) {
        printf("%02d:%02d:%02d %s\n", now.wHour, now.wMinute, now.wSecond, msg);
        fflush(stdout);
    }
    if (logFile != NULL) {
        fprintf(logFile, "%04d-%02d-%02d %02d:%02d:%02d %s\n", now.wYear, now.wMonth,
                now.wDay, now.wHour, now.wMinute, now.wSecond, msg);
        fflush(logFile);
    }
    LeaveCriticalSection(&logLock);
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

/* waits at most IO_SECONDS for the client, so a client that stops talking
   cannot hold a connection forever */
static int recvWait(SOCKET s, char *buf, int len) {
    struct timeval tv;
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(s, &fds);
    tv.tv_sec = IO_SECONDS;
    tv.tv_usec = 0;
    if (select(0, &fds, NULL, NULL, &tv) != 1) {
        return -1;
    }
    return recv(s, buf, len, 0);
}

/* reads up to the end character, which is dropped; fails when the connection
   closes or the text does not fit */
static int readUntil(SOCKET s, char *buf, int size, char end) {
    int len;
    char ch;

    len = 0;
    for (;;) {
        if (recvWait(s, &ch, 1) != 1) {
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

    if (recvWait(c->sock, &ch, 1) != 1) {
        return -1;
    }
    if (ch == 0) {
        return 0;
    }
    if (readUntil(c->sock, msg, sizeof(msg), '\n') < 0) {
        msg[0] = 0;
    }
    logMsg("[%d] client error: %s", c->id, msg);
    return ch;
}

/* makes a socket non-inheritable where the platform allows it, so a child
   of one session can never inherit another session's socket */
static void noInheritSock(SOCKET s) {
#if HAVE_SETHANDLEINFO
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
#else
    (void)s;   /* NT 3.1/3.5: handled by the graceful shutdown in closeConn */
#endif
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
    noInheritSock(s);
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

/* sends the FIN with shutdown, then lets the client finish reading before
   closing, so nothing still queued is lost (never an abortive RST) */
static void closeConn(SOCKET s) {
    struct timeval tv;
    fd_set fds;
    char buf[256];
    int i;

    if (s == INVALID_SOCKET) {
        return;
    }
    shutdown(s, 1);   /* SD_SEND: send FIN, keep reading */
    for (i = 0; i < 64; i++) {
        FD_ZERO(&fds);
        FD_SET(s, &fds);
        tv.tv_sec = DRAIN_MS / 1000;
        tv.tv_usec = (DRAIN_MS % 1000) * 1000;
        if (select(0, &fds, NULL, NULL, &tv) != 1) {
            break;
        }
        if (recv(s, buf, sizeof(buf), 0) <= 0) {
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

/* -------- process handle helpers ----------------------------------------- */

/* an inheritable duplicate of h, made only for the moment of CreateProcess */
static HANDLE inheritable(HANDLE h) {
    HANDLE dup;

    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        return NULL;
    }
    return dup;
}

static HANDLE openNul(void) {
    SECURITY_ATTRIBUTES sa;
    HANDLE h;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    h = CreateFile("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                   &sa, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    return h;
}

static void dropHandle(HANDLE h) {
    if (h != NULL) {
        CloseHandle(h);
    }
}

/*
 * Starts "cmd /c command".
 *
 *  - stdout (and stderr, if no separate channel) go to one pipe we read;
 *    a separate stderr channel gets its own pipe.
 *  - stdin is a pipe we write (the client's input), so interactive and BSD
 *    clients work; commands that ignore stdin are unaffected.
 *  - The child gets its own process group (CREATE_NEW_PROCESS_GROUP), so a
 *    Ctrl+C in rshd's window or another session cannot reach it, and rshd
 *    can stop just this command with GenerateConsoleCtrlEvent.
 *  - All pipe ends are created non-inheritable; only the child's three ends
 *    are made inheritable, inside spawnLock, and closed right after, so no
 *    other session's CreateProcess can inherit them.
 */
static BOOL startCommand(CONN *c, char *command) {
    char cmdLine[CMD_SIZE + 32];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE outRead, outWrite;
    HANDLE errRead, errWrite;
    HANDLE inRead, inWrite;
    HANDLE childIn, childOut, childErr;
    BOOL sep;
    BOOL ok;
    DWORD err;

    sep = (c->errSock != INVALID_SOCKET);
    outRead = outWrite = NULL;
    errRead = errWrite = NULL;
    inRead = inWrite = NULL;
    childIn = childOut = childErr = NULL;

    if (!CreatePipe(&outRead, &outWrite, NULL, 0)) {
        return FALSE;
    }
    if (!CreatePipe(&inRead, &inWrite, NULL, 0)) {
        CloseHandle(outRead);
        CloseHandle(outWrite);
        return FALSE;
    }
    if (sep && !CreatePipe(&errRead, &errWrite, NULL, 0)) {
        CloseHandle(outRead);
        CloseHandle(outWrite);
        CloseHandle(inRead);
        CloseHandle(inWrite);
        return FALSE;
    }

    sprintf(cmdLine, "%s /c %s", comspec != NULL ? comspec : "cmd", command);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    EnterCriticalSection(&spawnLock);
    childIn = inheritable(inRead);
    childOut = inheritable(outWrite);
    childErr = sep ? inheritable(errWrite) : inheritable(outWrite);
    if (childIn != NULL && childOut != NULL && childErr != NULL) {
        si.hStdInput = childIn;
        si.hStdOutput = childOut;
        si.hStdError = childErr;
        ok = CreateProcess(comspec, cmdLine, NULL, NULL, TRUE,
                           CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi);
        err = GetLastError();
    } else {
        ok = FALSE;
        err = GetLastError();
    }
    dropHandle(childIn);
    dropHandle(childOut);
    dropHandle(childErr);
    LeaveCriticalSection(&spawnLock);

    /* rshd keeps the read end of stdout/stderr and the write end of stdin */
    CloseHandle(outWrite);
    CloseHandle(inRead);
    if (sep) {
        CloseHandle(errWrite);
    }

    if (!ok) {
        CloseHandle(outRead);
        CloseHandle(inWrite);
        if (sep) {
            CloseHandle(errRead);
        }
        SetLastError(err);
        return FALSE;
    }
    CloseHandle(pi.hThread);
    c->proc = pi.hProcess;
    c->pid = pi.dwProcessId;
    c->outPipe = outRead;
    c->inPipe = inWrite;
    c->errPipe = sep ? errRead : NULL;
    logMsg("[%d] started cmd, process id %lu", c->id, pi.dwProcessId);
    return TRUE;
}

/* -------- running-command table (for shutdown) --------------------------- */

static void addRunning(CONN *c) {
    int i;

    EnterCriticalSection(&runLock);
    for (i = 0; i < MAX_RUNNING; i++) {
        if (running[i] == NULL) {
            running[i] = c;
            break;
        }
    }
    LeaveCriticalSection(&runLock);
}

static void dropRunning(CONN *c) {
    int i;

    EnterCriticalSection(&runLock);
    for (i = 0; i < MAX_RUNNING; i++) {
        if (running[i] == c) {
            running[i] = NULL;
        }
    }
    LeaveCriticalSection(&runLock);
}

/* records why a command should stop; the owning thread escalates it */
static void stopCommand(CONN *c, int why) {
    if (c->stopWhy == STOP_NONE) {
        c->stopWhy = why;
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

/* kills every running command at once; each session thread then ends its
   client as usual (see copyOutput) */
static void killAll(void) {
    CONN *c;
    int i;

    EnterCriticalSection(&runLock);
    for (i = 0; i < MAX_RUNNING; i++) {
        c = running[i];
        if (c != NULL && c->proc != NULL) {
            TerminateProcess(c->proc, CONTROL_C_EXIT);
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
   stop on their own: each one is sent CTRL_BREAK and then hard-killed by its
   own session thread (see stopAll / copyOutput).  A second Ctrl+C makes the
   handler end the process without waiting. */
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
    char msg[LINE_SIZE];

    if (c->errSock != INVALID_SOCKET) {
        sprintf(msg, "rshd: %s\n", text);
        sendAll(c->errSock, msg, strlen(msg));
        return;
    }
    sprintf(msg, "%srshd: %s\n", c->last == '\n' ? "" : "\n", text);
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

/* sends what a pipe holds now: 1 sent something, 0 empty, -1 pipe gone or
   the client is gone */
static int drainPipe(CONN *c, HANDLE pipe, SOCKET dest, DWORD *total) {
    char buf[IO_SIZE];
    DWORD avail;
    DWORD n;

    if (pipe == NULL || dest == INVALID_SOCKET) {
        return 0;
    }
    if (!PeekNamedPipe(pipe, NULL, 0, NULL, &avail, NULL)) {
        return -1;
    }
    if (avail == 0) {
        return 0;
    }
    if (avail > sizeof(buf)) {
        avail = sizeof(buf);
    }
    if (!ReadFile(pipe, buf, avail, &n, NULL) || n == 0) {
        return -1;
    }
    if (!sendAll(dest, buf, (int)n)) {
        stopCommand(c, STOP_GONE);
        return -1;
    }
    *total += n;
    c->last = buf[n - 1];
    return 1;
}

/*
 * Copies all of the command's output to the client, then returns.
 *
 * PeekNamedPipe + a short wait on the process handle delivers every byte
 * with natural backpressure (send blocks when the client reads slowly) and
 * no busy loop.  The pipe reports end-of-file as soon as the child closes
 * its write ends, because rshd closed its own copies right after spawning.
 * A grandchild can keep the pipe open after cmd exits, so once cmd has
 * exited and the pipe has been empty for grandGrace, stop waiting.
 */
static DWORD copyOutput(CONN *c) {
    DWORD total;
    DWORD quiet;
    DWORD noted;
    DWORD emptyAt;
    int exited;
    int so;
    int se;
    int escalated;

    total = 0;
    quiet = GetTickCount();
    noted = quiet;
    emptyAt = 0;
    escalated = 0;
    for (;;) {
        exited = WaitForSingleObject(c->proc, 0) == WAIT_OBJECT_0;
        so = drainPipe(c, c->outPipe, c->sock, &total);
        se = (c->errPipe != NULL) ? drainPipe(c, c->errPipe, c->errSock, &total) : 0;
        if (so > 0 || se > 0) {
            quiet = GetTickCount();
            noted = quiet;
            emptyAt = 0;
            continue;
        }
        if (so < 0) {
            break;   /* stdout pipe reached end-of-file (or client gone) */
        }
        /* nothing available right now */
        if (c->stopWhy != STOP_NONE && !escalated) {
            escalated = 1;
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, c->pid);
            if (WaitForSingleObject(c->proc, STOP_WAIT_MS) != WAIT_OBJECT_0) {
                logMsg("[%d] command did not stop, terminating it", c->id);
                TerminateProcess(c->proc, CONTROL_C_EXIT);
            }
            continue;
        }
        if (exited) {
            if (emptyAt == 0) {
                emptyAt = GetTickCount();
            }
            /* quitting: no point waiting for a grandchild's output */
            if (GetTickCount() - emptyAt >= grandGrace || c->stopWhy == STOP_SHUTDOWN) {
                break;
            }
        } else if (idleLimit != 0 && c->stopWhy == STOP_NONE && GetTickCount() - quiet >= idleLimit) {
            stopCommand(c, STOP_IDLE);
        }
        if (GetTickCount() - noted >= NOTE_MS) {
            noted = GetTickCount();
            logMsg("[%d] still running, no output for %lu seconds", c->id, (noted - quiet) / 1000);
        }
        if (exited) {
            Sleep(POLL_MS);
        } else {
            WaitForSingleObject(c->proc, POLL_MS);
        }
    }
    if (c->stopWhy != STOP_NONE) {
        reportStop(c);
    }
    return total;
}

/* -------- the input / disconnect monitor thread -------------------------- */

/*
 * Reads the main socket while the command runs: bytes become the command's
 * stdin; a graceful close means no more input; a reset means the client is
 * gone, so the command is stopped.  A byte on the stderr channel is a signal
 * (BSD rsh sends one on Ctrl+C) and also stops the command.  The thread ends
 * when told to (c->done) or when the client is gone, and signals monitorDone.
 */
static void __cdecl monitorThread(void *arg) {
    CONN *c;
    char buf[IO_SIZE];
    struct timeval tv;
    fd_set fds;
    int n;
    int watching;

    c = (CONN *)arg;
    while (!c->done) {
        watching = 0;
        FD_ZERO(&fds);
        if (c->sockWatch) {
            FD_SET(c->sock, &fds);
            watching = 1;
        }
        if (c->errWatch && c->errSock != INVALID_SOCKET) {
            FD_SET(c->errSock, &fds);
            watching = 1;
        }
        if (!watching) {
            Sleep(100);
            continue;
        }
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        n = select(0, &fds, NULL, NULL, &tv);
        if (n <= 0) {
            continue;
        }
        if (c->sockWatch && FD_ISSET(c->sock, &fds)) {
            n = recv(c->sock, buf, sizeof(buf), 0);
            if (n > 0) {
                if (c->inPipe != NULL) {
                    DWORD w;
                    if (!WriteFile(c->inPipe, buf, (DWORD)n, &w, NULL)) {
                        c->sockWatch = 0;   /* child stdin is gone */
                    }
                }
            } else if (n == 0) {
                if (c->inPipe != NULL) {
                    CloseHandle(c->inPipe);
                    c->inPipe = NULL;       /* give the command stdin EOF */
                }
                c->sockWatch = 0;           /* client just half-closed; keep serving output */
            } else {
                logMsg("[%d] connection reset by the client", c->id);
                stopCommand(c, STOP_GONE);
                break;
            }
        }
        if (c->errWatch && c->errSock != INVALID_SOCKET && FD_ISSET(c->errSock, &fds)) {
            n = recv(c->errSock, buf, 1, 0);
            if (n == 1) {
                logMsg("[%d] client sent signal %d", c->id, (unsigned char)buf[0]);
                stopCommand(c, STOP_SIGNAL);
                break;
            }
            c->errWatch = 0;                /* stderr channel closed */
        }
    }
    SetEvent(c->monitorDone);
}

/* -------- exec --------------------------------------------------------- */

static void logExit(CONN *c, DWORD total) {
    DWORD code;

    if (WaitForSingleObject(c->proc, 1000) != WAIT_OBJECT_0 || !GetExitCodeProcess(c->proc, &code)) {
        logMsg("[%d] done, %lu bytes sent, cmd still running", c->id, total);
        return;
    }
    if (c->marker[0] != 0) {
        char line[MARK_SIZE + 16];
        sprintf(line, "%s%lu__\n", c->marker, code);
        sendAll(c->sock, line, strlen(line));
    } else if (sendExit) {
        char line[64];
        sprintf(line, "%srshd: exit code %lu\n", c->last == '\n' ? "" : "\n", code);
        sendAll(c->sock, line, strlen(line));
    }
    if (code > 0xFFFF) {
        logMsg("[%d] done, %lu bytes sent, exit code 0x%08lx", c->id, total, code);
    } else {
        logMsg("[%d] done, %lu bytes sent, exit code %lu", c->id, total, code);
    }
}

static void endCommand(CONN *c) {
    if (c->proc == NULL) {
        return;
    }
    dropRunning(c);
    if (c->outPipe != NULL) {
        CloseHandle(c->outPipe);
        c->outPipe = NULL;
    }
    if (c->errPipe != NULL) {
        CloseHandle(c->errPipe);
        c->errPipe = NULL;
    }
    if (c->inPipe != NULL) {
        CloseHandle(c->inPipe);
        c->inPipe = NULL;
    }
    CloseHandle(c->proc);
    c->proc = NULL;
}

/* the command has started: show it in the status window and the quit list */
static void addCommand(CONN *c, char *command) {
    _snprintf(c->cmd, sizeof(c->cmd) - 1, "%s", command);
    c->cmd[sizeof(c->cmd) - 1] = 0;
    c->startTick = GetTickCount();
    addRunning(c);
}

/* the command runs and the client has its status byte: serve it to the end */
static void serveCommand(CONN *c) {
    DWORD total;

    c->monitorDone = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (c->monitorDone == NULL || _beginthread(monitorThread, 0, c) == (unsigned long)-1L) {
        /* no monitor: serve output anyway, without stdin or disconnect-stop */
        logMsg("[%d] cannot start monitor thread, running without it", c->id);
        if (c->monitorDone != NULL) {
            CloseHandle(c->monitorDone);
            c->monitorDone = NULL;
        }
    }

    total = copyOutput(c);

    /* stop the monitor thread and wait for it to really end before freeing */
    c->done = 1;
    if (c->monitorDone != NULL) {
        WaitForSingleObject(c->monitorDone, INFINITE);
        CloseHandle(c->monitorDone);
        c->monitorDone = NULL;
    }
    logExit(c, total);
    endCommand(c);
}

static void doExec(CONN *c, char *command) {
    if (!startCommand(c, command)) {
        sendErr(c, "rshd: cannot start %s, error %lu", comspec != NULL ? comspec : "cmd", GetLastError());
        return;
    }
    addCommand(c, command);
    if (!sendByte(c->sock, 0)) {
        logMsg("[%d] client went away before the output started", c->id);
        stopCommand(c, STOP_GONE);
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, c->pid);
        WaitForSingleObject(c->proc, STOP_WAIT_MS);
        TerminateProcess(c->proc, CONTROL_C_EXIT);
        endCommand(c);
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
   the marker into c->marker; 0 if it does not arrive whole or does not fit */
static int readScript(CONN *c, char *body, int size) {
    char line[CMD_SIZE];
    int used;
    int len;
    int n;

    for (n = 0; ; n++) {
        if (n == 4 || readUntil(c->sock, line, sizeof(line), '\n') < 0) {
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
        if (readUntil(c->sock, line, sizeof(line), '\n') < 0) {
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

    if (!sendByte(c->sock, 0)) {
        logMsg("[%d] client went away before its script came", c->id);
        return;
    }
    c->started = 1;
    if (!readScript(c, body, sizeof(body))) {
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
    if (!startCommand(c, command)) {
        sprintf(text, "cannot start %s, error %lu", comspec != NULL ? comspec : "cmd", GetLastError());
        logMsg("[%d] %s", c->id, text);
        sendNote(c, text);
        return;
    }
    CloseHandle(c->inPipe);   /* the script was the input: the command gets none */
    c->inPipe = NULL;
    addCommand(c, command);
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
        n = recvWait(c->sock, buf, want);
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
        if (readUntil(c->sock, line, sizeof(line), '\n') < 0) {
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
   in a zero byte; the stderr channel is connected before the rest arrives */
static void handleConn(CONN *c) {
    char errPort[FIELD_SIZE];
    char localUser[FIELD_SIZE];
    char remoteUser[FIELD_SIZE];
    char command[CMD_SIZE];
    int port;

    if (readUntil(c->sock, errPort, sizeof(errPort), 0) < 0) {
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
    if (readUntil(c->sock, localUser, sizeof(localUser), 0) < 0 ||
        readUntil(c->sock, remoteUser, sizeof(remoteUser), 0) < 0 ||
        readUntil(c->sock, command, sizeof(command), 0) < 0) {
        sendErr(c, "rshd: bad request");
        return;
    }
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
    }
    if (c->started) {
        logMsg("[%d] %s", c->id, text);
        sendNote(c, text);
        return;
    }
    sendErr(c, "rshd: %s", text);
}

static void __cdecl connThread(void *arg) {
    CONN *c;

    c = (CONN *)arg;
    __try {
        handleConn(c);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        internalError(c, GetExceptionCode());
    }
    endCommand(c);
    c->done = 1;
    if (c->monitorDone != NULL) {
        WaitForSingleObject(c->monitorDone, INFINITE);
        CloseHandle(c->monitorDone);
        c->monitorDone = NULL;
    }
    closeConn(c->errSock);
    closeConn(c->sock);
    logMsg("[%d] connection closed", c->id);
    free(c);
}

static void startConn(SOCKET s, struct sockaddr_in *peer, int id) {
    unsigned char *ip;
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
    setNoDelay(s);
    c->peer = *peer;
    c->id = id;
    c->sockWatch = 1;
    c->last = '\n';
    ip = (unsigned char *)&peer->sin_addr;
    sprintf(c->ip, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    logMsg("[%d] connection from %s port %d", id, c->ip, ntohs(peer->sin_port));
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
    noInheritSock(s);
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
        noInheritSock(s);
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

/* stops accepting and tells every running command to stop; each session
   thread sends CTRL_BREAK, then kills its command after a grace period
   (see copyOutput) */
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
    char path[MAX_PATH];
    char *name;

    if (GetModuleFileName(NULL, path, sizeof(path)) == 0) {
        return;
    }
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
    char binPath[MAX_PATH];
    char image[MAX_PATH + 256];

    if (GetModuleFileName(NULL, myPath, sizeof(myPath)) == 0) {
        printf("cannot find my own path, error %lu\n", GetLastError());
        return;
    }
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
    sprintf(image, "\"%s\"%s", binPath, extra);
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
    char extra[512];
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
                } else {
                    strcat(extra, " ");
                    strcat(extra, argv[x]);
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

    if (!GetCurrentDirectory(sizeof(dir), dir)) {
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
    logMsg("each command runs in its own hidden process group");
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

int main(int argc, char **argv) {
    SERVICE_TABLE_ENTRY dispatch[2];

    InitializeCriticalSection(&spawnLock);
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
