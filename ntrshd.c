#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define RSH_PORT 514
#define BUFFER_SIZE 8192
#define MAX_CMD_SIZE 4096

/* Console colors */
#define CONSOLE_PURPLE (FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define CONSOLE_DEFAULT (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

/* Structure to pass client data to thread */
typedef struct {
    SOCKET clientSocket;
    char clientHost[64];
} CLIENT_DATA;

/* Function prototypes */
SOCKET initializeServer();
DWORD WINAPI handleClient(LPVOID lpParam);
BOOL executeCommand(const char* command, SOCKET clientSocket, const char* remoteUser, const char* clientHost);
BOOL parseRshProtocol(char* buffer, int bytesReceived, char* localUser, char* remoteUser, char* command);
BOOL createProcessWithPipes(const char* command, HANDLE* hReadPipe, HANDLE* hWritePipe, PROCESS_INFORMATION* pi);
BOOL sendOutputToClient(SOCKET clientSocket, char* buffer, DWORD bytesRead);
void readRemainingOutput(HANDLE hReadPipe, SOCKET clientSocket);
void logMessage(const char* format, ...);
void setWindowTitle(const char* title);
void setIdleTitle();
void setRunningTitle(const char* remoteUser, const char* clientHost, const char* command);
void setConsoleColor(WORD color);
void resetConsoleColor();

/* Global variables for logging */
CRITICAL_SECTION logCriticalSection;
HANDLE hConsole;
WORD defaultConsoleColor;

/* Global variables for tracking active processes */
CRITICAL_SECTION processCountCriticalSection;
int activeProcessCount = 0;

/* Helper function to initialize server socket */
SOCKET initializeServer() {
    WSADATA wsaData;
    SOCKET listenSocket;
    struct sockaddr_in serverAddr;
    int result;
    
    /* Initialize Winsock */
    result = WSAStartup(MAKEWORD(1, 1), &wsaData);
    if (result != 0) {
        logMessage("WSAStartup failed: %d\n", result);
        return INVALID_SOCKET;
    }
    
    /* Create socket */
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == INVALID_SOCKET) {
        logMessage("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return INVALID_SOCKET;
    }
    
    /* Bind to port */
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(RSH_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    
    result = bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        logMessage("Bind failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }
    
    /* Listen for connections */
    result = listen(listenSocket, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        logMessage("Listen failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }
    
    return listenSocket;
}

/* Main entry point */
int main(int argc, char* argv[]) {
    SOCKET listenSocket;
    SOCKET clientSocket;
    struct sockaddr_in clientAddr;
    int clientAddrLen;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    
    /* Initialize console handle and get default color */
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        defaultConsoleColor = csbi.wAttributes;
    } else {
        defaultConsoleColor = CONSOLE_DEFAULT;
    }
    
    /* Initialize critical sections */
    InitializeCriticalSection(&logCriticalSection);
    InitializeCriticalSection(&processCountCriticalSection);
    
    /* Initialize server */
    listenSocket = initializeServer();
    if (listenSocket == INVALID_SOCKET) {
        DeleteCriticalSection(&logCriticalSection);
        DeleteCriticalSection(&processCountCriticalSection);
        return 1;
    }
    
    logMessage("NTRSHD listening on port %d...\n", RSH_PORT);
    
    /* Set idle window title */
    setIdleTitle();
    
    /* Accept connections loop */
    while (1) {
        CLIENT_DATA* clientData;
        
        clientAddrLen = sizeof(clientAddr);
        clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket == INVALID_SOCKET) {
            logMessage("Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        logMessage("Connection from %s:%d\n", 
                   inet_ntoa(clientAddr.sin_addr), 
                   ntohs(clientAddr.sin_port));
        
        /* Allocate client data structure */
        clientData = (CLIENT_DATA*)malloc(sizeof(CLIENT_DATA));
        if (clientData) {
            clientData->clientSocket = clientSocket;
            strcpy(clientData->clientHost, inet_ntoa(clientAddr.sin_addr));
            
            /* Handle client in a new thread */
            CreateThread(NULL, 0, handleClient, (LPVOID)clientData, 0, NULL);
        } else {
            logMessage("Memory allocation failed for client data\n");
            closesocket(clientSocket);
        }
    }
    
    /* Cleanup (never reached in this implementation) */
    closesocket(listenSocket);
    WSACleanup();
    DeleteCriticalSection(&logCriticalSection);
    DeleteCriticalSection(&processCountCriticalSection);
    
    return 0;
}

/* Parse RSH protocol fields */
BOOL parseRshProtocol(char* buffer, int bytesReceived, char* localUser, char* remoteUser, char* command) {
    int offset;
    int i;
    int fieldIndex;
    char* fields[3];
    
    /* Check initial null byte */
    if (buffer[0] != 0) {
        logMessage("Invalid RSH protocol: missing initial null byte\n");
        return FALSE;
    }
    
    /* Setup field pointers */
    fields[0] = localUser;
    fields[1] = remoteUser;
    fields[2] = command;
    
    /* Parse the three fields separated by null bytes */
    offset = 1;
    fieldIndex = 0;
    
    for (i = 1; i < bytesReceived && fieldIndex < 3; i++) {
        if (buffer[i] != 0) continue;
        
        /* Found null byte - copy field */
        if (fieldIndex >= 3) break;
        
        strncpy(fields[fieldIndex], buffer + offset, i - offset);
        fields[fieldIndex][i - offset] = '\0';
        fieldIndex++;
        offset = i + 1;
    }
    
    /* Verify we got all fields */
    if (fieldIndex < 3) {
        logMessage("Invalid RSH protocol: incomplete fields\n");
        return FALSE;
    }
    
    return TRUE;
}

/* Handle client connection */
DWORD WINAPI handleClient(LPVOID lpParam) {
    CLIENT_DATA* clientData = (CLIENT_DATA*)lpParam;
    SOCKET clientSocket = clientData->clientSocket;
    char* clientHost = clientData->clientHost;
    char buffer[BUFFER_SIZE];
    char localUser[256];
    char remoteUser[256];
    char command[MAX_CMD_SIZE];
    int bytesReceived;
    
    /* Initialize buffers */
    memset(buffer, 0, sizeof(buffer));
    memset(localUser, 0, sizeof(localUser));
    memset(remoteUser, 0, sizeof(remoteUser));
    memset(command, 0, sizeof(command));
    
    /* Receive data from client */
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived <= 0) {
        logMessage("Error receiving data: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        free(clientData);
        return 1;
    }
    
    /* Parse RSH protocol */
    if (!parseRshProtocol(buffer, bytesReceived, localUser, remoteUser, command)) {
        closesocket(clientSocket);
        free(clientData);
        return 1;
    }
    
    /* Log command with current directory */
    {
        char currentDir[256];
        if (!GetCurrentDirectory(sizeof(currentDir), currentDir)) {
            strcpy(currentDir, "Unknown");
        }
        logMessage("Command: %s [%s]\n", command, currentDir);
    }
    
    /* Increment active process count */
    EnterCriticalSection(&processCountCriticalSection);
    activeProcessCount++;
    LeaveCriticalSection(&processCountCriticalSection);
    
    /* Execute the command */
    executeCommand(command, clientSocket, remoteUser, clientHost);
    
    /* Decrement active process count */
    EnterCriticalSection(&processCountCriticalSection);
    activeProcessCount--;
    LeaveCriticalSection(&processCountCriticalSection);
    
    /* Close connection */
    closesocket(clientSocket);
    
    /* Update title based on remaining processes */
    setIdleTitle();
    
    /* Free client data */
    free(clientData);
    
    return 0;
}

/* Helper function to create pipes and process */
BOOL createProcessWithPipes(const char* command, HANDLE* hReadPipe, HANDLE* hWritePipe, PROCESS_INFORMATION* pi) {
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    char* cmdLine;
    int cmdLineLen;
    BOOL result;
    
    /* Allocate command line buffer */
    cmdLineLen = strlen(command) + 20;
    cmdLine = (char*)malloc(cmdLineLen);
    if (!cmdLine) {
        logMessage("Memory allocation failed\n");
        return FALSE;
    }
    
    /* Create pipe for stdout redirection */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    if (!CreatePipe(hReadPipe, hWritePipe, &sa, 0)) {
        logMessage("CreatePipe failed: %d\n", GetLastError());
        free(cmdLine);
        return FALSE;
    }
    
    /* Ensure read handle is not inherited */
    SetHandleInformation(*hReadPipe, HANDLE_FLAG_INHERIT, 0);
    
    /* Setup startup info */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = *hWritePipe;
    si.hStdError = *hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    /* Build command line - check if already using cmd */
    if (strncmp(command, "cmd", 3) == 0 || strncmp(command, "CMD", 3) == 0) {
        strcpy(cmdLine, command);
    } else {
        sprintf(cmdLine, "cmd.exe /c %s", command);
    }
    
    /* Create process */
    memset(pi, 0, sizeof(PROCESS_INFORMATION));
    result = CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, pi);
    
    free(cmdLine);
    
    if (!result) {
        logMessage("CreateProcess failed: %d\n", GetLastError());
        CloseHandle(*hReadPipe);
        CloseHandle(*hWritePipe);
        return FALSE;
    }
    
    /* Close write end of pipe in parent */
    CloseHandle(*hWritePipe);
    return TRUE;
}

/* Helper function to send output to client and log */
BOOL sendOutputToClient(SOCKET clientSocket, char* buffer, DWORD bytesRead) {
    /* Send to client first */
    if (send(clientSocket, buffer, bytesRead, 0) == SOCKET_ERROR) {
        logMessage("Send failed: %d\n", WSAGetLastError());
        return FALSE;
    }
    
    /* Log to console with default color (with truncation for safety) */
    EnterCriticalSection(&logCriticalSection);
    resetConsoleColor();
    buffer[bytesRead] = '\0';
    if (bytesRead > 900) {
        buffer[900] = '\0';
        printf("%s...\n", buffer);
    } else {
        printf("%s", buffer);
    }
    fflush(stdout);
    LeaveCriticalSection(&logCriticalSection);
    return TRUE;
}

/* Read remaining output from pipe */
void readRemainingOutput(HANDLE hReadPipe, SOCKET clientSocket) {
    char readBuffer[BUFFER_SIZE];
    DWORD bytesRead;
    
    while (ReadFile(hReadPipe, readBuffer, sizeof(readBuffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        if (!sendOutputToClient(clientSocket, readBuffer, bytesRead)) {
            break;
        }
    }
}

/* Execute command and send output to client */
BOOL executeCommand(const char* command, SOCKET clientSocket, const char* remoteUser, const char* clientHost) {
    HANDLE hReadPipe;
    HANDLE hWritePipe;
    PROCESS_INFORMATION pi;
    char readBuffer[BUFFER_SIZE];
    DWORD bytesRead;
    DWORD bytesAvailable;
    BOOL result;
    
    /* Set running window title */
    setRunningTitle(remoteUser, clientHost, command);
    
    /* Create process with pipes */
    if (!createProcessWithPipes(command, &hReadPipe, &hWritePipe, &pi)) {
        return FALSE;
    }
    
    /* Read output and send to client */
    while (1) {
        /* Check if data is available */
        if (!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &bytesAvailable, NULL)) {
            break;
        }
        
        if (bytesAvailable == 0) {
            /* No data available - check if process is still running */
            if (WaitForSingleObject(pi.hProcess, 10) != WAIT_TIMEOUT) {
                /* Process has ended, read any remaining data */
                readRemainingOutput(hReadPipe, clientSocket);
                break;
            }
            continue;
        }
        
        /* Data is available - read it */
        result = ReadFile(hReadPipe, readBuffer, sizeof(readBuffer) - 1, &bytesRead, NULL);
        if (!result || bytesRead == 0) {
            break;
        }
        
        /* Send output to client and log */
        if (!sendOutputToClient(clientSocket, readBuffer, bytesRead)) {
            break;
        }
    }
    
    /* Cleanup */
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    /* Log completion */
    logMessage("Done\n");
    
    return TRUE;
}

/* Thread-safe logging function */
void logMessage(const char* format, ...) {
    va_list args;
    char buffer[1024];
    int len;
    
    /* Format the message safely */
    va_start(args, format);
    len = _vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    va_end(args);
    
    /* Ensure null termination */
    if (len < 0 || len >= sizeof(buffer) - 1) {
        buffer[sizeof(buffer) - 1] = '\0';
    }
    
    /* Thread-safe console output with purple color */
    EnterCriticalSection(&logCriticalSection);
    setConsoleColor(CONSOLE_PURPLE);
    printf("%s", buffer);
    resetConsoleColor();
    fflush(stdout);
    LeaveCriticalSection(&logCriticalSection);
}

/* Set window title */
void setWindowTitle(const char* title) {
    SetConsoleTitle(title);
}

/* Set idle window title */
void setIdleTitle() {
    char titleBuffer[512];
    char currentDir[256];
    
    /* Get current working directory */
    if (!GetCurrentDirectory(sizeof(currentDir), currentDir)) {
        strcpy(currentDir, "Unknown");
    }
    
    EnterCriticalSection(&processCountCriticalSection);
    if (activeProcessCount > 0) {
        sprintf(titleBuffer, "NTRSHD [%d RUNNING] Listening on Port 514 [%s]", activeProcessCount, currentDir);
        setWindowTitle(titleBuffer);
    } else {
        sprintf(titleBuffer, "NTRSHD [IDLE] Listening on Port 514 [%s]", currentDir);
        setWindowTitle(titleBuffer);
    }
    LeaveCriticalSection(&processCountCriticalSection);
}

/* Set running window title with command truncation */
void setRunningTitle(const char* remoteUser, const char* clientHost, const char* command) {
    char titleBuffer[256];
    char truncatedCommand[21];
    int commandLen;
    int currentCount;
    
    /* Get current process count */
    EnterCriticalSection(&processCountCriticalSection);
    currentCount = activeProcessCount;
    LeaveCriticalSection(&processCountCriticalSection);
    
    /* Truncate command to 20 characters */
    commandLen = strlen(command);
    if (commandLen > 20) {
        strncpy(truncatedCommand, command, 20);
        truncatedCommand[20] = '\0';
    } else {
        strcpy(truncatedCommand, command);
    }
    
    /* Format title */
    sprintf(titleBuffer, "NTRSHD [%d RUNNING] %s@%s: %s", currentCount, remoteUser, clientHost, truncatedCommand);
    setWindowTitle(titleBuffer);
}

/* Set console color */
void setConsoleColor(WORD color) {
    SetConsoleTextAttribute(hConsole, color);
}

/* Reset console color to default */
void resetConsoleColor() {
    SetConsoleTextAttribute(hConsole, defaultConsoleColor);
}
