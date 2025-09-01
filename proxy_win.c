// proxy_win.c - Tiny TCP proxy server for Windows
// Ported from the original Linux version with feature parity (except syslog/systemd/daemonize)
// Build:  g++ proxy_win.c -o proxy.exe -lws2_32
// Notes:
//  - -b bind_address (IPv4/IPv6/hostname)
//  - -l local_port
//  - -h remote_host (IPv4/IPv6/hostname)
//  - -p remote_port
//  - -i "input parser"   (remote -> client path)
//  - -o "output parser"  (client -> remote path)
//  - -f foreground (ignored; always foreground on Windows)
//  - -s syslog (ignored)
//
// Example:
//   proxy.exe -b :: -l 8080 -h example.com -p 80
//   proxy.exe -l 9000 -h 127.0.0.1 -p 22 -o "cmd /c some_out_filter" -i "cmd /c some_in_filter"

#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define BUF_SIZE 16384
#define BACKLOG  20

#define TRUE 1
#define FALSE 0 

static SOCKET server_sock = INVALID_SOCKET;
static volatile long g_connection_count = 0;

// cmdline options
static char *bind_addr   = NULL;
static char *remote_host = NULL;
static char *cmd_in      = NULL;
static char *cmd_out     = NULL;
static int   remote_port = 0;
static bool  foreground  = TRUE; // -f ignored
static bool  use_syslog  = FALSE; // ignored

// -------- logging ----------
static void plog(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

// -------- tiny getopt clone for Windows (supports short opts with args) ----------
static int parse_options(int argc, char **argv, int *local_port_out) {
    int local_port = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') continue;
        char opt = argv[i][1];
        char *arg = NULL;
        if (argv[i][2] != '\0') arg = &argv[i][2]; // -l8080
        else if (i + 1 < argc)  arg = argv[++i];    // -l 8080
        // options that don’t take value
        if (opt=='f' || opt=='s') {
            if (opt=='f') foreground = TRUE;
            if (opt=='s') use_syslog = TRUE; // ignored
            if (arg && argv[i][2]=='\0') i--; // step back if we consumed extra
            continue;
        }
        if (!arg) {
            plog("Missing argument for -%c", opt);
            return -1;
        }
        switch (opt) {
        case 'l': local_port = atoi(arg); break;
        case 'b': bind_addr = arg; break;
        case 'h': remote_host = arg; break;
        case 'p': remote_port = atoi(arg); break;
        case 'i': cmd_in = arg; break;
        case 'o': cmd_out = arg; break;
        default:
            plog("Unknown option -%c", opt);
            return -1;
        }
    }
    if (local_port > 0 && remote_host && remote_port > 0) {
        *local_port_out = local_port;
        return 0;
    }
    return -1;
}

// -------- helpers ----------
static int check_ipversion(const char *address) {
    IN6_ADDR dummy6;
    IN_ADDR  dummy4;
    if (InetPtonA(AF_INET, address, &dummy4) == 1)  return AF_INET;
    if (InetPtonA(AF_INET6, address, &dummy6) == 1) return AF_INET6;
    return 0;
}

// Make socket non-inheritable (so child CreateProcess won't inherit by default)
static void set_handle_noinherit(SOCKET s) {
    HANDLE h = (HANDLE)s;
    SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
}

// -------- sockets ----------
static SOCKET create_listen_socket(int port) {
    struct addrinfo hints; ZeroMemory(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_PASSIVE;
    // Prefer IPv6 dual-stack
    hints.ai_family   = AF_INET6;

    char portstr[16]; _snprintf_s(portstr, _TRUNCATE, "%d", port);

    struct addrinfo *res = NULL;
    // If user supplied a bind_addr, pick family accordingly and try numeric shortcut
    int family = AF_UNSPEC, valid = 0;
    if (bind_addr && (valid = check_ipversion(bind_addr))) {
        family = valid;
        hints.ai_family = family;
        hints.ai_flags |= AI_NUMERICHOST;
    }
    if (getaddrinfo(bind_addr, portstr, &hints, &res) != 0) {
        // Try fallback with AF_UNSPEC
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags    = AI_PASSIVE;
        hints.ai_family   = AF_UNSPEC;
        if (getaddrinfo(bind_addr, portstr, &hints, &res) != 0) {
            plog("getaddrinfo(bind) failed");
            return INVALID_SOCKET;
        }
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        plog("socket() failed: %d", WSAGetLastError());
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    // Reuse address
    BOOL opt = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    // If IPv6, allow dual-stack (accept IPv4-mapped) when binding to ::
    if (res->ai_family == AF_INET6) {
        DWORD off = 0; // 0 = dual-stack enabled
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(off));
    }

    if (bind(s, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        plog("bind() failed: %d", WSAGetLastError());
        closesocket(s);
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    if (listen(s, BACKLOG) == SOCKET_ERROR) {
        plog("listen() failed: %d", WSAGetLastError());
        closesocket(s);
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    freeaddrinfo(res);
    set_handle_noinherit(s);
    return s;
}

static SOCKET create_connection() {
    struct addrinfo hints; ZeroMemory(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family   = AF_UNSPEC;

    char portstr[16]; _snprintf_s(portstr, _TRUNCATE, "%d", remote_port);

    // numeric shortcut
    int valid = check_ipversion(remote_host);
    if (valid) {
        hints.ai_family = valid;
        hints.ai_flags  |= AI_NUMERICHOST;
    }

    struct addrinfo *res = NULL;
    if (getaddrinfo(remote_host, portstr, &hints, &res) != 0) {
        plog("getaddrinfo(remote) failed");
        WSASetLastError(WSAEFAULT);
        return INVALID_SOCKET;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        plog("socket(remote) failed: %d", WSAGetLastError());
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        plog("connect() failed: %d", WSAGetLastError());
        closesocket(s);
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    freeaddrinfo(res);
    set_handle_noinherit(s);
    return s;
}

// -------- external command pump ----------
typedef struct {
    SOCKET src_sock;
    SOCKET dst_sock;
    const char* cmd; // may be NULL -> raw forward
    // internal for child process
    HANDLE hChild = NULL;
    HANDLE hStdinWr = NULL;  // parent writes -> child's stdin
    HANDLE hStdoutRd = NULL; // parent reads  <- child's stdout
} filter_ctx;

// Create child process with redirected stdin/stdout for filter
static BOOL start_filter_process(filter_ctx* ctx) {
    SECURITY_ATTRIBUTES sa; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE; sa.lpSecurityDescriptor = NULL;

    HANDLE hStdinRd = NULL,  hStdoutWr = NULL;
    // stdin pipe (parent write, child read)
    if (!CreatePipe(&hStdinRd, &ctx->hStdinWr, &sa, 0)) {
        plog("CreatePipe(stdin) failed: %lu", GetLastError()); return FALSE;
    }
    // stdout pipe (child write, parent read)
    if (!CreatePipe(&ctx->hStdoutRd, &hStdoutWr, &sa, 0)) {
        plog("CreatePipe(stdout) failed: %lu", GetLastError());
        CloseHandle(hStdinRd); CloseHandle(ctx->hStdinWr); return FALSE;
    }
    // make parent ends non-inheritable
    SetHandleInformation(ctx->hStdinWr, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(ctx->hStdoutRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput  = hStdinRd;
    si.hStdOutput = hStdoutWr;
    si.hStdError  = hStdoutWr; // merge stderr to stdout

    // Create child; allow shell commands. Use cmd.exe /c "..." to match Linux system(cmd) behavior.
    char cmdline[4096];
    _snprintf_s(cmdline, _TRUNCATE, "cmd /c %s", ctx->cmd);

    BOOL ok = CreateProcessA(
        NULL, cmdline, NULL, NULL, TRUE,
        CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi);

    // Close child-sides in parent
    CloseHandle(hStdinRd);
    CloseHandle(hStdoutWr);

    if (!ok) {
        plog("CreateProcess failed: %lu", GetLastError());
        CloseHandle(ctx->hStdinWr);
        CloseHandle(ctx->hStdoutRd);
        return FALSE;
    }

    // keep handles
    ctx->hChild = pi.hProcess;
    CloseHandle(pi.hThread);
    return TRUE;
}

// Non-blocking read from child stdout if any, to avoid deadlock
static DWORD read_child_stdout_if_any(HANDLE h, char* buf, DWORD bufsz) {
    DWORD avail = 0;
    if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL)) return 0;
    if (avail == 0) return 0;
    DWORD toread = (avail > bufsz ? bufsz : avail);
    DWORD n = 0;
    if (!ReadFile(h, buf, toread, &n, NULL)) return 0;
    return n;
}

// -------- data forwarding threads ----------
typedef struct {
    SOCKET src;
    SOCKET dst;
} forward_args;

typedef struct {
    filter_ctx fctx;
    BOOL use_filter;
} forward_ext_args;

// raw forward: src -> dst
static unsigned __stdcall forward_thread(void* arg) {
    forward_args* a = (forward_args*)arg;
    char buf[BUF_SIZE];
    int n;
    while ((n = recv(a->src, buf, sizeof(buf), 0)) > 0) {
        int off = 0;
        while (off < n) {
            int m = send(a->dst, buf + off, n - off, 0);
            if (m <= 0) goto done;
            off += m;
        }
    }
done:
    shutdown(a->dst, SD_BOTH);
    closesocket(a->dst);
    shutdown(a->src, SD_BOTH);
    closesocket(a->src);
    free(a);
    return 0;
}

// filtered forward via external command: src -> filter(cmd) -> dst
static unsigned __stdcall forward_ext_thread(void* arg) {
    forward_ext_args* a = (forward_ext_args*)arg;
    filter_ctx* ctx = &a->fctx;
    char buf[BUF_SIZE];

    if (ctx->cmd && !start_filter_process(ctx)) {
        // fallback to raw if filter fails to spawn
        forward_args* raw = (forward_args*)malloc(sizeof(forward_args));
        raw->src = ctx->src_sock; raw->dst = ctx->dst_sock;
        free(a);
        return forward_thread(raw);
    }

    // Loop: recv from socket -> write to child's stdin; read any available stdout -> send to dst
    for (;;) {
        int n = recv(ctx->src_sock, buf, sizeof(buf), 0);
        if (n <= 0) break;

        // write to child stdin (write all)
        DWORD off = 0;
        while (off < (DWORD)n) {
            DWORD w = 0;
            if (!WriteFile(ctx->hStdinWr, buf + off, n - off, &w, NULL)) { n = -1; break; }
            off += w;
        }

        // pump child stdout without blocking
        for (;;) {
            DWORD r = read_child_stdout_if_any(ctx->hStdoutRd, buf, sizeof(buf));
            if (r == 0) break;
            DWORD off2 = 0;
            while (off2 < r) {
                int m = send(ctx->dst_sock, buf + off2, r - off2, 0);
                if (m <= 0) { n = -1; break; }
                off2 += m;
            }
            if (n < 0) break;
        }
        if (n < 0) break;
    }

    // Close child's stdin to signal EOF
    if (ctx->hStdinWr) { CloseHandle(ctx->hStdinWr); ctx->hStdinWr = NULL; }

    // Drain remaining stdout
    for (;;) {
        DWORD r = read_child_stdout_if_any(ctx->hStdoutRd, buf, sizeof(buf));
        if (r == 0) break;
        DWORD off2 = 0;
        while (off2 < r) {
            int m = send(ctx->dst_sock, buf + off2, r - off2, 0);
            if (m <= 0) break;
            off2 += m;
        }
    }

    if (ctx->hStdoutRd) { CloseHandle(ctx->hStdoutRd); ctx->hStdoutRd = NULL; }
    if (ctx->hChild)    { WaitForSingleObject(ctx->hChild, 5000); CloseHandle(ctx->hChild); ctx->hChild = NULL; }

    shutdown(ctx->dst_sock, SD_BOTH); closesocket(ctx->dst_sock);
    shutdown(ctx->src_sock, SD_BOTH); closesocket(ctx->src_sock);

    free(a);
    return 0;
}

static void handle_client(SOCKET client_sock) {
    SOCKET remote_sock = create_connection();
    if (remote_sock == INVALID_SOCKET) {
        plog("Cannot connect to remote");
        closesocket(client_sock);
        return;
    }

    // client -> remote (optional cmd_out)
    if (cmd_out) {
        forward_ext_args* fe1 = (forward_ext_args*)malloc(sizeof(forward_ext_args));
        ZeroMemory(fe1, sizeof(*fe1));
        fe1->use_filter = TRUE;
        fe1->fctx.src_sock = client_sock;
        fe1->fctx.dst_sock = remote_sock;
        fe1->fctx.cmd = cmd_out;
        _beginthreadex(NULL, 0, &forward_ext_thread, fe1, 0, NULL);
    } else {
        forward_args* a1 = (forward_args*)malloc(sizeof(forward_args));
        a1->src = client_sock; a1->dst = remote_sock;
        _beginthreadex(NULL, 0, &forward_thread, a1, 0, NULL);
    }

    // remote -> client (optional cmd_in)
    if (cmd_in) {
        forward_ext_args* fe2 = (forward_ext_args*)malloc(sizeof(forward_ext_args));
        ZeroMemory(fe2, sizeof(*fe2));
        fe2->use_filter = TRUE;
        fe2->fctx.src_sock = remote_sock;
        fe2->fctx.dst_sock = client_sock;
        fe2->fctx.cmd = cmd_in;
        _beginthreadex(NULL, 0, &forward_ext_thread, fe2, 0, NULL);
    } else {
        forward_args* a2 = (forward_args*)malloc(sizeof(forward_args));
        a2->src = remote_sock; a2->dst = client_sock;
        _beginthreadex(NULL, 0, &forward_thread, a2, 0, NULL);
    }
}

// -------- Ctrl+C handler for graceful shutdown ----------
static BOOL WINAPI console_ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        if (server_sock != INVALID_SOCKET) closesocket(server_sock);
        WSACleanup();
        ExitProcess(0);
    }
    return FALSE;
}

// -------- main loop ----------
int main(int argc, char **argv) {
    int local_port = 0;

    if (parse_options(argc, argv, &local_port) != 0) {
        fprintf(stderr,
            "Syntax: %s [-b bind_address] -l local_port -h remote_host -p remote_port "
            "[-i \"input parser\"] [-o \"output parser\"] [-f] [-s]\n", argv[0]);
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        plog("WSAStartup failed");
        return 1;
    }

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    server_sock = create_listen_socket(local_port);
    if (server_sock == INVALID_SOCKET) {
        plog("Cannot start server");
        WSACleanup();
        return 1;
    }

    printf("Proxy listening on %s%s:%d  ->  %s:%d\n",
        (bind_addr ? "" : "(any)"),
        (bind_addr ? bind_addr : ""),
        local_port, remote_host, remote_port);

    for (;;) {
        struct sockaddr_storage client_addr; int addrlen = sizeof(client_addr);
        SOCKET client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        if (client_sock == INVALID_SOCKET) {
            int e = WSAGetLastError();
            if (e == WSAEINTR) continue;
            plog("accept failed: %d", e);
            break;
        }
        set_handle_noinherit(client_sock);
        InterlockedIncrement(&g_connection_count);
        handle_client(client_sock);
        // note: handle_client spawns threads and returns immediately
    }

    closesocket(server_sock);
    WSACleanup();
    return 0;
}
