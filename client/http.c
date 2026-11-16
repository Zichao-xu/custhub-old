/* 最小 HTTP/1.0 客户端: 工程师登录(POST)和下载发布物(GET)
 * 只走中转的 http 端口; 完整性靠签名清单里的哈希, 不靠传输 */
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define BADSOCK INVALID_SOCKET
#define closesock closesocket
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
typedef int sock_t;
#define BADSOCK (-1)
#define closesock close
#endif

void http_init(void)
{
#ifdef _WIN32
    static int done;
    if (!done) { WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd); done = 1; }
#endif
}

static sock_t dial(const char *host, const char *port, int timeout_s)
{
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    http_init();
    if (getaddrinfo(host, port, &hints, &res)) return BADSOCK;
    sock_t s = BADSOCK;
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BADSOCK) continue;
#ifdef _WIN32
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
#else
        fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
#endif
        connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        fd_set ws; FD_ZERO(&ws); FD_SET(s, &ws);
        struct timeval tv = { timeout_s, 0 };
        int err = 1; socklen_t el = sizeof err;
        if (select((int)s + 1, NULL, &ws, NULL, &tv) == 1 &&
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &el) == 0 && err == 0) {
#ifdef _WIN32
            nb = 0; ioctlsocket(s, FIONBIO, &nb);
            DWORD to = (DWORD)timeout_s * 1000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
#else
            fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
            struct timeval rt = { timeout_s, 0 };
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rt, sizeof rt);
#endif
            break;
        }
        closesock(s); s = BADSOCK;
    }
    freeaddrinfo(res);
    return s;
}

static int send_all(sock_t s, const char *b, size_t n)
{
    while (n) {
        int k = send(s, b, (int)n, 0);
        if (k <= 0) return -1;
        b += k; n -= (size_t)k;
    }
    return 0;
}

/* 读响应头, 返回状态码; *body 指向头之后已读到的部分, *blen 其长度 */
static int read_head(sock_t s, char *buf, size_t cap, char **body, size_t *blen)
{
    size_t got = 0;
    char *e = NULL;
    while (!e && got < cap - 1) {
        int k = recv(s, buf + got, (int)(cap - 1 - got), 0);
        if (k <= 0) break;
        got += (size_t)k; buf[got] = 0;
        e = strstr(buf, "\r\n\r\n");
    }
    if (!e) return -1;
    int st = 0;
    if (sscanf(buf, "HTTP/%*s %d", &st) != 1) return -1;
    *body = e + 4; *blen = got - (size_t)(e + 4 - buf);
    return st;
}

int http_post(const char *host, const char *port, const char *path, const char *payload, char *out, size_t cap)
{
    char req[2048], buf[8192], *body; size_t bl;
    int n = snprintf(req, sizeof req,
        "POST %s HTTP/1.0\r\nHost: %s:%s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        path, host, port, (int)strlen(payload), payload);
    if (n <= 0 || n >= (int)sizeof req) return -1;
    sock_t s = dial(host, port, 10);
    if (s == BADSOCK) return -1;
    if (send_all(s, req, (size_t)n)) { closesock(s); return -1; }
    int st = read_head(s, buf, sizeof buf, &body, &bl);
    if (st > 0) {
        size_t o = bl < cap - 1 ? bl : cap - 1;
        memmove(out, body, o);
        while (o < cap - 1) {
            int k = recv(s, out + o, (int)(cap - 1 - o), 0);
            if (k <= 0) break;
            o += (size_t)k;
        }
        out[o] = 0;
    }
    closesock(s);
    return st;
}

/* GET 到内存(补 NUL); 返回状态码 */
int http_get_text(const char *host, const char *port, const char *path, char *out, size_t cap)
{
    char req[2048], buf[8192], *body; size_t bl;
    int n = snprintf(req, sizeof req, "GET %s HTTP/1.0\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", path, host, port);
    if (n <= 0 || n >= (int)sizeof req) return -1;
    sock_t s = dial(host, port, 10);
    if (s == BADSOCK) return -1;
    if (send_all(s, req, (size_t)n)) { closesock(s); return -1; }
    int st = read_head(s, buf, sizeof buf, &body, &bl);
    size_t o = 0;
    if (st > 0 && out && cap) {
        o = bl < cap - 1 ? bl : cap - 1;
        memmove(out, body, o);
        while (o < cap - 1) {
            int k = recv(s, out + o, (int)(cap - 1 - o), 0);
            if (k <= 0) break;
            o += (size_t)k;
        }
        out[o] = 0;
    }
    closesock(s);
    return st;
}

/* GET 到文件; 超过 maxsize 即放弃; 返回状态码, 200 时 *size 为写入字节数 */
int http_get_file(const char *host, const char *port, const char *path, const char *dst, long maxsize, long *size)
{
    char req[1024], buf[8192], *body; size_t bl;
    int n = snprintf(req, sizeof req, "GET %s HTTP/1.0\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", path, host, port);
    if (n <= 0 || n >= (int)sizeof req) return -1;
    sock_t s = dial(host, port, 15);
    if (s == BADSOCK) return -1;
    if (send_all(s, req, (size_t)n)) { closesock(s); return -1; }
    int st = read_head(s, buf, sizeof buf, &body, &bl);
    if (st != 200) { closesock(s); return st; }
    FILE *f = fopen(dst, "wb");
    if (!f) { closesock(s); return -1; }
    long tot = 0; int bad = 0;
    if (bl) { tot = (long)bl; bad = fwrite(body, 1, bl, f) != bl; }
    while (!bad && tot <= maxsize) {
        int k = recv(s, buf, sizeof buf, 0);
        if (k < 0) { bad = 1; break; }
        if (k == 0) break;
        tot += k;
        if (fwrite(buf, 1, (size_t)k, f) != (size_t)k) bad = 1;
    }
    closesock(s);
    if (fclose(f) || bad || tot > maxsize) { remove(dst); return -1; }
    *size = tot;
    return 200;
}
