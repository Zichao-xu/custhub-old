#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

char g_dir[PATHLEN];

#ifdef _WIN32
#define SEP "\\"
#else
#define SEP "/"
#endif

void cr_init_dir(void)
{
    const char *e = getenv("CUSTHUB_D");                  /* 仅供测试 */
    if (e && *e && strlen(e) < PATHLEN - 64) { strcpy(g_dir, e); return; }
#ifdef _WIN32
    const char *pd = getenv("ProgramData");
    snprintf(g_dir, PATHLEN, "%s\\cust-remote", pd && strlen(pd) < 200 ? pd : "C:\\ProgramData");
#else
    strcpy(g_dir, plat_is_dir("/Library/CustRemote") ? "/Library/CustRemote" : "/opt/cust-remote");
#endif
}

void pjoin(char *out, const char *name)
{
    snprintf(out, PATHLEN, "%s" SEP "%s", g_dir, name);
}

void cr_log(const char *file, const char *fmt, ...)
{
    char p[PATHLEN], msg[MAXLINE], ts[32];
    va_list ap;
    va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    time_t t = time(NULL); struct tm *tm = localtime(&t);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", tm);
    pjoin(p, file);
    FILE *f = fopen(p, "ab");
    if (f) {
        if (ftell(f) > 1024 * 1024) {                      /* 日志超 1MB 从头来 */
            fclose(f); f = fopen(p, "wb");
        }
        if (f) { fprintf(f, "%s %s\n", ts, msg); fclose(f); }
    }
}

long read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    int more = fgetc(f) != EOF;
    fclose(f);
    if (more) return -2;
    buf[n] = 0;
    return (long)n;
}

int write_file(const char *path, const char *data, size_t len)
{
    char tmp[PATHLEN + 16];
    snprintf(tmp, sizeof tmp, "%s.cr-new", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    int ok = fwrite(data, 1, len, f) == len;
    ok = (fflush(f) == 0) && ok;
    ok = (fclose(f) == 0) && ok;
    if (!ok || plat_replace(tmp, path) != 0) { remove(tmp); return -1; }
    return 0;
}

static int b64v(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* 跳过空白; 遇到 '=' 结束; 其他非法字符拒 */
long b64_decode(const char *in, size_t inlen, uint8_t *out, size_t cap)
{
    uint32_t acc = 0; int bits = 0; size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        int c = (unsigned char)in[i];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c == '=') break;
        int v = b64v(c);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v; bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return (long)o;
}

char *next_line(char **cur)
{
    char *s = *cur;
    if (!s || !*s) return NULL;
    char *e = strchr(s, '\n');
    if (e) { *e = 0; *cur = e + 1; } else *cur = s + strlen(s);
    size_t n = strlen(s);
    if (n && s[n - 1] == '\r') s[n - 1] = 0;
    return s;
}

int sb_add(char *buf, size_t cap, size_t *len, const char *s)
{
    size_t n = strlen(s);
    if (*len + n + 1 > cap) return -1;
    memcpy(buf + *len, s, n + 1);
    *len += n;
    return 0;
}

int valid_b64_key(const char *s)
{
    size_t n = strlen(s);
    if (n < 68 || n > 70) return 0;
    for (size_t i = 0; i < n; i++)
        if (b64v((unsigned char)s[i]) < 0 && !(s[i] == '=' && i >= 68)) return 0;
    return 1;
}

int pub_from_b64(const char *b64, uint8_t pub[32])
{
    uint8_t w[64];
    long n = b64_decode(b64, strlen(b64), w, sizeof w);
    /* string "ssh-ed25519" + string(32) = 4+11+4+32 */
    if (n != 51) return -1;
    if (memcmp(w, "\0\0\0\x0bssh-ed25519\0\0\0\x20", 19) != 0) return -1;
    memcpy(pub, w + 19, 32);
    return 0;
}

int find_ed25519(const char *line, char *b64, size_t cap)
{
    const char *p = strstr(line, "ssh-ed25519 ");
    if (!p) return -1;
    p += 12;
    size_t n = 0;
    while (p[n] && b64v((unsigned char)p[n]) >= 0) n++;
    while (p[n] == '=') n++;
    if (n == 0 || n >= cap) return -1;
    memcpy(b64, p, n); b64[n] = 0;
    return 0;
}

int valid_host(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 63) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == ':' || c == '-')) return 0;
    }
    return s[0] != '-';                                    /* 不让主机名被 ssh 当成选项 */
}

int all_digits(const char *s, size_t maxlen)
{
    size_t n = strlen(s);
    if (n == 0 || n > maxlen) return 0;
    for (size_t i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}

/* client.conf: 安装时写; 缺的项按本机情况猜 */
int conf_load(conf_t *c)
{
    char p[PATHLEN], buf[4096];
    memset(c, 0, sizeof *c);
    pjoin(p, "client.conf");
    if (read_file(p, buf, sizeof buf) >= 0) {
        char *cur = buf, *l;
        while ((l = next_line(&cur))) {
            char *v = strchr(l, ' ');
            if (!v || l[0] == '#') continue;
            *v++ = 0;
            if (!strcmp(l, "port") && all_digits(v, 5)) strcpy(c->port, v);
            else if (!strcmp(l, "sshport") && all_digits(v, 5)) strcpy(c->sshport, v);
            else if (!strcmp(l, "ssh") && strlen(v) < PATHLEN) strcpy(c->ssh, v);
            else if (!strcmp(l, "key") && strlen(v) < PATHLEN) strcpy(c->key, v);
            else if (!strcmp(l, "http_port") && all_digits(v, 5)) strcpy(c->http_port, v);
        }
    }
    pjoin(p, "ak");
    c->dropbear = plat_is_dir(p);                          /* OpenWrt: dropbear 读 $D/ak/authorized_keys */
    if (!c->http_port[0]) strcpy(c->http_port, "8443");
    if (!c->sshport[0]) {                                  /* OpenWrt 安装时记在 sshport */
        pjoin(p, "sshport");
        long n = read_file(p, buf, 16);
        if (n > 0) { buf[strcspn(buf, "\r\n")] = 0; if (all_digits(buf, 5)) strcpy(c->sshport, buf); }
        if (!c->sshport[0]) strcpy(c->sshport, "22");
    }
    if (!c->ssh[0]) {
        if (c->dropbear) strcpy(c->ssh, "dbclient");
        else plat_default_ssh(c->ssh, sizeof c->ssh);
    }
    if (strstr(c->ssh, "dbclient")) c->dropbear = 1;
    if (!c->key[0]) {
        pjoin(c->key, "tun_ed25519");
        if (!plat_is_file(c->key)) pjoin(c->key, "tun_key");
    }
    return 0;
}
