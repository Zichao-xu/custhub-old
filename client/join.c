/* 接入(custhub join) · 公共部分 + macOS / Linux / OpenWrt 流程; Windows 流程在 join_win.c
 * 取代 client*.sh.tpl / client.ps1.tpl / uninstall*.tpl: 一行命令只负责下载本程序, 其余都在这里
 *
 * 接入清单(管理端渲染, 中转 /j/TOKEN.join 下发; 里面没有长期秘密, 只有本次接入的一次性回报钥匙):
 *   custhub-join v1
 *   base http://中转:端口        token 本次令牌        tunport 回拨口      silent 0|1      keep_tun 0|1
 *   pubkey ssh-ed25519 AAAA… cust-remote               管理钥匙(过渡期; 信任清单生效后由它接手)
 *   repkey <base64 私钥>                                 进度回报 ssh 备用通道的一次性钥匙
 *   hub 地址 端口 ssh-ed25519 主机公钥                    每台中转一行
 *   pkg 键 文件名 sha512                                 本次可能要下载的安装包(Windows 的 OpenSSH、壁纸等)
 *   cleanup <base64>                                    Windows「清理弹窗广告」脚本(③ 换成 C 之前的过渡)
 * 进度: GET base/cgi-bin/report?t=&s=&m=[&u=&h=]; 失败日志 POST 同地址; HTTP 不通走 ssh custrep@中转 log|fail */
#include "cr.h"
#include "plat.h"
#include "join.h"
#include "vendor/monocypher.h"
#include "vendor/monocypher-ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifndef _WIN32
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <strings.h>
#endif

job_t J;
static int rch;                                          /* 回报走哪条: 0 未定 1 http 2 ssh */
static char rhub[96];                                    /* ssh 回报上次成功的中转 "地址 端口" */

/* ---------------- 输出与回报 ---------------- */

void say(const char *fmt, ...)
{
    char b[2048];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    out("%s\n", b);
    cr_log("join.log", "%s", b);
}

static void urlenc(const char *s, char *o, size_t cap)
{
    static const char hx[] = "0123456789ABCDEF";
    size_t k = 0;
    for (; *s && k + 4 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') o[k++] = (char)c;
        else { o[k++] = '%'; o[k++] = hx[c >> 4]; o[k++] = hx[c & 15]; }
    }
    o[k] = 0;
}

static void rep_ssh_init(void)
{
    char p[PATHLEN], kh[PATHLEN];
    pjoin(p, "rep_key");
    if (!J.repkey[0] || plat_is_file(p)) return;
    static uint8_t key[4096];
    long n = b64_decode(J.repkey, strlen(J.repkey), key, sizeof key);
    if (n <= 0) return;
    write_file(p, (char *)key, (size_t)n);
    plat_secure_key(p);
    static char khb[8192], hb[8192]; size_t kl = 0; khb[0] = 0;
    char line[300], *cur = hb, *l;
    snprintf(hb, sizeof hb, "%s", J.hubs);
    while ((l = next_line(&cur))) {
        char h[128], port[16], t[32], k[128];
        if (sscanf(l, "%127s %15s %31s %127s", h, port, t, k) != 4) continue;
        if (!strcmp(port, "22")) snprintf(line, sizeof line, "%s %s %s\n", h, t, k);
        else snprintf(line, sizeof line, "[%s]:%s %s %s\n", h, port, t, k);
        sb_add(khb, sizeof khb, &kl, line);
    }
    pjoin(kh, "rep_known");
    write_file(kh, khb, kl);
}

static int rep_ssh(const char *mode, const char *body)
{
    if (!J.repkey[0]) return -1;
    char ssh[PATHLEN];
    plat_default_ssh(ssh, sizeof ssh);
    if (strstr(ssh, "dbclient") || (!plat_is_file(ssh) && strchr(ssh, '\\'))) return -1;
    rep_ssh_init();
    char k[PATHLEN], kh[PATHLEN], kho[PATHLEN + 32];
    pjoin(k, "rep_key"); pjoin(kh, "rep_known");
    snprintf(kho, sizeof kho, "UserKnownHostsFile=%s", kh);
    static char hb[8192];
    snprintf(hb, sizeof hb, "%s%s\n%s", rhub[0] ? rhub : "", rhub[0] ? " x x" : "", J.hubs);
    char *cur = hb, *l;
    while ((l = next_line(&cur))) {
        char h[128], port[16], dest[160];
        if (sscanf(l, "%127s %15s", h, port) != 2 || !valid_host(h) || !all_digits(port, 5)) continue;
        snprintf(dest, sizeof dest, "custrep@%s", h);
        const char *av[] = { ssh, "-i", k, "-o", "IdentitiesOnly=yes", "-o", kho, "-o", "StrictHostKeyChecking=yes",
                             "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR", "-p", port, dest, mode, NULL };
        if (plat_run_in(av, body, strlen(body), NULL, 0, 30) == 0) { snprintf(rhub, sizeof rhub, "%s %s", h, port); return 0; }
    }
    return -1;
}

void rep(const char *s, const char *m, const char *extra, int tries, const char *uh)
{
    char q[1600], em[1200];
    urlenc(m, em, sizeof em);
    snprintf(q, sizeof q, "/cgi-bin/report?t=%s&s=%s&m=%s%s", J.token, s, em, extra ? extra : "");
    if (rch != 2) {
        for (int i = 0; i < tries; i++) {               /* 通道刚起来那一两秒网卡在变, 单次请求可能失败 */
            if (http_get_text(J.host, J.port, q, NULL, 0) == 200) { rch = 1; return; }
            if (i + 1 < tries) plat_sleep(1);
        }
    }
    char body[1400];
    snprintf(body, sizeof body, "%s\t%s\t%s\n", s, m, uh ? uh : "");
    for (char *c = body + strlen(s) + 1; *c && *c != '\n'; c++) if (*c == '\r') *c = ' ';
    if (rep_ssh("log", body) == 0) { rch = 2; return; }
    rch = 0;
}

void ok(const char *s, const char *fmt, ...)
{
    char m[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(m, sizeof m, fmt, ap); va_end(ap);
    say("  √ %s", m);
    rep(s, m, NULL, 2, NULL);
}

void doing(const char *fmt, ...)
{
    char m[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(m, sizeof m, fmt, ap); va_end(ap);
    say("  … %s", m);
    rep("doing", m, NULL, 1, NULL);                       /* 开始前也报, 卡住能知道断在哪 */
}

void warn(const char *fmt, ...)
{
    char m[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(m, sizeof m, fmt, ap); va_end(ap);
    say("  ! %s", m);
    rep("warn", m, NULL, 2, NULL);
}

static const char *hint(const char *m)
{
    if (strstr(m, "校验")) return "安装包校验不符(下载被篡改或不完整), 重试一次";
    if (strstr(m, "SHA-2")) return "这台 Win7 缺 SHA-2 系统补丁, 装上补丁重启后再运行";
    if (strstr(m, "SP1")) return "这台 Win7 没装 SP1, 需要先装 SP1";
    if (strstr(m, "ARM")) return "暂不支持 ARM 版 Windows";
    if (strstr(m, "1618")) return "系统里有别的程序正在安装, 等它装完再运行";
    if (strstr(m, "1603") || strstr(m, "1625") || strstr(m, "拒绝")) return "安装被阻止, 多半是杀毒软件(360/火绒)拦截, 放行后重试";
    if (strstr(m, "下载") || strstr(m, "连不上")) return "连不上我们的服务器, 检查客户网络后重试";
    if (strstr(m, "远程登录") && J.os == OS_MAC) return "系统设置 → 通用 → 共享 → 打开「远程登录」后重试";
    if (strstr(m, "sshd")) return "SSH 服务没起来, 把窗口截图发给我们";
    return "把这个窗口截图发给我们";
}

/* 失败: 先传日志尾(+现场)再报 fail, 管理端收到 fail 时日志已就位 */
void jfail(const char *fmt, ...)
{
    char m[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(m, sizeof m, fmt, ap); va_end(ap);
    const char *h = hint(m);
    say(""); say("  × 失败: %s", m); say("    建议: %s", h);
    static char log[MAXBUF], body[MAXBUF + 8192];
    char p[PATHLEN];
    pjoin(p, "join.log");
    long n = read_file(p, log, sizeof log);
    const char *tail = n > 0 ? log + (n > 12000 ? n - 12000 : 0) : "";
    static char dg[8192]; dg[0] = 0;
    join_diag(dg, sizeof dg);
    snprintf(body, sizeof body, "%s\n----\n%s\n---- 现场 ----\n%s", m, tail, dg);
    int sent = 0;
    if (rch != 2) {
        char q[256], resp[64];
        snprintf(q, sizeof q, "/cgi-bin/report?t=%s", J.token);
        sent = http_post(J.host, J.port, q, body, resp, sizeof resp) == 200;
    }
    if (!sent) rep_ssh("fail", body);
    char fm[1200];
    snprintf(fm, sizeof fm, "%s | %s", m, h);
    rep("fail", fm, NULL, 2, NULL);
    join_finish(0);
    exit(1);
}

/* ---------------- 清单 ---------------- */

static int fetch_job(const char *url)
{
    /* url = http://地址:端口/j/令牌 */
    if (strncmp(url, "http://", 7)) return -1;
    const char *h = url + 7, *sl = strchr(h, '/'), *co = strchr(h, ':');
    if (!sl || !co || co > sl || co - h >= (long)sizeof J.host || sl - co - 1 >= (long)sizeof J.port) return -1;
    memcpy(J.host, h, (size_t)(co - h)); J.host[co - h] = 0;
    memcpy(J.port, co + 1, (size_t)(sl - co - 1)); J.port[sl - co - 1] = 0;
    if (!valid_host(J.host) || !all_digits(J.port, 5) || strncmp(sl, "/j/", 3) || strlen(sl + 3) >= sizeof J.token) return -1;
    char path[160]; static char buf[MAXBUF];
    snprintf(path, sizeof path, "%s.join", sl);
    int st = 0;
    for (int i = 0; i < 3 && st != 200; i++) { st = http_get_text(J.host, J.port, path, buf, sizeof buf); if (st != 200) plat_sleep(2); }
    if (st != 200) return -2;
    char *cur = buf, *l;
    l = next_line(&cur);
    if (!l || strcmp(l, "custhub-join v1")) return -3;
    size_t hl = 0;
    while ((l = next_line(&cur))) {
        char *v = strchr(l, ' ');
        if (!v) continue;
        *v++ = 0;
        if (!strcmp(l, "token") && strlen(v) < sizeof J.token) strcpy(J.token, v);
        else if (!strcmp(l, "tunport") && all_digits(v, 5)) strcpy(J.tunport, v);
        else if (!strcmp(l, "silent")) J.silent = atoi(v);
        else if (!strcmp(l, "keep_tun")) J.keep_tun = atoi(v);
        else if (!strcmp(l, "pubkey") && strlen(v) < sizeof J.pubkey && !strncmp(v, "ssh-ed25519 ", 12)) strcpy(J.pubkey, v);
        else if (!strcmp(l, "repkey") && strlen(v) < sizeof J.repkey) strcpy(J.repkey, v);
        else if (!strcmp(l, "cleanup") && strlen(v) < sizeof J.cleanup) strcpy(J.cleanup, v);
        else if (!strcmp(l, "hub")) { sb_add(J.hubs, sizeof J.hubs, &hl, v); sb_add(J.hubs, sizeof J.hubs, &hl, "\n"); }
        else if (!strcmp(l, "pkg") && J.npkg < MAXPKG) {
            pkg_t *p = &J.pkg[J.npkg];
            if (sscanf(v, "%47s %159s %128s", p->key, p->file, p->sha) == 3 && strlen(p->sha) == 128 && !strstr(p->file, "..")) J.npkg++;
        }
    }
    if (!J.token[0] || !J.tunport[0] || !J.pubkey[0] || !J.hubs[0]) return -3;
    return 0;
}

static int hex2(const char *s, uint8_t *o, size_t n)
{
    for (size_t i = 0; i < n; i++) { unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1; o[i] = (uint8_t)v; }
    return 0;
}

static int sha_ok(const char *path, const char *hex)
{
    uint8_t want[64], h[64];
    if (hex2(hex, want, 64)) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    crypto_sha512_ctx c; crypto_sha512_init(&c);
    uint8_t b[16384]; size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0) crypto_sha512_update(&c, b, n);
    fclose(f);
    crypto_sha512_final(&c, h);
    return crypto_verify64(h, want) == 0;
}

static int get_file(const char *rel, const char *dst, const char *sha)
{
    if (plat_is_file(dst) && sha_ok(dst, sha)) return 0;
    char url[400]; long got;
    snprintf(url, sizeof url, "/pkg/%s", rel);
    int st = http_get_file(J.host, J.port, url, dst, 512L * 1024 * 1024, &got);
    if (st != 200) jfail("下载 %s 失败(%d)", rel, st);
    if (!sha_ok(dst, sha)) { remove(dst); jfail("%s 校验不符", rel); }
    return 0;
}

/* 安装包: 普通文件直接取; 以 / 结尾的目录包先取 manifest.sha512(指纹在清单里), 再按它逐个取、逐个核对 */
const char *get_pkg(const char *key, char *out, size_t cap)
{
    pkg_t *p = NULL;
    for (int i = 0; i < J.npkg; i++) if (!strcmp(J.pkg[i].key, key)) p = &J.pkg[i];
    if (!p) jfail("接入清单里没有安装包 %s", key);
    size_t fl = strlen(p->file);
    if (p->file[fl - 1] != '/') {
        const char *base = strrchr(p->file, '/'); base = base ? base + 1 : p->file;
        pjoin(out, base);
        doing("下载 %s", p->file);
        get_file(p->file, out, p->sha);
        return out;
    }
    char dir[PATHLEN], man[PATHLEN], rel[400];
    snprintf(rel, sizeof rel, "%.*s", (int)(fl - 1), p->file);
    const char *base = strrchr(rel, '/'); base = base ? base + 1 : rel;
    pjoin(dir, base);
    plat_mkdir(dir);
    doing("下载 %s", p->file);
    snprintf(man, sizeof man, "%s%cmanifest.sha512", dir, SEPC);
    snprintf(rel, sizeof rel, "%smanifest.sha512", p->file);
    get_file(rel, man, p->sha);
    static char mb[65536];
    if (read_file(man, mb, sizeof mb) < 0) jfail("读不了 %s", man);
    char *cur = mb, *l;
    while ((l = next_line(&cur))) {
        char h[160], f[200], dst[PATHLEN];
        if (sscanf(l, "%159s %199s", h, f) != 2 || strstr(f, "..") || strlen(h) != 128) continue;
        snprintf(rel, sizeof rel, "%s%s", p->file, f);
        snprintf(dst, sizeof dst, "%s%c%s", dir, SEPC, f);
        for (char *c = dst + strlen(dir) + 1; *c; c++) if (*c == '/' || *c == '\\') { *c = 0; plat_mkdir(dst); *c = SEPC; }
        get_file(rel, dst, h);
    }
    snprintf(out, cap, "%s", dir);
    return out;
}

/* ---------------- 共同步骤 ---------------- */

void st_set(const char *k, const char *v)            /* 安装前状态只在第一次记 */
{
    char p[PATHLEN], buf[8192], key[96];
    pjoin(p, "state.txt");
    long n = read_file(p, buf, sizeof buf);
    if (n < 0) { n = 0; buf[0] = 0; }
    snprintf(key, sizeof key, "%s=", k);
    if (!strncmp(buf, key, strlen(key))) return;
    char nk[100]; snprintf(nk, sizeof nk, "\n%s", key);
    if (strstr(buf, nk)) return;
    if ((size_t)n + strlen(k) + strlen(v) + 4 >= sizeof buf) return;
    if (n && buf[n - 1] != '\n') buf[n++] = '\n';
    n += snprintf(buf + n, sizeof buf - (size_t)n, "%s=%s\n", k, v);
    write_file(p, buf, (size_t)n);
}

int st_get(const char *k, char *v, size_t cap)
{
    char p[PATHLEN], buf[8192], key[96];
    pjoin(p, "state.txt");
    if (read_file(p, buf, sizeof buf) < 0) return -1;
    snprintf(key, sizeof key, "%s=", k);
    char *cur = buf, *l;
    while ((l = next_line(&cur))) if (!strncmp(l, key, strlen(key))) { snprintf(v, cap, "%s", l + strlen(key)); return 0; }
    return -1;
}

/* 通道: hubs.txt + client.conf + 程序装进安装目录; 钥匙由平台流程先生成好 */
void write_tunnel_files(const char *ssh_path)
{
    char p[PATHLEN], conf[PATHLEN + 64];
    pjoin(p, "hubs.txt");
    if (write_file(p, J.hubs, strlen(J.hubs))) jfail("写不了 %s", p);
    int n = snprintf(conf, sizeof conf, "port %s\n", J.tunport);
    if (ssh_path && ssh_path[0]) snprintf(conf + n, sizeof conf - (size_t)n, "ssh %s\n", ssh_path);
    pjoin(p, "client.conf");
    if (write_file(p, conf, strlen(conf))) jfail("写不了 %s", p);
    if (install_copy_self()) jfail("程序装不进 %s", g_dir);
    pjoin(p, "tun-status.txt");
    remove(p);
}

void report_tunkey(const char *pubkey_line)
{
    char kb[160]; uint8_t pub[32];
    if (find_ed25519(pubkey_line, kb, sizeof kb) || pub_from_b64(kb, pub)) jfail("读不出通道公钥");
    char line[200], b[300];
    snprintf(line, sizeof line, "ssh-ed25519 %s", kb);
    /* 管理端按 base64 收(旧脚本的约定) */
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = strlen(line), o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned char)line[i] << 16 | (i + 1 < n ? (unsigned char)line[i + 1] << 8 : 0) | (i + 2 < n ? (unsigned char)line[i + 2] : 0);
        b[o++] = t[v >> 18 & 63]; b[o++] = t[v >> 12 & 63];
        b[o++] = i + 1 < n ? t[v >> 6 & 63] : '='; b[o++] = i + 2 < n ? t[v & 63] : '=';
    }
    b[o] = 0;
    rep("tunkey", b, NULL, 3, NULL);
}

/* 接入成功后: 被本程序取代的旧脚本/旧名二进制删掉(安装包缓存留着, 重装时省下载) */
void legacy_cleanup(void)
{
#ifdef _WIN32
    const char *f[] = { "cust-remote.exe", "cust-remote.old.exe", "cust-remote.new.exe", "cust-remote.bad.exe", "tun.ps1", "tun.ps1.bak",
                        "trust-apply.ps1", "engineer.ps1", "watchdog.ps1", "restart-tun.ps1", "kick.out", "kick.err", "move.ps1", "join.owner", NULL };
#else
    const char *f[] = { "cust-remote", "cust-remote.old", "cust-remote.new", "cust-remote.bad", "tun.sh", "tun.sh.bak",
                        "trust-apply.sh", "engineer.sh", "tun.err", NULL };
#endif
    char p[PATHLEN];
    for (int i = 0; f[i]; i++) { pjoin(p, f[i]); remove(p); }
    pjoin(p, "tun.d");
    if (plat_is_dir(p)) plat_rmtmp(p);
    pjoin(p, "svc.bak"); remove(p);                       /* 成功了, 回滚用的备份不再需要 */
#ifndef _WIN32
    /* 管理端「移除客户」仍按旧路径调 uninstall.sh: 留个转发到本程序的壳 */
    char sh[PATHLEN + 64];
    pjoin(p, "uninstall.sh");
    snprintf(sh, sizeof sh, "#!/bin/sh\nexec %s/custhub remove \"$@\"\n", g_dir);
    write_file(p, sh, strlen(sh));
    chmod(p, 0755);
#endif
}

int wait_link(int secs)
{
    char p[PATHLEN], buf[4096];
    pjoin(p, "tun-status.txt");
    for (int i = 0; i < secs; i += 2) {
        plat_sleep(2);
        if (read_file(p, buf, sizeof buf) > 0 && !strncmp(buf, "# custhub ", 10) && (strstr(buf, " up\n") || strstr(buf, " up\r\n"))) return 1;
    }
    return 0;
}

/* 等新守护连通; 连不上且原来有旧守护 → 恢复旧守护再报失败(机器不能因接入而失联, 11-16 c-8) */
void link_or_rollback(int secs)
{
    if (wait_link(secs)) return;
    if (!service_had_prior()) jfail("%d 秒内反向通道没连通", secs);
    doing("新守护 %d 秒内没连上, 恢复旧守护", secs);
    service_restore();
    char p[PATHLEN], buf[4096];
    pjoin(p, "tun-status.txt");
    for (int i = 0; i < 60; i += 2) {                     /* 旧守护的状态没有标识行, 有 up 就算回来了 */
        plat_sleep(2);
        if (read_file(p, buf, sizeof buf) > 0 && strncmp(buf, "# custhub ", 10) && strstr(buf, " up")) {
            jfail("新守护 %d 秒内没连上, 已恢复旧守护(通道已回来, 机器没有失联)", secs);
        }
    }
    jfail("新守护没连上, 已恢复旧守护, 但 60 秒内旧守护也没连上");
}

void report_done(const char *user, const char *host)
{
    char eu[200], eh[200], ex[480], uh[300];
    urlenc(user, eu, sizeof eu); urlenc(host, eh, sizeof eh);
    snprintf(ex, sizeof ex, "&u=%s&h=%s", eu, eh);
    snprintf(uh, sizeof uh, "%s %s", user, host);
    rep("done", "ok", ex, 8, uh);
    char k[PATHLEN]; pjoin(k, "rep_key"); remove(k);       /* 一次性钥匙用完即删(中转那边接入结束也会撤销) */
}

int cmd_join(int argc, char **argv)
{
    if (argc < 2) { out("用法: custhub join http://中转:端口/j/令牌\n"); return 2; }
    memset(&J, 0, sizeof J);
    int r = fetch_job(argv[1]);
    if (r) {
        out(r == -2 ? "取不到接入清单(命令过期了? 找我们要一条新的)\n" : "接入地址或清单无效\n");
        return 1;
    }
    snprintf(J.url, sizeof J.url, "%s", argv[1]);
    return join_platform(argc, argv);
}

/* ======================================================================= */
#ifndef _WIN32

static int run(const char *cmd)                          /* 只用于固定的系统命令行(无外来输入拼接) */
{
    const char *av[] = { "/bin/sh", "-c", cmd, NULL };
    return plat_run(av, NULL, 0, 60);
}

static int runo(const char *cmd, char *o, size_t cap)
{
    const char *av[] = { "/bin/sh", "-c", cmd, NULL };
    return plat_run(av, o, cap, 60);
}

static int port_open(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int r = connect(s, (struct sockaddr *)&a, sizeof a) == 0;
    close(s);
    return r;
}

static int wait_port(int port, int secs)
{
    for (int i = 0; i < secs; i++) { if (port_open(port)) return 1; plat_sleep(1); }
    return port_open(port);
}

static int has_cmd(const char *c)
{
    char cmd[160]; snprintf(cmd, sizeof cmd, "command -v %s >/dev/null 2>&1", c);
    return run(cmd) == 0;
}

/* authorized_keys: 去掉含 cust-remote 的旧行, 加我们的; open=1 不带 from= */
static void addkey(const char *home, const char *owner, int open)
{
    char d[PATHLEN], f[PATHLEN];
    static char buf[MAXBUF], nw[MAXBUF];
    snprintf(d, sizeof d, "%s/.ssh", home);
    snprintf(f, sizeof f, "%s/authorized_keys", d);
    mkdir(d, 0700);
    size_t l = 0; nw[0] = 0;
    if (read_file(f, buf, sizeof buf) >= 0) {
        char *cur = buf, *ln;
        while ((ln = next_line(&cur))) if (*ln && !strstr(ln, "cust-remote")) { sb_add(nw, sizeof nw, &l, ln); sb_add(nw, sizeof nw, &l, "\n"); }
    }
    if (!open) sb_add(nw, sizeof nw, &l, "from=\"127.0.0.1,::1\" ");
    sb_add(nw, sizeof nw, &l, J.pubkey); sb_add(nw, sizeof nw, &l, "\n");
    FILE *o = fopen(f, "w");                              /* 原地写: 保留属主, 免得 sshd 的 StrictModes 不认 */
    if (!o || fwrite(nw, 1, l, o) != l) { if (o) fclose(o); jfail("写不了 %s", f); }
    fclose(o);
    chmod(d, 0700); chmod(f, 0600);
    struct passwd *pw = getpwnam(owner);
    if (pw) { if (chown(d, pw->pw_uid, pw->pw_gid) || chown(f, pw->pw_uid, pw->pw_gid)) {} }
}

static void strip_key(const char *f)                      /* 卸载: 删掉我们的行(旧管理钥匙 cust-remote + 信任清单写的 custhub-trust:) */
{
    static char buf[MAXBUF], nw[MAXBUF];
    if (read_file(f, buf, sizeof buf) < 0) return;
    size_t l = 0; nw[0] = 0;
    char *cur = buf, *ln;
    while ((ln = next_line(&cur))) if (*ln && !strstr(ln, "cust-remote") && !strstr(ln, "custhub-trust:")) { sb_add(nw, sizeof nw, &l, ln); sb_add(nw, sizeof nw, &l, "\n"); }
    FILE *o = fopen(f, "w");
    if (o) { fwrite(nw, 1, l, o); fclose(o); }
}

static void keygen_openssh(char *publine, size_t cap)
{
    char k[PATHLEN], pub[PATHLEN];
    pjoin(k, "tun_ed25519");
    snprintf(pub, sizeof pub, "%s.pub", k);
    if (!plat_is_file(k)) {
        const char *av[] = { "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "cust-tun", "-f", k, NULL };
        if (plat_run(av, NULL, 0, 30) != 0) jfail("生成反向通道密钥失败");
    }
    chmod(k, 0600);
    if (read_file(pub, publine, cap) < 0) jfail("生成反向通道密钥失败");
}

static void user_of(char *u, size_t cap, char *home, size_t hcap)
{
    const char *e = getenv("CUST_USER");
    if (!e || !*e) e = getenv("SUDO_USER");
    char sv[96];
    if ((!e || !*e) && st_get("user", sv, sizeof sv) == 0) e = sv;
    if ((!e || !*e) && J.os == OS_MAC) {
        struct stat s;
        if (stat("/dev/console", &s) == 0) { struct passwd *pw = getpwuid(s.st_uid); if (pw) e = pw->pw_name; }
    }
    if (!e || !*e) e = "root";
    snprintf(u, cap, "%s", e);
    struct passwd *pw = getpwnam(u);
    if (!pw || !pw->pw_dir || !plat_is_dir(pw->pw_dir)) jfail("账号 %s 没有家目录, 装不了钥匙", u);
    snprintf(home, hcap, "%s", pw->pw_dir);
}

static void hostname_of(char *h, size_t cap)
{
    char b[256] = "";
    if (J.os == OS_MAC && runo("scutil --get LocalHostName", b, sizeof b) == 0) {}
    else if (read_file("/proc/sys/kernel/hostname", b, sizeof b) < 0) gethostname(b, sizeof b);
    b[strcspn(b, "\r\n")] = 0;
    snprintf(h, cap, "%s", b);
}

void join_diag(char *o, size_t cap)
{
    char b[4096] = ""; size_t l = strlen(o);
    if (J.os == OS_MAC) runo("echo '-- launchd'; launchctl print system/com.custremote.tun 2>&1 | grep -E 'state|runs|last exit|pid'; "
                             "echo '-- default'; netstat -rn -f inet 2>&1 | grep -E '^default' | head -3; "
                             "echo '-- proxy apps'; ps -axo comm | grep -iE 'clash|surge|mihomo|v2ray|xray|sing-box|tailscale|wireguard|vpn' | sort -u", b, sizeof b);
    else if (J.os == OS_LINUX) runo("echo '-- systemctl'; systemctl status cust-remote-tun --no-pager 2>&1 | head -12", b, sizeof b);
    else runo("echo '-- procd'; /etc/init.d/cust-remote-tun status 2>&1; ps w | grep '[d]bclient'", b, sizeof b);
    sb_add(o, cap, &l, b);
    char p[PATHLEN], t[2048];
    pjoin(p, "tun-status.txt");
    if (read_file(p, t, sizeof t) > 0) { sb_add(o, cap, &l, "-- tun-status\n"); sb_add(o, cap, &l, t); }
    pjoin(p, "tun.log");
    if (read_file(p, t, sizeof t) > 0) { sb_add(o, cap, &l, "-- tun.log\n"); sb_add(o, cap, &l, t); }
}

void join_finish(int okk) { (void)okk; }

/* ---------------- macOS ---------------- */

static int launchd_on(const char *svc)
{
    char cmd[200];
    snprintf(cmd, sizeof cmd, "launchctl print-disabled system | grep -qE '\"%s\" => (enabled|false)'", svc);
    return run(cmd) == 0;
}

static void mac_grp(const char *grp, const char *u)     /* 「仅限这些用户」时把账户加进访问组; 记下是我们加的 */
{
    char cmd[300];
    snprintf(cmd, sizeof cmd, "dscl . -read /Groups/%s >/dev/null 2>&1", grp);
    if (run(cmd)) return;
    snprintf(cmd, sizeof cmd, "dseditgroup -o checkmember -m '%s' %s >/dev/null 2>&1", u, grp);
    if (!run(cmd)) return;
    snprintf(cmd, sizeof cmd, "dseditgroup -o edit -a '%s' -t user %s", u, grp);
    if (!run(cmd)) { char k[80]; snprintf(k, sizeof k, "grp_%s", grp); st_set(k, u); }
}

static void quitterm(void)                                /* 输完密码就让 Terminal 消失(只剩我们这个窗口时) */
{
    char b[8192];
    if (run("pgrep -x Terminal >/dev/null")) return;
    plat_sleep(1);
    if (runo("ps -axo tty=,command=", b, sizeof b)) return;
    char *cur = b, *l;
    while ((l = next_line(&cur))) {
        char tty[32], cmd[64];
        if (sscanf(l, "%31s %63s", tty, cmd) == 2 && strcmp(tty, "??") && !strcmp(cmd, "login")) return;
    }
    run("pkill -x Terminal");
}

static int join_mac(void)
{
    char u[96], uh[PATHLEN], line[512];
    if (!J.keep_tun) quitterm();
    say("==== 远程维护接入 ====");
    char ver[64] = "", arch[32] = "";
    runo("sw_vers -productVersion", ver, sizeof ver); runo("uname -m", arch, sizeof arch);
    ver[strcspn(ver, "\n")] = 0; arch[strcspn(arch, "\n")] = 0;
    snprintf(line, sizeof line, "macOS %s %s", ver, arch);
    rep("start", line, NULL, 2, NULL);
    user_of(u, sizeof u, uh, sizeof uh);
    if (!strcmp(u, "root")) jfail("认不出当前登录用户");
    st_set("user", u);

    /* 旧版留下的 WireGuard 通道 */
    if (plat_is_file("/Library/LaunchDaemons/com.custremote.wg.plist") || plat_is_file("/Library/LaunchDaemons/com.custremote.watch.plist")) {
        run("for x in wg watch; do launchctl bootout system/com.custremote.$x 2>/dev/null; rm -f /Library/LaunchDaemons/com.custremote.$x.plist; done; "
            "pkill -f /Library/CustRemote/bin/wireguard-go 2>/dev/null; "
            "[ -f /Library/CustRemote/ep.route ] && route -n delete -host \"$(cat /Library/CustRemote/ep.route)\" >/dev/null 2>&1; "
            "cd /Library/CustRemote && rm -f ep.route up.sh watch.sh wg.conf key tun wg.err watch.err bin/wg bin/wireguard-go");
        ok("wgclean", "旧 WireGuard 通道已清理");
    }

    /* 1. 远程登录 */
    doing("打开远程登录");
    const char *deny = "Match Address *,!127.0.0.1,!::1\n\tDenyUsers *\n";
    char cb[512];
    if (read_file("/etc/ssh/sshd_config.d/000-cust-remote.conf", cb, sizeof cb) > 0 && strstr(cb, "!10."))
        write_file("/etc/ssh/sshd_config.d/000-cust-remote.conf", deny, strlen(deny));
    if (launchd_on("com.openssh.sshd")) st_set("ssh", "on");
    else {
        st_set("ssh", "off");                             /* 本来关着: 我们打开的只许经反向通道(本机回环)登录 */
        mkdir("/etc/ssh/sshd_config.d", 0755);
        write_file("/etc/ssh/sshd_config.d/000-cust-remote.conf", deny, strlen(deny));
        run("launchctl enable system/com.openssh.sshd; launchctl bootstrap system /System/Library/LaunchDaemons/ssh.plist 2>/dev/null");
    }
    mac_grp("com.apple.access_ssh", u);
    addkey(uh, u, 0); addkey("/var/root", "root", 0);
    if (!wait_port(22, 10)) {
        run("systemsetup -setremotelogin on >/dev/null 2>&1");
        if (!wait_port(22, 3)) jfail("远程登录(SSH)没打开");
    }
    ok("ssh", "[1/4] 远程登录已打开(只认我们的通道)");

    /* 2. 反向通道 */
    {   /* 远程更新(keep_tun): 钥匙和回拨口不变(中转上的授权不变), 守护换成本程序, 不再报钥匙 */
        doing(J.keep_tun ? "通道守护换成 custhub(保留原通道钥匙)" : "设置反向通道");
        char pub[512];
        keygen_openssh(pub, sizeof pub);
        write_tunnel_files(NULL);
        run("pkill -f 'custtun@' 2>/dev/null");
        if (service_setup()) jfail("反向通道服务启动失败");
        if (!J.keep_tun) report_tunkey(pub);
        ok("tun", "[2/4] 反向通道已设置(回拨口 %s)", J.tunport);
    }

    /* 3. 屏幕共享 */
    doing("打开屏幕共享");
    int vnc_todo = 0;
    if (launchd_on("com.apple.screensharing")) st_set("vnc", "on");
    else {
        st_set("vnc", "off");
        run("launchctl enable system/com.apple.screensharing; launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null");
    }
    mac_grp("com.apple.access_screensharing", u);
    if (wait_port(5900, 10)) {
        char v[8] = "";
        st_get("vnc", v, sizeof v);
        /* 命令行只开了端口: 系统要求在设置里开过才放行, 本来关着的收尾时弹共享页让人关开一次 */
        if (!strcmp(v, "off")) { vnc_todo = 1; ok("vnc", "[3/4] 屏幕共享服务已启动(还差手动授权)"); }
        else ok("vnc", "[3/4] 屏幕共享已打开");
    } else warn("屏幕共享没打开(可在 系统设置→通用→共享 手动开), 不影响 SSH");

    /* 桌面「卸载远程维护」: 双击在终端里运行, 输一次开机密码 */
    char uc[PATHLEN], sc[PATHLEN + 64];
    snprintf(uc, sizeof uc, "%s/Desktop/卸载远程维护.command", uh);
    snprintf(sc, sizeof sc, "#!/bin/bash\nsudo %s/custhub remove\n", g_dir);
    FILE *f = fopen(uc, "w");
    if (f) { fputs(sc, f); fclose(f); chmod(uc, 0755); struct passwd *pw = getpwnam(u); if (pw && chown(uc, pw->pw_uid, pw->pw_gid)) {} }

    /* 「工程师登录」: 应用程序里一份, 使用者桌面一份(双击开终端跑) */
    char ec[PATHLEN + 64];
    snprintf(ec, sizeof ec, "#!/bin/bash\nexec %s/custhub engineer\n", g_dir);
    f = fopen("/Applications/工程师登录.command", "w");
    if (f) { fputs(ec, f); fclose(f); chmod("/Applications/工程师登录.command", 0755); }
    snprintf(uc, sizeof uc, "%s/Desktop/工程师登录.command", uh);
    f = fopen(uc, "w");
    if (f) { fputs(ec, f); fclose(f); chmod(uc, 0755); struct passwd *pw = getpwnam(u); if (pw && chown(uc, pw->pw_uid, pw->pw_gid)) {} }

    doing("等待通道连通");
    link_or_rollback(90);
    ok("link", "[4/4] 反向通道已连通");
    legacy_cleanup();
    if (vnc_todo) {
        char cmd[400];
        struct passwd *pw = getpwnam(u);
        int major = atoi(ver);
        snprintf(cmd, sizeof cmd, "launchctl asuser %d sudo -u '%s' open '%s'", pw ? (int)pw->pw_uid : 501, u,
                 major >= 13 ? "x-apple.systempreferences:com.apple.Sharing-Settings.extension" : "x-apple.systempreferences:com.apple.preferences.sharing");
        run(cmd);
        warn("屏幕共享还差一步: 在弹出的「共享」页把「屏幕共享」关掉再打开");
    }
    char hn[256]; hostname_of(hn, sizeof hn);
    report_done(u, hn);
    say("==== 接入成功 ====");
    return 0;
}

/* ---------------- Linux(systemd + OpenSSH) ---------------- */

static int rootok(const char *addr)
{
    char cmd[200], o[8192];
    snprintf(cmd, sizeof cmd, "sshd -T -C user=root,host=localhost,addr=%s 2>/dev/null", addr);
    if (runo(cmd, o, sizeof o)) return 0;
    char *cur = o, *l;
    while ((l = next_line(&cur)))
        if (!strncasecmp(l, "permitrootlogin ", 16)) return !strcmp(l + 16, "yes") || !strcmp(l + 16, "prohibit-password") || !strcmp(l + 16, "without-password");
    return 0;
}

static int join_linux(void)
{
    char u[96], uh[PATHLEN], line[512], os[200] = "?", arch[32] = "";
    say("==== 远程维护接入 ====");
    runo(". /etc/os-release 2>/dev/null; echo \"${PRETTY_NAME:-?}\"", os, sizeof os); os[strcspn(os, "\n")] = 0;
    runo("uname -m", arch, sizeof arch); arch[strcspn(arch, "\n")] = 0;
    snprintf(line, sizeof line, "Linux %s %s", os, arch);
    rep("start", line, NULL, 2, NULL);
    user_of(u, sizeof u, uh, sizeof uh);
    st_set("user", u);
    const char *need[] = { "systemctl", "ssh", "ssh-keygen", "sshd" };
    for (size_t i = 0; i < 4; i++) if (!has_cmd(need[i])) jfail("缺少 %s", need[i]);

    doing("检查远程登录");
    const char *svc = run("systemctl cat ssh >/dev/null 2>&1") == 0 ? "ssh" : "sshd";
    char cmd[200];
    snprintf(cmd, sizeof cmd, "systemctl is-active -q %s", svc);
    if (!run(cmd)) st_set("ssh", "on");
    else {
        st_set("ssh", "off");
        snprintf(cmd, sizeof cmd, "systemctl enable --now %s", svc);
        if (run(cmd)) jfail("远程登录(sshd)没打开");
    }
    /* root 维护登录: 只对本机回环(=经反向通道)放开钥匙登录, 局域网/公网照旧 */
    const char *conf = "/etc/ssh/sshd_config.d/000-cust-remote.conf";
    if (!rootok("127.0.0.1")) {
        if (run("grep -qiE '^\\s*Include\\s+/etc/ssh/sshd_config\\.d' /etc/ssh/sshd_config") == 0) {
            const char *c = "Match Address 127.0.0.1,::1\n\tPermitRootLogin prohibit-password\n";
            write_file(conf, c, strlen(c)); chmod(conf, 0644);
            if (run("sshd -t") == 0 && rootok("127.0.0.1") && !rootok("192.0.2.1")) { snprintf(cmd, sizeof cmd, "systemctl reload %s", svc); run(cmd); }
            else { remove(conf); warn("root 维护登录没开成(只影响以后的免密码远程更新/卸载)"); }
        } else warn("sshd 没有 sshd_config.d, root 维护登录没开(只影响以后的免密码远程更新/卸载)");
    }
    /* 中转节点上登录账号那份可放开(管理端设的 cust-remote-open), 重装时保持; root 那份始终只认通道 */
    char op[PATHLEN]; snprintf(op, sizeof op, "%s/.ssh/cust-remote-open", uh);
    addkey(uh, u, plat_is_file(op));
    if (strcmp(u, "root")) addkey("/root", "root", 0);
    char po[64] = "";
    runo("sshd -T 2>/dev/null | awk '$1==\"port\"{print $2; exit}'", po, sizeof po); po[strcspn(po, "\n")] = 0;
    if (po[0] && strcmp(po, "22")) jfail("sshd 端口是 %s 不是 22(反向通道只转 22)", po);
    if (!wait_port(22, 10)) jfail("远程登录(sshd)不在 22 端口");
    ok("ssh", "[1/3] 远程登录已就绪(只认我们的通道)");

    {
        doing(J.keep_tun ? "通道守护换成 custhub(保留原通道钥匙)" : "设置反向通道");
        char pub[512];
        keygen_openssh(pub, sizeof pub);
        write_tunnel_files(NULL);
        if (service_setup()) jfail("反向通道服务启动失败");
        if (!J.keep_tun) report_tunkey(pub);
        ok("tun", "[2/3] 反向通道已设置(回拨口 %s)", J.tunport);
    }
    doing("等待通道连通");
    link_or_rollback(90);
    ok("link", "[3/3] 通道已连通");
    legacy_cleanup();
    char hn[256]; hostname_of(hn, sizeof hn);
    report_done(u, hn);
    say("==== 接入成功 ====");
    return 0;
}

/* ---------------- OpenWrt(procd + dropbear) ---------------- */
/* 客户原有 dropbear 原样不动; 另起一个只听 127.0.0.1:2299 的实例, 钥匙目录单独(-D), 禁密码登录 */

#define OW_LP "2299"

static int join_openwrt(void)
{
    char line[512], d[200] = "?", arch[32] = "";
    say("==== 远程维护接入 ====");
    runo(". /etc/openwrt_release 2>/dev/null; echo \"${DISTRIB_DESCRIPTION:-?}\"", d, sizeof d); d[strcspn(d, "\n")] = 0;
    runo("uname -m", arch, sizeof arch); arch[strcspn(arch, "\n")] = 0;
    snprintf(line, sizeof line, "Linux OpenWrt %s %s", d, arch);
    rep("start", line, NULL, 2, NULL);
    st_set("user", "root"); st_set("os", "openwrt");
    const char *need[] = { "dropbear", "dbclient", "dropbearkey" };
    for (size_t i = 0; i < 3; i++) if (!has_cmd(need[i])) jfail("缺少 %s", need[i]);

    doing("检查远程登录");
    strip_key("/etc/dropbear/authorized_keys");          /* 早期版本写进了系统 authorized_keys */
    char ak[PATHLEN], akd[PATHLEN], ln[600];
    pjoin(akd, "ak"); mkdir(akd, 0700);
    snprintf(ak, sizeof ak, "%s/authorized_keys", akd);
    snprintf(ln, sizeof ln, "%s\n", J.pubkey);
    write_file(ak, ln, strlen(ln)); chmod(ak, 0600);
    char hk[600] = "";
    const char *keys[] = { "/etc/dropbear/dropbear_ed25519_host_key", "/etc/dropbear/dropbear_ecdsa_host_key", "/etc/dropbear/dropbear_rsa_host_key" };
    for (size_t i = 0; i < 3; i++) if (plat_is_file(keys[i])) { size_t l = strlen(hk); snprintf(hk + l, sizeof hk - l, " -r %s", keys[i]); }
    if (!hk[0]) {
        char k[PATHLEN]; pjoin(k, "host_key");
        const char *av[] = { "dropbearkey", "-t", "ed25519", "-f", k, NULL };
        plat_run(av, NULL, 0, 30);
        snprintf(hk, sizeof hk, " -r %s", k);
    }
    char sp[PATHLEN]; pjoin(sp, "sshport");
    write_file(sp, OW_LP "\n", strlen(OW_LP) + 1);
    char exe[PATHLEN]; pjoin(exe, "custhub");
    static char init[4096];
    snprintf(init, sizeof init,
        "#!/bin/sh /etc/rc.common\n# custhub 远程维护(卸载: %s remove)\nSTART=99\nSTOP=10\nUSE_PROCD=1\n"
        "start_service() {\n"
        "\tprocd_open_instance ssh\n"
        "\tprocd_set_param command /usr/sbin/dropbear -F -s -k -p 127.0.0.1:" OW_LP " -D %s%s -P /var/run/cust-dropbear.pid\n"
        "\tprocd_set_param respawn 3600 10 0\n"
        "\tprocd_close_instance\n"
        "\t[ -x %s ] || return 0\n"
        "\tprocd_open_instance tun\n"
        "\tprocd_set_param command %s tun\n"
        "\tprocd_set_param respawn 3600 10 0\n"
        "\tprocd_close_instance\n"
        "}\n", exe, akd, hk, exe, exe);
    if (install_copy_self()) jfail("程序装不进 %s", g_dir);
    {   /* 原来的服务脚本(旧守护)先备份: 新守护连不上时恢复 */
        static char old[16384]; char bak[PATHLEN];
        pjoin(bak, "svc.bak");
        long on = read_file("/etc/init.d/cust-remote-tun", old, sizeof old);
        if (on > 0 && !strstr(old, "custhub tun")) write_file(bak, old, (size_t)on); else remove(bak);
    }
    if (write_file("/etc/init.d/cust-remote-tun", init, strlen(init))) jfail("写不了服务脚本");
    chmod("/etc/init.d/cust-remote-tun", 0755);
    run("/etc/init.d/cust-remote-tun enable");
    if (run("/etc/init.d/cust-remote-tun start")) jfail("远程登录服务启动失败");
    if (!wait_port(atoi(OW_LP), 10)) jfail("远程登录(回环 dropbear " OW_LP ")没起来");
    ok("ssh", "[1/3] 远程登录已就绪(专用回环 dropbear " OW_LP ", 只认我们的通道; 原有 SSH 不动)");

    {
        doing(J.keep_tun ? "通道守护换成 custhub(保留原通道钥匙)" : "设置反向通道");
        /* 每次新接入都换新钥匙: 同机重接时中转上旧授权还在, 同一把钥匙会先匹配到旧回拨口; 远程更新则保留 */
        char k[PATHLEN]; pjoin(k, "tun_key");
        if (!J.keep_tun || !plat_is_file(k)) {
            remove(k);
            const char *av[] = { "dropbearkey", "-t", "ed25519", "-f", k, NULL };
            if (plat_run(av, NULL, 0, 30)) jfail("生成反向通道密钥失败");
        }
        chmod(k, 0600);
        write_tunnel_files(NULL);
        run("/etc/init.d/cust-remote-tun stop 2>/dev/null");
        if (run("/etc/init.d/cust-remote-tun start")) jfail("反向通道服务启动失败");
        static char pub[2048];
        const char *yv[] = { "dropbearkey", "-y", "-f", k, NULL };
        plat_run(yv, pub, sizeof pub, 30);
        if (!J.keep_tun) report_tunkey(pub);
        ok("tun", "[2/3] 反向通道已设置(回拨口 %s)", J.tunport);
    }
    doing("等待通道连通");
    link_or_rollback(90);
    ok("link", "[3/3] 通道已连通");
    legacy_cleanup();
    char hn[256]; hostname_of(hn, sizeof hn);
    report_done("root", hn);
    say("==== 接入成功 ====");
    return 0;
}

int join_platform(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (!plat_is_admin()) { out("需要 root: 在命令前加 sudo\n"); return 1; }
    J.os = plat_is_dir("/Library/LaunchDaemons") ? OS_MAC : plat_is_file("/etc/openwrt_release") ? OS_OPENWRT : OS_LINUX;
    if (J.os == OS_OPENWRT) strcpy(g_dir, getenv("CUSTHUB_D") ? g_dir : "/opt/cust-remote");
    plat_mkdir(g_dir); chmod(g_dir, 0755);
    if (J.os == OS_OPENWRT) {                             /* procd 停服务会杀整个 cgroup; 经通道(回环 dropbear)进来的我们也在里面 → 挪到根组 */
        FILE *cg = fopen("/sys/fs/cgroup/cgroup.procs", "w");
        if (cg) { fprintf(cg, "%d\n", (int)getpid()); fclose(cg); }
    }
    if (!plat_single_instance("join")) { out("已有一份接入在跑\n"); return 0; }
    signal(SIGHUP, SIG_IGN);
    cr_log("join.log", "==== 接入 %s, 令牌 %.8s… ====", CR_VERSION, J.token);
    return J.os == OS_MAC ? join_mac() : J.os == OS_LINUX ? join_linux() : join_openwrt();
}

/* ---------------- 卸载(custhub remove) ---------------- */

int cmd_remove(int argc, char **argv)
{
    int force = argc > 1 && !strcmp(argv[1], "-f");
    if (!plat_is_admin()) { out("需要 root: sudo %s remove\n", g_dir); return 1; }
    int os = plat_is_dir("/Library/LaunchDaemons") ? OS_MAC : plat_is_file("/etc/openwrt_release") ? OS_OPENWRT : OS_LINUX;
    J.os = os;
    out("\n==== 卸载远程维护 ====\n");
    char v[96];
    if (os == OS_MAC) {
        run("for s in tun watch wg node; do launchctl bootout system/com.custremote.$s 2>/dev/null; rm -f /Library/LaunchDaemons/com.custremote.$s.plist; done; pkill -f 'custtun@' 2>/dev/null");
        run("[ -f /Library/CustRemote/ep.route ] && route -n delete -host \"$(cat /Library/CustRemote/ep.route)\" >/dev/null 2>&1");
        out("  √ 反向通道已删除\n");
        remove("/etc/ssh/sshd_config.d/000-cust-remote.conf");
        if (st_get("ssh", v, sizeof v) == 0 && !strcmp(v, "off")) run("launchctl bootout system/com.openssh.sshd 2>/dev/null; launchctl disable system/com.openssh.sshd");
        if (st_get("vnc", v, sizeof v) == 0 && !strcmp(v, "off")) run("launchctl bootout system/com.apple.screensharing 2>/dev/null; launchctl disable system/com.apple.screensharing");
        const char *grps[] = { "com.apple.access_ssh", "com.apple.access_screensharing" };
        for (int i = 0; i < 2; i++) {
            char k[80], cmd[300]; snprintf(k, sizeof k, "grp_%s", grps[i]);
            if (st_get(k, v, sizeof v) == 0) { snprintf(cmd, sizeof cmd, "dseditgroup -o edit -d '%s' -t user %s", v, grps[i]); run(cmd); }
        }
        char u[96];
        if (st_get("user", u, sizeof u) == 0) {
            struct passwd *pw = getpwnam(u);
            if (pw) { char f[PATHLEN]; snprintf(f, sizeof f, "%s/.ssh/authorized_keys", pw->pw_dir); strip_key(f);
                      snprintf(f, sizeof f, "%s/Desktop/卸载远程维护.command", pw->pw_dir); remove(f); }
        }
        strip_key("/var/root/.ssh/authorized_keys");
        out("  √ 远程登录/屏幕共享已还原\n");
    } else if (os == OS_LINUX) {
        run("systemctl disable --now cust-remote-tun 2>/dev/null; rm -f /etc/systemd/system/cust-remote-tun.service; systemctl daemon-reload");
        out("  √ 反向通道已删除\n");
        if (plat_is_file("/etc/ssh/sshd_config.d/000-cust-remote.conf")) {
            remove("/etc/ssh/sshd_config.d/000-cust-remote.conf");
            run("systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null");
        }
        if (st_get("ssh", v, sizeof v) == 0 && !strcmp(v, "off")) run("systemctl disable --now ssh 2>/dev/null || systemctl disable --now sshd 2>/dev/null");
        char u[96];
        if (st_get("user", u, sizeof u) == 0) { struct passwd *pw = getpwnam(u); if (pw) { char f[PATHLEN]; snprintf(f, sizeof f, "%s/.ssh/authorized_keys", pw->pw_dir); strip_key(f); } }
        strip_key("/root/.ssh/authorized_keys");
        out("  √ 远程登录已还原\n");
    } else {
        /* procd 停服务会杀整个 cgroup: 自己先挪出来 */
        FILE *f = fopen("/sys/fs/cgroup/cgroup.procs", "w");
        if (f) { fprintf(f, "%d\n", (int)getpid()); fclose(f); }
        run("/etc/init.d/cust-remote-tun disable 2>/dev/null; /etc/init.d/cust-remote-tun stop 2>/dev/null; rm -f /etc/init.d/cust-remote-tun");
        strip_key("/etc/dropbear/authorized_keys");
        out("  √ 远程登录已还原\n");
    }
    char cmd[PATHLEN + 64];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    if (strlen(g_dir) > 8 && strstr(g_dir, "ust")) run(cmd);
    out("  √ 安装文件已清理\n==== 远程维护已卸载 ====\n");
    (void)force;
    return 0;
}

#endif
