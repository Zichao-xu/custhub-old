/* 自升级(SPEC §6): 只接受主钥匙签名、版本更高的发布物; 换上后进试用期, 起不来或连不上就回滚
 *
 * 发布清单(中转在 kick 时随信任清单一起发; 命名空间 custhub-release):
 *   custhub-release v1
 *   version 0.2.0
 *   file <平台> <字节数> <sha512 十六进制>      每个平台一行, 平台名同构建产物(win-x64 / mac-arm64 / linux-mips …)
 *   --sig-- / 签名 / --end--
 * 二进制从同一台中转取: http://中转:http_port/pkg/client/custhub-<版本>-<平台>[.exe]
 *
 * 安装目录里的状态文件:
 *   custhub.new / .old        下载中的新版 / 换下来的旧版(回滚用)
 *   upgrade.pending           "旧版本 新版本 启动次数"  —— 试用期; 有通道连上就删(转正)
 *   upgrade.bad               "版本 回滚次数"           —— 回滚满 2 次的版本不再尝试 */
#include "cr.h"
#include "plat.h"
#include "vendor/monocypher.h"
#include "vendor/monocypher-ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXBIN    (8L * 1024 * 1024)
#define TRIAL_S   120
#define MAX_TRIES 3

static void (*g_stop)(void);

long ver_num(const char *v)
{
    int a, b, c; char x;
    if (sscanf(v, "%d.%d.%d%c", &a, &b, &c, &x) != 3 || a < 0 || b < 0 || c < 0 || a > 999 || b > 999 || c > 999) return -1;
    return a * 1000000L + b * 1000L + c;
}

static void bin_path(char *out, const char *suffix)       /* suffix: "" / ".new" / ".old" */
{
    char n[64];
    snprintf(n, sizeof n, "custhub%s" EXE, suffix);
    pjoin(out, n);
}

static int sha512_file(const char *path, uint8_t h[64], long *size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    crypto_sha512_ctx ctx;
    crypto_sha512_init(&ctx);
    uint8_t buf[16384]; size_t n; long tot = 0;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) { crypto_sha512_update(&ctx, buf, n); tot += (long)n; }
    fclose(f);
    crypto_sha512_final(&ctx, h);
    *size = tot;
    return 0;
}

static int hex64(const char *s, uint8_t out[64])
{
    if (strlen(s) != 128) return -1;
    for (int i = 0; i < 64; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int bad_count(const char *ver)
{
    char p[PATHLEN], buf[2048];
    pjoin(p, "upgrade.bad");
    if (read_file(p, buf, sizeof buf) < 0) return 0;
    char *cur = buf, *l; char v[32]; int n;
    while ((l = next_line(&cur))) if (sscanf(l, "%31s %d", v, &n) == 2 && !strcmp(v, ver)) return n;
    return 0;
}

static void bad_add(const char *ver)
{
    char p[PATHLEN], buf[2048], nw[2400]; size_t len = 0;
    int n = bad_count(ver) + 1;
    pjoin(p, "upgrade.bad");
    nw[0] = 0;
    if (read_file(p, buf, sizeof buf) >= 0) {
        char *cur = buf, *l; char v[32]; int k;
        while ((l = next_line(&cur)))
            if (sscanf(l, "%31s %d", v, &k) == 2 && strcmp(v, ver)) { sb_add(nw, sizeof nw, &len, l); sb_add(nw, sizeof nw, &len, "\n"); }
    }
    char line[64]; snprintf(line, sizeof line, "%s %d\n", ver, n);
    sb_add(nw, sizeof nw, &len, line);
    write_file(p, nw, len);
}

typedef struct { char from[32], to[32]; int tries; } pending_t;

static int pending_read(pending_t *p)
{
    char path[PATHLEN], buf[128];
    pjoin(path, "upgrade.pending");
    if (read_file(path, buf, sizeof buf) < 0) return 0;
    return sscanf(buf, "%31s %31s %d", p->from, p->to, &p->tries) == 3;
}

static void pending_write(const pending_t *p)
{
    char path[PATHLEN], buf[128];
    pjoin(path, "upgrade.pending");
    snprintf(buf, sizeof buf, "%s %s %d\n", p->from, p->to, p->tries);
    write_file(path, buf, strlen(buf));
}

static void pending_clear(void) { char p[PATHLEN]; pjoin(p, "upgrade.pending"); remove(p); }

static void restart_into(const char *exe)
{
    const char *av[] = { exe, "tun", "--takeover", NULL };
    plat_restart_self(exe, av);
}

/* 把 .old 换回来, 记一次回滚, 用旧版接着跑 */
static void rollback(const pending_t *p, const char *why)
{
    char cur[PATHLEN], old[PATHLEN], gone[PATHLEN];
    bin_path(cur, ""); bin_path(old, ".old"); bin_path(gone, ".bad");
    if (!plat_is_file(old)) { cr_log("upgrade.log", "%s → %s %s, 但没有旧版可回滚, 继续用新版", p->from, p->to, why); pending_clear(); return; }
    bad_add(p->to);
    pending_clear();
    remove(gone);
    if (plat_replace(cur, gone) || plat_replace(old, cur)) { cr_log("upgrade.log", "回滚改名失败"); return; }
    cr_log("upgrade.log", "回滚 %s → %s: %s", p->to, p->from, why);
    if (g_stop) g_stop();
    restart_into(cur);
    cr_log("upgrade.log", "回滚后重启失败");
}

void upgrade_trial_start(void (*stop_children)(void))
{
    pending_t p;
    g_stop = stop_children;
    if (!pending_read(&p)) return;
    if (strcmp(p.to, CR_VERSION)) {                       /* 跑的不是试用的那个版本(已被回滚或手动换过): 作废 */
        pending_clear();
        return;
    }
    p.tries++;
    if (p.tries > MAX_TRIES) { rollback(&p, "连续启动后都没连上中转"); return; }
    pending_write(&p);
    cr_log("upgrade.log", "试用 %s(第 %d 次启动)", p.to, p.tries);
}

void upgrade_trial_tick(int any_up, long started)
{
    pending_t p;
    if (!pending_read(&p) || strcmp(p.to, CR_VERSION)) return;
    if (any_up) { pending_clear(); cr_log("upgrade.log", "%s 转正(已有通道连上)", p.to); return; }
    if (plat_now() - started > TRIAL_S) rollback(&p, "试用期内没有一条通道连上");
}

/* 核对一份待装的二进制: 大小 + sha512 + 能跑起来且报对版本 */
static int check_bin(const char *path, long size, const uint8_t want[64], const char *ver)
{
    uint8_t h[64]; long got;
    if (sha512_file(path, h, &got) || got != size || crypto_verify64(h, want)) return -1;
    plat_make_exec(path);
    char out[256], expect[64];
    const char *av[] = { path, "version", NULL };
    if (plat_run(av, out, sizeof out, 20) != 0) return -2;
    snprintf(expect, sizeof expect, "custhub %s", ver);
    return strncmp(out, expect, strlen(expect)) == 0 && (out[strlen(expect)] == ' ' || out[strlen(expect)] == '\n' || out[strlen(expect)] == '\r') ? 0 : -2;
}

/* 已核对好的 .new 换上; restart=0 只换不重启(手动/测试) */
static int swap_in(const char *ver, int restart)
{
    char cur[PATHLEN], nw[PATHLEN], old[PATHLEN];
    bin_path(cur, ""); bin_path(nw, ".new"); bin_path(old, ".old");
    pending_t p;
    snprintf(p.from, sizeof p.from, "%s", CR_VERSION);
    snprintf(p.to, sizeof p.to, "%s", ver);
    p.tries = 0;
    remove(old);
    if (plat_is_file(cur) && plat_replace(cur, old)) { cr_log("upgrade.log", "换下旧版失败"); return -1; }   /* Windows 也允许给运行中的 exe 改名 */
    if (plat_replace(nw, cur)) { plat_replace(old, cur); cr_log("upgrade.log", "换上新版失败"); return -1; }
    pending_write(&p);
    cr_log("upgrade.log", "已换上 %s(原 %s), 进入试用", ver, CR_VERSION);
    if (!restart) return 0;
    if (g_stop) g_stop();
    restart_into(cur);
    /* 走到这里 = 没能重启: 换回去 */
    pending_clear();
    plat_replace(cur, nw); plat_replace(old, cur);
    cr_log("upgrade.log", "重启进新版失败, 已换回");
    return -1;
}

/* 验签并找本平台那一行; 返回 0 表示有比自己新的可用版本 */
static int parse_release(const char *text, char *ver, long *size, uint8_t sha[64])
{
    static bundle_t b;
    static char d[MAXBUF];
    if (bundle_parse(text, "custhub-release v1", &b)) return -1;
    memcpy(d, b.data, b.dlen + 1);
    char *cur = d, *l;
    next_line(&cur);
    l = next_line(&cur);
    if (!l || strncmp(l, "version ", 8) || ver_num(l + 8) < 0 || strlen(l + 8) > 15) return -1;
    strcpy(ver, l + 8);
    if (ver_num(ver) <= ver_num(CR_VERSION)) return 1;
    uint8_t keys[MAXKEYS][32];
    int nk = master_keys(keys, MAXKEYS);
    if (!nk || !bundle_verify(&b, "custhub-release", keys, nk)) { cr_log("upgrade.log", "发布清单 %s 验签没过", ver); return -1; }
    while ((l = next_line(&cur))) {
        char plat[32], hex[160]; long sz;
        if (sscanf(l, "file %31s %ld %159s", plat, &sz, hex) != 3) continue;
        if (strcmp(plat, CR_PLAT)) continue;
        if (sz <= 0 || sz > MAXBIN || hex64(hex, sha)) return -1;
        *size = sz;
        return 0;
    }
    return 1;                                              /* 这个版本没有本平台的 */
}

void upgrade_check(const char *kick, const char *host, void (*stop_children)(void))
{
    static char tried[32]; static long tried_at;
    char ver[32]; long size; uint8_t sha[64];
    g_stop = stop_children;
    if (parse_release(kick, ver, &size, sha)) return;
    if (bad_count(ver) >= 2) return;
    if (!strcmp(tried, ver) && plat_now() - tried_at < 600) return;   /* 同一版本失败后 10 分钟内不再试 */
    snprintf(tried, sizeof tried, "%s", ver); tried_at = plat_now();

    conf_t c; conf_load(&c);
    char nw[PATHLEN], url[160];
    bin_path(nw, ".new");
    snprintf(url, sizeof url, "/pkg/client/custhub-%s-%s%s", ver, CR_PLAT, strncmp(CR_PLAT, "win", 3) ? "" : ".exe");
    long got = 0;
    int st = http_get_file(host, c.http_port, url, nw, size, &got);
    if (st != 200) { cr_log("upgrade.log", "从 %s 下载 %s 失败(%d)", host, ver, st); return; }
    int r = check_bin(nw, size, sha, ver);
    if (r) { remove(nw); cr_log("upgrade.log", "%s %s", ver, r == -1 ? "大小或哈希不符, 丢弃" : "跑不起来或版本不对, 丢弃"); return; }
    cr_log("upgrade.log", "从 %s 取到 %s, 核对通过", host, ver);
    swap_in(ver, 1);
}

/* 手动: custhub upgrade 清单文件 二进制 —— 与自动升级同样的验签/核对, 换上但不重启 */
int cmd_upgrade_file(const char *manifest, const char *bin)
{
    static char text[MAXBUF];
    char ver[32], nw[PATHLEN]; long size; uint8_t sha[64];
    if (read_file(manifest, text, sizeof text) < 0) { out("读不了清单\n"); return 2; }
    int r = parse_release(text, ver, &size, sha);
    if (r < 0) { out("清单无效或验签没过\n"); return 1; }
    if (r > 0) { out("清单里没有比 %s 新的本平台(%s)版本\n", CR_VERSION, CR_PLAT); return 0; }
    static char buf[MAXBIN];
    FILE *f = fopen(bin, "rb");
    if (!f) { out("读不了 %s\n", bin); return 2; }
    size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
    bin_path(nw, ".new");
    FILE *o = fopen(nw, "wb");
    if (!o || fwrite(buf, 1, n, o) != n) { if (o) fclose(o); out("写不了 %s\n", nw); return 2; }
    fclose(o);
    if ((r = check_bin(nw, size, sha, ver))) { remove(nw); out(r == -1 ? "大小或哈希不符\n" : "跑不起来或版本不对\n"); return 1; }
    if (swap_in(ver, 0)) { out("换上失败(见 upgrade.log)\n"); return 1; }
    out("已换上 %s, 重启守护后进入试用期\n", ver);
    return 0;
}
