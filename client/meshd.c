/* 通道守护顺带带起网络层(design-v3 §7 第 4 段: 新旧并行)
 *   目录 $D/mesh: node.key(首次生成, 本机网络身份, 不带任何管理权限)
 *                 conf(每轮按本机情况重写)  trust(主钥匙签的成员名单)  trust.pull(从中转取来的最新一份)  mesh.log
 *   种子名单随发布物下发: 正连着的中转的 /pkg/client/release.txt 里的版本 → /pkg/client/custhub-<版本>-mesh-trust
 *   (中转照常拉 Release 转发, 不用为网络层改任何东西); 之后的新名单沿网络链路自己传, 报到时中继也会给; 没有名单 = 网络层不启动
 *   本机还不在名单里时, 网络层只向中继报到(自报机器名 + 回拨口, 管理员据此对上 c-N), 每台中继 10 分钟一次, 等批准
 *   网络层是独立子进程: 它崩了只影响它自己, 反向通道照旧; 守护退出/升级时一起停 */
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define MESH_CTL "127.0.0.1:7471"

static proc_t mp;
static long next_spawn, next_fetch;

void meshd_stop(void) { plat_kill(&mp); }

static void hostname(char *out, size_t cap)
{
#ifdef _WIN32
    DWORD n = (DWORD)cap;
    if (!GetComputerNameA(out, &n)) snprintf(out, cap, "win");
#else
    if (gethostname(out, cap)) snprintf(out, cap, "host");
    out[cap - 1] = 0;
#endif
    for (char *p = out; *p; p++) if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) *p = '_';
}

static int write_if_changed(const char *path, const char *data, size_t len)
{
    static char old[MAXBUF];
    long n = read_file(path, old, sizeof old);
    if (n == (long)len && !memcmp(old, data, len)) return 0;
    return write_file(path, data, len) == 0 ? 1 : -1;
}

/* alive: 此刻反向通道连着的中转; 只从它们取名单 */
void meshd_tick(const conf_t *c, const char *const *alive, int nalive)
{
    char dir[PATHLEN], p[PATHLEN], self[PATHLEN];
    long now = plat_now();
    pjoin(dir, "mesh");
    if (plat_mkdir(dir)) return;
    if (plat_self_path(self, sizeof self)) return;

    snprintf(p, sizeof p, "%s/node.key", dir);
    if (!plat_is_file(p)) {
        const char *av[] = { self, "mesh", "keygen", dir, NULL };
        char pub[128];
        if (plat_run(av, pub, sizeof pub, 20) != 0) return;
        plat_secure_key(p);
        cr_log("mesh.log", "生成网络身份 %s", pub);
    }

    /* conf: 主公钥取信任清单应用时落的 master.pub 第一把 */
    static char mk[4096];
    char mline[200] = "";
    pjoin(p, "master.pub");
    if (read_file(p, mk, sizeof mk) > 0) {
        char *cur = mk, *l;
        while ((l = next_line(&cur))) { char *s = strstr(l, "ssh-ed25519 "); if (s) { snprintf(mline, sizeof mline, "%.150s", s); break; } }
    }
    if (!mline[0]) return;                                 /* 还没有主公钥: 等信任清单 */
    char host[64], cf[1024];
    hostname(host, sizeof host);
    int n = snprintf(cf, sizeof cf,
        "master %s\nctl %s\nallow %s\nfallback %s/trust.pull\nlog %s/mesh.log\nname %s\nhello %s %s %s port=%s\n",
        mline, MESH_CTL, c->sshport, dir, dir, host, host, CR_PLAT, CR_VERSION, c->port);
    snprintf(p, sizeof p, "%s/conf", dir);
    if (write_if_changed(p, cf, (size_t)n) > 0 && plat_alive(&mp)) plat_kill(&mp);   /* 配置变了: 重启网络层 */

    /* 名单: 从连着的中转取 */
    if (now >= next_fetch && nalive > 0) {
        static char t[MAXBUF];
        next_fetch = now + 600;                            /* 发布物里没带名单是常态(网络层还没启用), 别查太勤 */
        for (int i = 0; i < nalive; i++) {
            char ver[24] = "", url[96];
            if (http_get_text(alive[i], c->http_port, "/pkg/client/release.txt", t, sizeof t) != 200) continue;
            char *v = strstr(t, "\nversion ");
            if (!v || sscanf(v + 9, "%23s", ver) != 1 || ver_num(ver) < 0) continue;
            snprintf(url, sizeof url, "/pkg/client/custhub-%s-mesh-trust", ver);
            if (http_get_text(alive[i], c->http_port, url, t, sizeof t) != 200) continue;
            if (strncmp(t, "custhub-mesh-trust ", 19)) continue;
            snprintf(p, sizeof p, "%s/trust.pull", dir);
            if (write_if_changed(p, t, strlen(t)) > 0) cr_log("mesh.log", "从 %s 取到成员名单", alive[i]);
            next_fetch = now + 600 + (now % 60);
            break;
        }
    }
    char tp[PATHLEN], tpull[PATHLEN];
    snprintf(tp, sizeof tp, "%s/trust", dir);
    snprintf(tpull, sizeof tpull, "%s/trust.pull", dir);
    if (!plat_is_file(tp)) {                               /* 第一次: 拿取来的那份当种子(网络层自己会验签) */
        static char t[MAXBUF];
        long tn = read_file(tpull, t, sizeof t);
        if (tn <= 0 || write_file(tp, t, (size_t)tn)) return;
    }

    if (!plat_alive(&mp) && now >= next_spawn) {
        next_spawn = now + 30;
        const char *av[] = { self, "mesh", "run", dir, NULL };
        if (plat_spawn_bg(av, &mp)) cr_log("mesh.log", "网络层起不来");
    }
}
