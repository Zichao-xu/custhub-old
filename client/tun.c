/* 通道守护(取代 tun.ps1 / tun-mac.sh / tun-openwrt.sh): 对 hubs.txt 里每台中转保持一条 ssh -N -R
 * 重连前先不带 -N 连一次: 中转上的强制命令踢掉我们自己占着回拨口的旧连接, 顺带发来签名信任清单 → 验签应用
 * 连不上的中转 30 秒后再试, 不拖慢其他中转; 清单里没了的中转断开 */
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef _WIN32
#include <sys/stat.h>
#endif

#define UP_AFTER 20

typedef struct {
    char   host[64], port[8];
    proc_t p;
    long   since, next;
    int    want;
} hub_t;

static hub_t hubs[MAXHUBS];
static int nhubs;

static void stop_all(void)
{
    for (int i = 0; i < nhubs; i++) plat_kill(&hubs[i].p);
    meshd_stop();
}

static hub_t *hub_get(const char *h)
{
    for (int i = 0; i < nhubs; i++) if (!strcmp(hubs[i].host, h)) return &hubs[i];
    if (nhubs >= MAXHUBS) return NULL;
    hub_t *x = &hubs[nhubs++];
    memset(x, 0, sizeof *x);
    snprintf(x->host, sizeof x->host, "%s", h);
    return x;
}

/* hubs.txt: "地址 端口 ssh-ed25519 公钥"; 同时生成 known_hosts, 只认这些主机钥匙 */
static int load_hubs(const conf_t *c, char *kh)
{
    static char buf[16384];
    char p[PATHLEN], khbuf[16384];
    size_t kl = 0;
    khbuf[0] = 0;
    for (int i = 0; i < nhubs; i++) hubs[i].want = 0;
    pjoin(p, "hubs.txt");
    if (read_file(p, buf, sizeof buf) < 0) buf[0] = 0;
    char *cur = buf, *l;
    int n = 0;
    while ((l = next_line(&cur))) {
        char h[128], port[16], t[32], k[128], extra[8];
        if (strlen(l) > 250 || sscanf(l, "%127s %15s %31s %127s %7s", h, port, t, k, extra) != 4) continue;
        if (!valid_host(h) || !all_digits(port, 5) || strcmp(t, "ssh-ed25519") || !valid_b64_key(k)) continue;
        hub_t *x = hub_get(h);
        if (!x) continue;
        snprintf(x->port, sizeof x->port, "%s", port);
        x->want = 1; n++;
        char line[300];
        if (!strcmp(port, "22")) snprintf(line, sizeof line, "%s ssh-ed25519 %s\n", h, k);
        else snprintf(line, sizeof line, "[%s]:%s ssh-ed25519 %s\n", h, port, k);
        sb_add(khbuf, sizeof khbuf, &kl, line);
    }
    char old[16384];
    if (read_file(kh, old, sizeof old) < 0 || strcmp(old, khbuf)) write_file(kh, khbuf, kl);
    return n;
}

static void argv_kick(const conf_t *c, const char *kh, hub_t *x, const char **av, char *dest)
{
    int i = 0;
    snprintf(dest, 96, "custtun@%s", x->host);
    av[i++] = c->ssh; av[i++] = "-i"; av[i++] = c->key;
    if (c->dropbear) {
        av[i++] = "-p"; av[i++] = x->port; av[i++] = "-o"; av[i++] = "BatchMode=yes"; av[i++] = "-T";
    } else {
        static char khopt[PATHLEN + 32];
        snprintf(khopt, sizeof khopt, "UserKnownHostsFile=%s", kh);
        av[i++] = "-o"; av[i++] = "IdentitiesOnly=yes"; av[i++] = "-o"; av[i++] = khopt;
        av[i++] = "-o"; av[i++] = "StrictHostKeyChecking=yes"; av[i++] = "-o"; av[i++] = "BatchMode=yes";
        av[i++] = "-o"; av[i++] = "ConnectTimeout=10"; av[i++] = "-p"; av[i++] = x->port;
    }
    av[i++] = dest; av[i] = NULL;
}

static void argv_tun(const conf_t *c, const char *kh, hub_t *x, const char **av, char *dest, char *fwd)
{
    int i = 0;
    snprintf(dest, 96, "custtun@%s", x->host);
    snprintf(fwd, 64, "127.0.0.1:%s:127.0.0.1:%s", c->port, c->sshport);
    av[i++] = c->ssh; av[i++] = "-i"; av[i++] = c->key;
    if (c->dropbear) {
        av[i++] = "-p"; av[i++] = x->port; av[i++] = "-o"; av[i++] = "BatchMode=yes";
        av[i++] = "-o"; av[i++] = "ExitOnForwardFailure=yes"; av[i++] = "-N"; av[i++] = "-T";
        av[i++] = "-K"; av[i++] = "15";
    } else {
        static char khopt[PATHLEN + 32];
        snprintf(khopt, sizeof khopt, "UserKnownHostsFile=%s", kh);
        av[i++] = "-o"; av[i++] = "IdentitiesOnly=yes"; av[i++] = "-o"; av[i++] = khopt;
        av[i++] = "-o"; av[i++] = "StrictHostKeyChecking=yes"; av[i++] = "-o"; av[i++] = "BatchMode=yes";
        av[i++] = "-o"; av[i++] = "ConnectTimeout=10"; av[i++] = "-p"; av[i++] = x->port;
        av[i++] = "-N"; av[i++] = "-o"; av[i++] = "ServerAliveInterval=15"; av[i++] = "-o"; av[i++] = "ServerAliveCountMax=3";
        av[i++] = "-o"; av[i++] = "ExitOnForwardFailure=yes";
    }
    av[i++] = "-R"; av[i++] = fwd; av[i++] = dest; av[i] = NULL;
}

int cmd_tun(int argc, char **argv)
{
    conf_t c;
    conf_load(&c);
    int takeover = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc && all_digits(argv[i + 1], 5)) strcpy(c.port, argv[++i]);
        else if (!strcmp(argv[i], "--takeover")) takeover = 1;
    }
    if (!c.port[0]) { out("没有回拨口: client.conf 里写 \"port N\" 或加 --port N\n"); return 2; }
    /* 升级/回滚接班: 等上一个进程让出锁; 平时已有一个在跑就退出 */
    if (!(takeover ? plat_single_instance_wait("tun", 60) : plat_single_instance("tun"))) return 0;
    plat_on_term(stop_all);
    long started = plat_now();
    upgrade_trial_start(stop_all);

    char kh[PATHLEN];
    if (c.dropbear) {                                     /* dbclient 只读 $HOME/.ssh/known_hosts, 没有 -y 不认识就拒 */
        char sd[PATHLEN];
        pjoin(sd, ".ssh");
#ifndef _WIN32
        mkdir(sd, 0700);
#endif
        snprintf(kh, sizeof kh, "%s/known_hosts", sd);
        plat_setenv("HOME", g_dir);
    } else pjoin(kh, "hubs_known");
    cr_log("tun.log", "守护启动 %s(%s), 回拨口 %s → 本机 %s, %s", CR_VERSION, CR_PLAT, c.port, c.sshport, c.ssh);

    static char kick[MAXBUF];
    /* 定时轮询发布清单(SPEC §6.1): 中转把拉到的签名清单放在 /pkg/client/release.txt; 不只在重连 kick 时看 */
    const char *pe = getenv("CUSTHUB_POLL");             /* 仅供测试: 首次轮询前等几秒 */
    long next_poll = started + (pe && all_digits(pe, 4) ? atol(pe) : 60 + (long)(plat_now() % 60));
    for (;;) {
        load_hubs(&c, kh);
        /* 第一行标明是本程序写的: 接入/安装只认它, 不被旧守护残留的状态骗(11-16 c-8) */
        char st[4096]; size_t sl = 0; st[0] = 0;
        sb_add(st, sizeof st, &sl, "# custhub " CR_VERSION "\n");
        long now = plat_now();
        int any_up = 0;
        for (int i = 0; i < nhubs; i++) {
            hub_t *x = &hubs[i];
            if (!x->want) continue;
            char line[128];
            if (plat_alive(&x->p)) {
                /* 活过 20 秒才算连上: 短于 ssh 连接超时(10 秒)+建转发, 正在连、注定失败的会被误判成 up */
                if (now - x->since >= UP_AFTER) any_up = 1;
                snprintf(line, sizeof line, "%s %s\n", x->host, now - x->since >= UP_AFTER ? "up" : "connecting");
                sb_add(st, sizeof st, &sl, line);
                continue;
            }
            if (x->next && now < x->next) {                /* 刚失败过: 退避, 别拖慢其他中转 */
                snprintf(line, sizeof line, "%s down\n", x->host);
                sb_add(st, sizeof st, &sl, line);
                continue;
            }
            const char *av[40]; char dest[96], fwd[64];
            argv_kick(&c, kh, x, av, dest);
            int r = plat_run(av, kick, sizeof kick, 20);
            if (r >= 0 && kick[0]) {
                int a = trust_apply(kick);
                if (a < 0) cr_log("tun.log", "%s 发来的信任清单没应用(见 trust.log)", x->host);
                upgrade_check(kick, x->host, stop_all);    /* 有新版本: 换上并重启, 不会返回 */
            }
            argv_tun(&c, kh, x, av, dest, fwd);
            if (plat_spawn_bg(av, &x->p)) cr_log("tun.log", "起不来 %s", c.ssh);
            x->since = now; x->next = now + 30;
            snprintf(line, sizeof line, "%s connecting\n", x->host);
            sb_add(st, sizeof st, &sl, line);
        }
        for (int i = 0; i < nhubs; i++)                    /* 清单里没有了的中转: 断开 */
            if (!hubs[i].want && hubs[i].p.id) { plat_kill(&hubs[i].p); cr_log("tun.log", "中转 %s 已移出, 断开", hubs[i].host); }
        char sp[PATHLEN];
        pjoin(sp, "tun-status.txt");
        write_file(sp, st, sl);
        upgrade_trial_tick(any_up, started);
        {   /* 网络层(新旧并行): 只从此刻连着的中转取名单 */
            const char *alive[MAXHUBS]; int na = 0;
            for (int i = 0; i < nhubs; i++) if (hubs[i].want && plat_alive(&hubs[i].p) && now - hubs[i].since >= UP_AFTER) alive[na++] = hubs[i].host;
            meshd_tick(&c, alive, na);
        }
        if (now >= next_poll) {
            next_poll = now + 600 + (now % 120);           /* 每 10 分钟左右, 错开各客户机 */
            for (int i = 0; i < nhubs; i++) {
                if (!hubs[i].want || !plat_alive(&hubs[i].p)) continue;   /* 问正连着的中转 */
                if (http_get_text(hubs[i].host, c.http_port, "/pkg/client/release.txt", kick, sizeof kick) == 200) {
                    upgrade_check(kick, hubs[i].host, stop_all);   /* 有新版: 换上并重启, 不会返回 */
                    release_trust(kick, hubs[i].host);              /* 没有新版(或已是它): 取发布物带的信任清单 */
                    break;
                }
            }
        }
        plat_sleep(5);
    }
}
