/* 工程师登录(取代 engineer.ps1 / engineer.sh)
 * 手机验证器 6 位数 → 中转给这里现做的临时钥匙签 2 小时证书 → 取节点目录(验主钥匙签名) → 选机器 → 经中转 ssh 过去
 * 本机不存任何秘密: 验证码一次性、证书会过期, 退出时临时钥匙删掉 */
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define SEP "\\"
#else
#define SEP "/"
#endif

/* POST 公钥+验证码 → 证书 */
static int login_post(const char *host, const char *pub, const char *code, char *body, size_t cap)
{
    char payload[1024];
    snprintf(payload, sizeof payload, "%s\n%s\n", pub, code);
    conf_t c; conf_load(&c);
    return http_post(host, c.http_port, "/cgi-bin/login", payload, body, cap);
}

typedef struct { char host[64], port[8]; } ehub_t;
typedef struct { char alias[16], port[8], user[64], os[16], name[160]; int n; } node_t;

static int load_hubs(ehub_t *h)
{
    static char buf[16384];
    char p[PATHLEN];
    pjoin(p, "hubs.txt");
    if (read_file(p, buf, sizeof buf) < 0) return 0;
    char *cur = buf, *l;
    int n = 0;
    while ((l = next_line(&cur)) && n < MAXHUBS) {
        char hh[128], port[16], t[32];
        if (sscanf(l, "%127s %15s %31s", hh, port, t) != 3) continue;
        if (!valid_host(hh) || !all_digits(port, 5) || strcmp(t, "ssh-ed25519")) continue;
        strcpy(h[n].host, hh); strcpy(h[n].port, port); n++;
    }
    return n;
}

static int read_line(char *buf, size_t cap)
{
    if (!fgets(buf, (int)cap, stdin)) return -1;
    buf[strcspn(buf, "\r\n")] = 0;
    return 0;
}

static int node_cmp(const void *a, const void *b) { return ((const node_t *)a)->n - ((const node_t *)b)->n; }

int cmd_engineer(void)
{
#ifdef _WIN32
    if (!plat_is_admin()) return plat_elevate_self("engineer");   /* 安装目录只许管理员读 */
#endif
    conf_t c; conf_load(&c);
    ehub_t hubs[MAXHUBS];
    int nh = load_hubs(hubs);
    char line[256];
    if (!nh || c.dropbear) { out("这台机器还没接入\n回车退出"); read_line(line, sizeof line); return 1; }

    char W[PATHLEN], k[PATHLEN], kpub[PATHLEN], kcert[PATHLEN], cfg[PATHLEN], known[PATHLEN], hk[PATHLEN], kg[PATHLEN];
    if (plat_mkdtemp(W, sizeof W)) { out("建不了临时目录\n"); return 1; }
    snprintf(k, sizeof k, "%s" SEP "k", W);
    snprintf(kpub, sizeof kpub, "%s.pub", k);
    snprintf(kcert, sizeof kcert, "%s-cert.pub", k);
    snprintf(cfg, sizeof cfg, "%s" SEP "cfg", W);
    snprintf(known, sizeof known, "%s" SEP "known", W);
    pjoin(hk, "hubs_known");
    plat_keygen(c.ssh, kg, sizeof kg);
    int rc = 1;

    /* 0. 临时钥匙 */
    const char *kav[] = { kg, "-q", "-t", "ed25519", "-N", "", "-C", "engineer", "-f", k, NULL };
    char pub[512];
    if (plat_run(kav, NULL, 0, 30) != 0 || read_file(kpub, pub, sizeof pub) < 0) { out("生成临时钥匙失败\n"); goto done; }
    pub[strcspn(pub, "\r\n")] = 0;

    /* 1. 验证码 → 证书 */
    {
        static char cert[4096];
        int have = 0;
        for (int t = 0; t < 3 && !have; t++) {
            out("输入验证器 6 位数: ");
            if (read_line(line, sizeof line)) goto done;
            if (!(all_digits(line, 6) && strlen(line) == 6)) { out("验证码不对或已过期\n"); continue; }
            for (int i = 0; i < nh; i++) {
                int st = login_post(hubs[i].host, pub, line, cert, sizeof cert);
                if (st == 200 && !strncmp(cert, "ssh-ed25519-cert-v01@openssh.com ", 33)) { have = 1; break; }
                if (st == 403) break;                       /* 码不对: 再问别的中转只会浪费这次机会 */
            }
            if (!have) out("验证码不对或已过期\n");
        }
        if (!have) goto done;
        cert[strcspn(cert, "\r\n")] = 0;
        strcat(cert, "\n");
        if (write_file(kcert, cert, strlen(cert))) goto done;
    }

    /* 2. ssh 配置: 每台中转一个 Host, 中转主机钥匙用本机通道清单 */
    {
        static char cf[16384]; size_t cl = 0; cf[0] = 0;
        for (int i = 0; i < nh; i++) {
            char h[2048];
            snprintf(h, sizeof h,
                "Host hub%d\n  HostName %s\n  Port %s\n  User custhub\n  IdentityFile %s\n  CertificateFile %s\n"
                "  IdentitiesOnly yes\n  UserKnownHostsFile %s\n  StrictHostKeyChecking yes\n  BatchMode yes\n  ConnectTimeout 8\n  LogLevel ERROR\n",
                i + 1, hubs[i].host, hubs[i].port, k, kcert, hk);
            sb_add(cf, sizeof cf, &cl, h);
        }
        if (write_file(cfg, cf, cl)) goto done;
    }

    /* 3. 节点目录: 验主钥匙或中转 CA 证书的签名; 本机两样都不知道时照旧用, 但提示 */
    static bundle_t dir;
    static char raw[MAXBUF];
    int got = 0;
    {
        static uint8_t mk[MAXKEYS][32], ck[MAXKEYS][32];
        int nm0 = master_keys(mk, MAXKEYS), nc = ca_keys(ck, MAXKEYS), nm = nm0 + nc;
        for (int i = 0; i < nh && !got; i++) {
            char hn[16]; snprintf(hn, sizeof hn, "hub%d", i + 1);
            const char *av[] = { c.ssh, "-n", "-F", cfg, hn, "dir-get", NULL };
            if (plat_run(av, raw, sizeof raw, 30) != 0) continue;
            if (bundle_parse(raw, "custhub-dir v1", &dir)) continue;
            if (nm && !bundle_verify_ca(&dir, "custhub-dir", mk, nm0, ck, nc)) { out("中转 %s 给的节点目录验签没过, 换下一台\n", hubs[i].host); continue; }
            got = 1;
            if (!nm) out("(本机还没有主公钥/CA, 节点目录未验签)\n");
        }
    }
    if (!got) { out("连不上中转\n"); goto done; }

    static node_t nodes[512];
    int nn = 0;
    {
        static char d[MAXBUF];
        memcpy(d, dir.data, dir.dlen + 1);
        char *cur = d, *l;
        while ((l = next_line(&cur)) && nn < 512) {
            node_t *x = &nodes[nn];
            char b64[256];
            if (sscanf(l, "node %15s %7s %63s %15s %255s", x->alias, x->port, x->user, x->os, b64) != 5) continue;
            if (strncmp(x->alias, "c-", 2) || !all_digits(x->alias + 2, 5) || !all_digits(x->port, 5)) continue;
            long bl = b64_decode(b64, strlen(b64), (uint8_t *)x->name, sizeof x->name - 1);
            x->name[bl > 0 ? bl : 0] = 0;
            x->n = atoi(x->alias + 2);
            nn++;
        }
        qsort(nodes, (size_t)nn, sizeof *nodes, node_cmp);
    }

    /* 4. 选机器 → 连接 */
    for (;;) {
        static char up[MAXBUF];
        int uphub[512] = { 0 };
        for (int i = 0; i < nh; i++) {
            char hn[16]; snprintf(hn, sizeof hn, "hub%d", i + 1);
            const char *av[] = { c.ssh, "-n", "-F", cfg, hn, "tun-list", NULL };
            if (plat_run(av, up, sizeof up, 20) != 0) continue;
            char *cur = up, *l;
            while ((l = next_line(&cur))) {               /* 名字 \t 回拨口 \t 在线(1) */
                char *t1 = strchr(l, '\t'); if (!t1) continue;
                char *t2 = strchr(t1 + 1, '\t'); if (!t2) continue;
                *t2 = 0;
                if (strncmp(t2 + 1, "1", 1)) continue;
                for (int j = 0; j < nn; j++) if (!uphub[j] && !strcmp(nodes[j].port, t1 + 1)) uphub[j] = i + 1;
            }
        }
        out("\n");
        for (int j = 0; j < nn; j++)
            out("  %-6s %-6s %s%s\n", nodes[j].alias, nodes[j].os, nodes[j].name, uphub[j] ? "" : "  (不在线)");
        out("\n选择要连的机器编号 (c-N, 回车退出): ");
        if (read_line(line, sizeof line) || !line[0]) break;
        const char *pk = line;
        if (!strncmp(pk, "c-", 2)) pk += 2;
        int j;
        for (j = 0; j < nn; j++) if (all_digits(pk, 5) && nodes[j].n == atoi(pk)) break;
        if (j == nn) { out("没有 c-%s\n", pk); continue; }
        if (!uphub[j]) { out("不在线\n"); continue; }
        char pj[32], ha[48], kf[PATHLEN + 32], idf[PATHLEN + 32], cf2[PATHLEN + 32], dest[96];
        snprintf(pj, sizeof pj, "ProxyJump=hub%d", uphub[j]);
        snprintf(ha, sizeof ha, "HostKeyAlias=%s", nodes[j].alias);
        snprintf(kf, sizeof kf, "UserKnownHostsFile=%s", known);
        snprintf(idf, sizeof idf, "IdentityFile=%s", k);
        snprintf(cf2, sizeof cf2, "CertificateFile=%s", kcert);
        snprintf(dest, sizeof dest, "%s@127.0.0.1", nodes[j].user);
        const char *av[] = { c.ssh, "-F", cfg, "-o", pj, "-o", ha, "-o", kf, "-o", "StrictHostKeyChecking=accept-new",
                             "-o", idf, "-o", cf2, "-o", "IdentitiesOnly=yes", "-p", nodes[j].port, dest, NULL };
        plat_run_tty(av);
    }
    rc = 0;
done:
    plat_rmtmp(W);
    out("已退出, 临时钥匙已删除\n");
    return rc;
}
