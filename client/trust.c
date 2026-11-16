/* 信任清单(SPEC §3): 从中转顺带发来的文本里截出 → 用本机已信任的钥匙验签 → 只改带 custhub-trust: 标记的行
 * 行为与 trust-apply.sh / trust-apply.ps1 一致:
 *   验签钥匙 = authorized_keys 里旧管理钥匙(注释 cust-remote) 或主钥匙(custhub-trust:master), 不认 cert-authority 行
 *   旧管理钥匙永远不动 → 清单再错也不会把我们锁在外面; 版本号只升不降 */
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FROM "from=\"127.0.0.1,::1\""

int bundle_parse(const char *text, const char *head, bundle_t *b)
{
    static char w[MAXBUF];
    size_t n = strlen(text), sl = 0;
    if (n >= MAXBUF) return -1;
    memcpy(w, text, n + 1);
    char *cur = w, *l;
    int state = 0, done = 0;
    b->dlen = 0; b->nsig = 0; b->data[0] = 0;
    while ((l = next_line(&cur))) {
        if (!strcmp(l, head)) { state = 1; b->dlen = 0; b->nsig = 0; }   /* 以最后一份为准 */
        if (!state) continue;
        if (!strcmp(l, "--end--")) { done = 1; break; }
        if (strlen(l) >= MAXLINE) return -1;
        if (!strcmp(l, "--sig--")) {
            if (b->nsig >= MAXSIG) return -1;
            b->sig[b->nsig++][0] = 0; sl = 0; state = 2;
            continue;
        }
        if (state == 1) {
            if (sb_add(b->data, sizeof b->data, &b->dlen, l) || sb_add(b->data, sizeof b->data, &b->dlen, "\n")) return -1;
        } else {
            char *s = b->sig[b->nsig - 1];
            if (sb_add(s, sizeof b->sig[0], &sl, l) || sb_add(s, sizeof b->sig[0], &sl, "\n")) return -1;
        }
    }
    return (done && b->dlen && b->nsig) ? 0 : -1;
}

int bundle_verify(const bundle_t *b, const char *ns, uint8_t (*keys)[32], int nkeys)
{
    for (int i = 0; i < b->nsig; i++)
        if (sshsig_verify(b->sig[i], (const uint8_t *)b->data, b->dlen, ns, keys, nkeys)) return 1;
    return 0;
}

static int add_key(uint8_t (*keys)[32], int n, int max, const char *line)
{
    char b64[128]; uint8_t pub[32];
    if (n >= max || find_ed25519(line, b64, sizeof b64) || pub_from_b64(b64, pub)) return n;
    for (int i = 0; i < n; i++) if (!memcmp(keys[i], pub, 32)) return n;
    memcpy(keys[n], pub, 32);
    return n + 1;
}

/* 本机要维护的 authorized_keys = 现在含旧管理钥匙或信任标记的那些(运行时找, 不写死账号) */
static int ak_targets(char (*t)[512])
{
    static char buf[MAXBUF];
    char cand[MAXAK][512];
    int n = plat_ak_files(cand, MAXAK), k = 0;
    for (int i = 0; i < n; i++) {
        if (read_file(cand[i], buf, sizeof buf) < 0) continue;
        if (strstr(buf, OLDKEY) || strstr(buf, MARK ":")) strcpy(t[k++], cand[i]);
    }
    return k;
}

/* only_master: 只要主钥匙(节点目录只由主钥匙签) */
static int keys_from_ak(char (*t)[512], int nt, uint8_t (*keys)[32], int max, int only_master)
{
    static char buf[MAXBUF];
    int n = 0;
    for (int i = 0; i < nt; i++) {
        if (read_file(t[i], buf, sizeof buf) < 0) continue;
        char *cur = buf, *l;
        while ((l = next_line(&cur))) {
            if (strstr(l, "cert-authority")) continue;
            if (strstr(l, MARK ":master") || (!only_master && strstr(l, OLDKEY)))
                n = add_key(keys, n, max, l);
        }
    }
    return n;
}

int master_keys(uint8_t (*keys)[32], int max)
{
    char p[PATHLEN], buf[4096];
    int n = 0;
    pjoin(p, "master.pub");
    if (read_file(p, buf, sizeof buf) >= 0) {
        char *cur = buf, *l;
        while ((l = next_line(&cur))) n = add_key(keys, n, max, l);
    }
    if (n) return n;
    char t[MAXAK][512];
    int nt = ak_targets(t);
    return keys_from_ak(t, nt, keys, max, 1);
}

/* "key|ca ssh-ed25519 <68 base64> custhub-trust:<名字>" */
static int valid_entry(const char *l, int *is_ca, char *key, size_t cap)
{
    const char *p;
    if (!strncmp(l, "key ", 4)) { *is_ca = 0; p = l + 4; }
    else if (!strncmp(l, "ca ", 3)) { *is_ca = 1; p = l + 3; }
    else return 0;
    if (strncmp(p, "ssh-ed25519 ", 12)) return 0;
    char b64[69];
    memcpy(b64, p + 12, 68); b64[68] = 0;
    if (strlen(p + 12) < 68 + 1 + sizeof MARK || !valid_b64_key(b64) || strchr(b64, '=')) return 0;
    const char *tag = p + 12 + 68;
    if (strncmp(tag, " " MARK ":", sizeof MARK + 1)) return 0;
    const char *nm = tag + sizeof MARK + 1;
    size_t nl = strlen(nm);
    if (nl < 1 || nl > 32) return 0;
    for (size_t i = 0; i < nl; i++)
        if (!((nm[i] >= 'a' && nm[i] <= 'z') || (nm[i] >= '0' && nm[i] <= '9') || nm[i] == '-')) return 0;
    if (strlen(p) >= cap) return 0;
    strcpy(key, p);
    return 1;
}

typedef struct { int ca; char k[160]; } ent_t;

static int rewrite(const char *path, ent_t *e, int ne)
{
    static char buf[MAXBUF], nw[MAXBUF];
    size_t len = 0;
    if (read_file(path, buf, sizeof buf) < 0) return -1;
    int mode = plat_ak_mode(path);
    char *cur = buf, *l;
    while ((l = next_line(&cur))) {
        if (!*l || strstr(l, MARK ":")) continue;
        if (sb_add(nw, sizeof nw, &len, l) || sb_add(nw, sizeof nw, &len, "\n")) return -1;
    }
    for (int i = 0; i < ne; i++) {
        char line[MAXLINE];
        if (!e[i].ca) {
            if (mode == AK_SSHD) snprintf(line, sizeof line, FROM " %s\n", e[i].k);
            else snprintf(line, sizeof line, "%s\n", e[i].k);
        } else {
            if (mode == AK_DROPBEAR) continue;                     /* dropbear 不认证书 */
            if (mode == AK_WIN) snprintf(line, sizeof line, "cert-authority %s\n", e[i].k);
            else snprintf(line, sizeof line, "cert-authority," FROM " %s\n", e[i].k);
        }
        if (sb_add(nw, sizeof nw, &len, line)) return -1;
    }
    if (write_file(path, nw, len)) return -1;
    plat_after_ak(path);
    return 0;
}

int trust_apply(const char *text)
{
    static bundle_t b;
    static char d[MAXBUF];
    char p[PATHLEN], vb[32];
    if (bundle_parse(text, "custhub-trust-bundle v1", &b)) return 0;

    memcpy(d, b.data, b.dlen + 1);
    char *cur = d, *l;
    next_line(&cur);
    l = next_line(&cur);
    if (!l || strncmp(l, "version ", 8) || !all_digits(l + 8, 12)) return 0;
    long long v = atoll(l + 8), ov = 0;
    pjoin(p, "trust.ver");
    if (read_file(p, vb, sizeof vb) > 0) { vb[strcspn(vb, "\r\n")] = 0; if (all_digits(vb, 12)) ov = atoll(vb); }
    if (v <= ov) return 0;

    char t[MAXAK][512];
    int nt = ak_targets(t);
    if (!nt) { cr_log("trust.log", "版本 %lld: 本机没有要维护的 authorized_keys, 不应用", v); return 0; }

    uint8_t keys[MAXKEYS][32];
    int nk = keys_from_ak(t, nt, keys, MAXKEYS, 0);
    if (!bundle_verify(&b, MARK, keys, nk)) {
        cr_log("trust.log", "版本 %lld 验签没过, 不应用", v);
        return -1;
    }

    static ent_t e[MAXKEYS];
    int ne = 0;
    char master[MAXBUF / 4]; size_t ml = 0; master[0] = 0;
    while ((l = next_line(&cur)) && ne < MAXKEYS) {
        if (!valid_entry(l, &e[ne].ca, e[ne].k, sizeof e[ne].k)) continue;
        if (!e[ne].ca && strstr(e[ne].k, " " MARK ":master") && ml + strlen(e[ne].k) + 2 < sizeof master) {
            sb_add(master, sizeof master, &ml, e[ne].k); sb_add(master, sizeof master, &ml, "\n");
        }
        ne++;
    }
    int ok = 0;
    for (int i = 0; i < nt; i++) {
        if (rewrite(t[i], e, ne)) cr_log("trust.log", "版本 %lld: 写 %s 失败", v, t[i]);
        else ok++;
    }
    if (!ok) return -1;
    snprintf(vb, sizeof vb, "%lld\n", v);
    write_file(p, vb, strlen(vb));
    if (ml) { pjoin(p, "master.pub"); write_file(p, master, ml); }   /* 给工程师登录验节点目录用(普通用户读不到 root 的 authorized_keys) */
    cr_log("trust.log", "已应用信任清单版本 %lld (%d 条) → %d 份 authorized_keys", v, ne, ok);
    return 1;
}
