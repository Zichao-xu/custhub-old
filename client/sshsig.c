/* ssh-keygen -Y sign 签名格式(OpenSSH PROTOCOL.sshsig) 的校验; 只认 ed25519 + sha512
 * 签名钥匙两种: 本机信任的公钥本身, 或中转 CA 签发的 ed25519 用户证书(验证器 6 位数换来的 2 小时证书;
 *   ssh-keygen -Y sign -f 证书.pub 时签名里带的是整张证书, 格式见 OpenSSH PROTOCOL.certkeys)
 *   证书要求: CA 在本机信任里、CA 签名对、用户证书、没有 critical options、有效期不超过 1 天、
 *   被签内容里的 "signed <时间>" 落在有效期内(客户机可能离线很久才取到, 所以不拿"现在"比; 中转拉取时按现在比)
 * 算法全部来自 Monocypher(含可选的 ed25519/sha512 模块, 与 OpenSSH 的 ed25519 兼容) */
#include "cr.h"
#include "vendor/monocypher.h"
#include "vendor/monocypher-ed25519.h"
#include <string.h>

typedef struct { const uint8_t *p; size_t n; } rd_t;

static int rd_u32(rd_t *r, uint32_t *v)
{
    if (r->n < 4) return -1;
    *v = ((uint32_t)r->p[0] << 24) | ((uint32_t)r->p[1] << 16) | ((uint32_t)r->p[2] << 8) | r->p[3];
    r->p += 4; r->n -= 4;
    return 0;
}

static int rd_u64(rd_t *r, uint64_t *v)
{
    uint32_t hi, lo;
    if (rd_u32(r, &hi) || rd_u32(r, &lo)) return -1;
    *v = ((uint64_t)hi << 32) | lo;
    return 0;
}

static int rd_str(rd_t *r, const uint8_t **s, size_t *len)
{
    uint32_t l;
    if (rd_u32(r, &l) || l > r->n) return -1;
    *s = r->p; *len = l;
    r->p += l; r->n -= l;
    return 0;
}

static int is(const uint8_t *s, size_t n, const char *lit)
{
    return n == strlen(lit) && memcmp(s, lit, n) == 0;
}

static void put_str(uint8_t *b, size_t *o, const void *s, size_t n)
{
    b[(*o)++] = (uint8_t)(n >> 24); b[(*o)++] = (uint8_t)(n >> 16);
    b[(*o)++] = (uint8_t)(n >> 8);  b[(*o)++] = (uint8_t)n;
    memcpy(b + *o, s, n); *o += n;
}

#define BEGIN "-----BEGIN SSH SIGNATURE-----"
#define END   "-----END SSH SIGNATURE-----"

#define CERT_T   "ssh-ed25519-cert-v01@openssh.com"
#define CERT_MAX (86400 + 600)                /* 证书有效期上限: 验证器证书是 2 小时 */

/* 证书 → 被认证的公钥(32 字节); 不合格返回 -1 */
static int cert_key(const uint8_t *c, size_t cl, uint8_t (*cas)[32], int ncas, long long signed_at, const uint8_t **out)
{
    rd_t r = { c, cl };
    const uint8_t *t, *nonce, *pk, *kid, *prin, *crit, *ext, *res, *sk, *sig;
    size_t tl, nl, pkl, kidl, prinl, critl, extl, resl, skl, sigl;
    uint64_t serial, va, vb; uint32_t type;
    if (rd_str(&r, &t, &tl) || !is(t, tl, CERT_T)) return -1;
    if (rd_str(&r, &nonce, &nl) || rd_str(&r, &pk, &pkl) || pkl != 32 || rd_u64(&r, &serial) || rd_u32(&r, &type) ||
        rd_str(&r, &kid, &kidl) || rd_str(&r, &prin, &prinl) || rd_u64(&r, &va) || rd_u64(&r, &vb) ||
        rd_str(&r, &crit, &critl) || rd_str(&r, &ext, &extl) || rd_str(&r, &res, &resl)) return -1;
    if (rd_str(&r, &sk, &skl)) return -1;
    size_t body = (size_t)(r.p - c);                       /* CA 签的是从头到 signature key(含)为止 */
    if (rd_str(&r, &sig, &sigl) || r.n) return -1;
    if (type != 1 || critl != 0) return -1;                /* 只认用户证书, 不认带限制条件的 */
    if (signed_at <= 0 || va > vb || vb - va > CERT_MAX || (uint64_t)signed_at < va || (uint64_t)signed_at >= vb) return -1;
    rd_t k = { sk, skl };
    const uint8_t *kt, *kd; size_t ktl, kdl;
    if (rd_str(&k, &kt, &ktl) || rd_str(&k, &kd, &kdl) || k.n || !is(kt, ktl, "ssh-ed25519") || kdl != 32) return -1;
    int known = 0;
    for (int i = 0; i < ncas && !known; i++) known = memcmp(cas[i], kd, 32) == 0;
    if (!known) return -1;
    rd_t s = { sig, sigl };
    const uint8_t *st, *sd; size_t stl, sdl;
    if (rd_str(&s, &st, &stl) || rd_str(&s, &sd, &sdl) || s.n || !is(st, stl, "ssh-ed25519") || sdl != 64) return -1;
    if (crypto_ed25519_check(sd, kd, c, body)) return -1;
    *out = pk;
    return 0;
}

int sshsig_verify(const char *arm, const uint8_t *msg, size_t mlen,
                  const char *ns, uint8_t (*keys)[32], int nkeys)
{
    return sshsig_verify_ca(arm, msg, mlen, ns, keys, nkeys, NULL, 0, 0);
}

int sshsig_verify_ca(const char *arm, const uint8_t *msg, size_t mlen, const char *ns,
                     uint8_t (*keys)[32], int nkeys, uint8_t (*cas)[32], int ncas, long long signed_at)
{
    const char *b = strstr(arm, BEGIN), *e = strstr(arm, END);
    if (!b || !e || e < b) return 0;
    b += strlen(BEGIN);

    uint8_t blob[2048];
    long bl = b64_decode(b, (size_t)(e - b), blob, sizeof blob);
    if (bl < 10 || memcmp(blob, "SSHSIG", 6) != 0) return 0;
    rd_t r = { blob + 6, (size_t)bl - 6 };

    uint32_t ver;
    const uint8_t *pk, *sns, *res, *halg, *sig;
    size_t pkl, snsl, resl, halgl, sigl;
    if (rd_u32(&r, &ver) || ver != 1) return 0;
    if (rd_str(&r, &pk, &pkl) || rd_str(&r, &sns, &snsl) || rd_str(&r, &res, &resl) ||
        rd_str(&r, &halg, &halgl) || rd_str(&r, &sig, &sigl) || r.n != 0) return 0;
    if (!is(sns, snsl, ns) || !is(halg, halgl, "sha512") || resl > 256) return 0;

    /* 公钥: string "ssh-ed25519" + string(32), 或一张证书 */
    rd_t k = { pk, pkl };
    const uint8_t *kt, *kd; size_t ktl, kdl;
    if (rd_str(&k, &kt, &ktl)) return 0;
    int by_cert = 0;
    if (is(kt, ktl, CERT_T)) {
        if (!ncas || cert_key(pk, pkl, cas, ncas, signed_at, &kd)) return 0;
        by_cert = 1;
    } else if (rd_str(&k, &kd, &kdl) || k.n || !is(kt, ktl, "ssh-ed25519") || kdl != 32) return 0;

    /* 签名: string "ssh-ed25519" + string(64) */
    rd_t s = { sig, sigl };
    const uint8_t *st, *sd; size_t stl, sdl;
    if (rd_str(&s, &st, &stl) || rd_str(&s, &sd, &sdl) || s.n || !is(st, stl, "ssh-ed25519") || sdl != 64) return 0;

    int known = by_cert;
    for (int i = 0; i < nkeys && !known; i++) known = memcmp(keys[i], kd, 32) == 0;
    if (!known) return 0;

    /* 被签的内容: "SSHSIG" || string(命名空间) || string(保留) || string("sha512") || string(SHA512(消息)) */
    uint8_t h[64], tbs[6 + 4 + 64 + 4 + 256 + 4 + 6 + 4 + 64];
    size_t o = 0;
    if (snsl > 64) return 0;
    crypto_sha512(h, msg, mlen);
    memcpy(tbs, "SSHSIG", 6); o = 6;
    put_str(tbs, &o, sns, snsl);
    put_str(tbs, &o, res, resl);
    put_str(tbs, &o, "sha512", 6);
    put_str(tbs, &o, h, 64);
    return crypto_ed25519_check(sd, kd, tbs, o) == 0;
}
