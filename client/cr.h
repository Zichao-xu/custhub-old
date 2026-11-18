/* custhub 客户机程序 · 公共定义(SPEC §6)
 * 程序名 custhub; 安装目录、服务名、互斥锁沿用旧部署的 cust-remote / cust-tun 等, 以便原地接管
 * 一个程序取代各平台脚本: 通道守护 / 信任清单验签应用 / 工程师登录
 * 输入一律按定长缓冲解析, 超长即拒; 密码学只调 Monocypher, SSH 只调系统 ssh/dbclient */
#ifndef CR_H
#define CR_H
#include <stddef.h>
#include <stdint.h>

#ifndef CR_VERSION                       /* 测试可用 -DCR_VERSION 覆盖 */
#define CR_VERSION "0.2.2"
#endif
#define MARK       "custhub-trust"
#define OLDKEY     "cust-remote"          /* 旧管理钥匙注释(过渡期仍认它验签) */
#define MAXLINE    1024
#define MAXBUF     (64 * 1024)            /* 清单/目录/kick 输出上限 */
#define MAXHUBS    16
#define MAXKEYS    64
#define MAXAK      16                     /* 一台机器上要维护的 authorized_keys 份数 */
#define MAXSIG     4
#define PATHLEN    512

/* ---------- util.c ---------- */
extern char g_dir[PATHLEN];                     /* 本机安装目录 */
void   cr_init_dir(void);
void   pjoin(char *out, const char *name);      /* out = g_dir/name (out 至少 PATHLEN) */
void   cr_log(const char *file, const char *fmt, ...);
long   read_file(const char *path, char *buf, size_t cap);   /* 读整份并补 NUL; 不存在 -1, 超长 -2 */
int    write_file(const char *path, const char *data, size_t len);  /* 写临时文件再换上 */
long   b64_decode(const char *in, size_t inlen, uint8_t *out, size_t cap);
char  *next_line(char **cur);                   /* 原地切行, 去掉 \r; 没有了返回 NULL */
int    sb_add(char *buf, size_t cap, size_t *len, const char *s);   /* 追加, 超长返回 -1 */
int    pub_from_b64(const char *b64, uint8_t pub[32]);               /* ssh-ed25519 线格式公钥 → 32 字节 */
int    find_ed25519(const char *line, char *b64, size_t cap);        /* 行里找 "ssh-ed25519 BASE64" */
int    valid_host(const char *s);
int    all_digits(const char *s, size_t maxlen);
int    valid_b64_key(const char *s);          /* ssh-ed25519 公钥 base64(68 字符) */

/* ---------- sshsig.c ---------- */
/* 校验 ssh-keygen -Y sign 的签名(只认 ed25519 + sha512); keys 里任一把签的即通过 */
int sshsig_verify_ca(const char *armored, const uint8_t *msg, size_t mlen, const char *ns,
                     uint8_t (*keys)[32], int nkeys, uint8_t (*cas)[32], int ncas, long long signed_at);
                                         /* 也认 cas 里的 CA 签发的证书; signed_at = 被签内容里 "signed" 行的时间 */
int sshsig_verify(const char *armored, const uint8_t *msg, size_t mlen,
                  const char *ns, uint8_t (*keys)[32], int nkeys);

/* ---------- trust.c ---------- */
typedef struct {
    char   data[MAXBUF];        /* 被签名的那一段(每行带 \n) */
    size_t dlen;
    char   sig[MAXSIG][3072];
    int    nsig;
} bundle_t;
/* 从一段文本里截出签名文件: 从 head 行开始, 到 --end-- 为止; 没有 --end-- 视为残缺 */
int  bundle_parse(const char *text, const char *head, bundle_t *b);
int  bundle_verify(const bundle_t *b, const char *ns, uint8_t (*keys)[32], int nkeys);
int  trust_apply(const char *text);             /* 1 已应用 / 0 无需应用 / -1 出错 */
int  master_keys(uint8_t (*keys)[32], int max); /* 本机已知的主公钥(master.pub, 不够再读 authorized_keys) */
int  ca_keys(uint8_t (*keys)[32], int max);     /* 本机信任的中转 CA(ca.pub, 不够再读 authorized_keys 的 cert-authority 行) */
int  bundle_verify_ca(const bundle_t *b, const char *ns, uint8_t (*keys)[32], int nkeys, uint8_t (*cas)[32], int ncas);

/* ---------- http.c ---------- */
void http_init(void);
int  http_post(const char *host, const char *port, const char *path, const char *payload, char *out, size_t cap);
int  http_get_text(const char *host, const char *port, const char *path, char *out, size_t cap);
int  http_get_file(const char *host, const char *port, const char *path, const char *dst, long maxsize, long *size);

/* ---------- tun.c / engineer.c ---------- */
int cmd_tun(int argc, char **argv);
int cmd_engineer(void);
int cmd_mesh(int argc, char **argv);    /* ../mesh: 网络层(design-v3) */

/* ---------- upgrade.c: 自升级(SPEC §6) ---------- */
#ifndef CR_PLAT
#define CR_PLAT "dev"                    /* 本机开发版: 没有对应发布物, 永不自升级 */
#endif
long ver_num(const char *v);             /* "a.b.c" → 可比较的整数; 格式不对 -1 */
void upgrade_trial_start(void (*stop_children)(void));   /* tun 启动时: 处在试用期就计次, 次数超了回滚 */
void upgrade_trial_tick(int any_up, long started);   /* 守护循环里: 有通道 → 转正; 超时 → 回滚 */
void upgrade_check(const char *kick, const char *host, void (*stop_children)(void));
                                         /* kick 输出里有更新版本的签名发布清单 → 下载、核对、换上、重启 */
int  cmd_upgrade_file(const char *manifest, const char *bin);
void release_trust(const char *release_text, const char *host);   /* 发布物里带的信任清单(custhub-<版本>-trust) */   /* 手动: 用本地清单+二进制升级(测试/救急) */

/* ---------- install.c: 服务注册(SPEC §6) ---------- */
int cmd_install(int argc, char **argv);
int install_copy_self(void);             /* 把本程序复制成 $D/custhub[.exe](已在那就不动) */
int service_setup(void);                 /* 立即写好并启动通道守护服务(接入时用; install 走后台那套) */
int service_had_prior(void);             /* 有旧守护可回退 */
void service_restore(void);              /* 恢复切换前的服务定义并启动旧守护 */
int cmd_join(int argc, char **argv);     /* join.c */
int cmd_remove(int argc, char **argv);
int cmd_install_finish(void);
int cmd_uninstall(void);

/* ---------- 配置(client.conf, 一行一项 "键 值") ---------- */
typedef struct {
    char port[16];              /* 本机在中转上的回拨口 */
    char sshport[16];           /* 本机 sshd 端口 */
    char ssh[PATHLEN];          /* ssh 或 dbclient */
    char key[PATHLEN];          /* 通道钥匙 */
    char http_port[8];          /* 中转 http 端口(工程师登录、下载发布物) */
    int  dropbear;
} conf_t;
int conf_load(conf_t *c);
void meshd_tick(const conf_t *c, const char *const *alive, int nalive);   /* meshd.c: 守护带起网络层 */
void meshd_stop(void);

#endif
