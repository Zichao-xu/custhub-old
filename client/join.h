/* 接入(join) / 卸载(remove) 内部接口 */
#ifndef JOIN_H
#define JOIN_H
#include "cr.h"

#ifdef _WIN32
#define SEPC '\\'
#else
#define SEPC '/'
#endif

#define MAXPKG 32
enum { OS_WIN = 1, OS_MAC, OS_LINUX, OS_OPENWRT };

typedef struct { char key[48], file[160], sha[129]; } pkg_t;

typedef struct {
    char url[256];
    char host[64], port[8];      /* 下发中转 */
    char token[72];
    char tunport[8];
    int  silent, keep_tun, os;
    char pubkey[256];            /* 管理钥匙行 */
    char repkey[2048];           /* 回报一次性钥匙(base64 的私钥文件) */
    char hubs[4096];             /* hubs.txt 内容 */
    char cleanup[12288];         /* Windows「清理弹窗广告」脚本(base64, ③ 运维工具换成 C 之前的过渡) */
    pkg_t pkg[MAXPKG];
    int  npkg;
} job_t;

extern job_t J;

void say(const char *fmt, ...);
void rep(const char *step, const char *msg, const char *extra, int tries, const char *uh);
void ok(const char *step, const char *fmt, ...);
void doing(const char *fmt, ...);
void warn(const char *fmt, ...);
void jfail(const char *fmt, ...);
const char *get_pkg(const char *key, char *out, size_t cap);
void st_set(const char *k, const char *v);
int  st_get(const char *k, char *v, size_t cap);
void write_tunnel_files(const char *ssh_path);
void report_tunkey(const char *pubkey_line);
int  wait_link(int secs);
void link_or_rollback(int secs);
void legacy_cleanup(void);
void report_done(const char *user, const char *host);

/* 各平台实现 */
int  join_platform(int argc, char **argv);
void join_diag(char *out, size_t cap);          /* 失败时随日志回传的现场 */
void join_finish(int ok);                       /* 收尾(Windows: 窗口可见时停一下) */

#endif
