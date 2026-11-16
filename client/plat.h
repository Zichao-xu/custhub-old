/* 平台层: 进程、文件替换、控制台; posix.c / win.c 各实现一份 */
#ifndef PLAT_H
#define PLAT_H
#include <stddef.h>
#include <stdint.h>

typedef struct { intptr_t id; } proc_t;   /* posix: pid; Windows: 进程句柄 */

int  plat_spawn_bg(const char *const *argv, proc_t *p);        /* 后台起, 标准输入输出全接空 */
int  plat_run(const char *const *argv, char *out, size_t cap, int timeout_s);
                                                               /* 跑完收 stdout(可 NULL); 返回退出码, -1 起不来, -2 超时 */
int  plat_run_in(const char *const *argv, const char *in, size_t inlen, char *out, size_t cap, int timeout_s);
                                                               /* 同 plat_run, 另把 in 喂给子进程 stdin */
int  plat_run_tty(const char *const *argv);                    /* 前台交互跑(继承终端) */
int  plat_alive(proc_t *p);
void plat_kill(proc_t *p);
void plat_sleep(int s);
long plat_now(void);
int  plat_mkdtemp(char *out, size_t cap);
void plat_rmtmp(const char *dir);                              /* 删掉平铺的临时目录 */
int  plat_single_instance(const char *name);                   /* 已有一个在跑返回 0 */
void plat_setenv(const char *k, const char *v);
void plat_console_init(void);
void out(const char *fmt, ...);                                /* 控制台输出(UTF-8 安全) */
int  plat_ak_files(char (*paths)[512], int max);               /* 候选 authorized_keys(未过滤) */
int  plat_ak_mode(const char *path);                           /* AK_* */
int  plat_replace(const char *tmp, const char *dst);           /* 换上新文件, 保留属主/权限 */
void plat_after_ak(const char *path);                          /* Windows: 收紧 ACL */
void plat_default_ssh(char *out, size_t cap);
void plat_keygen(const char *ssh, char *out, size_t cap);
int  plat_is_dir(const char *path);
int  plat_is_file(const char *path);
void plat_on_term(void (*fn)(void));
int  plat_self_path(char *out, size_t cap);                     /* 本程序的完整路径 */
int  plat_spawn_detached(const char *const *argv);              /* 脱离本进程/会话独立运行(不进我们的作业, 不随终端断开) */
void plat_restart_self(const char *exe, const char *const *argv);
                                                               /* 换成 exe 继续跑: posix 原地 exec; Windows 起新进程后退出; 只在失败时返回 */
int  plat_single_instance_wait(const char *name, int secs);    /* 等旧实例让出锁(升级接班用) */
int  plat_is_admin(void);
int  plat_mkdir(const char *path);
void plat_make_exec(const char *path);
void plat_secure_key(const char *path);
int  plat_elevate_self(const char *args);                      /* Windows: 以管理员重开自己(弹 UAC) */                        /* 私钥文件: 只许 root / SYSTEM+管理员组 */

#ifdef _WIN32
#define EXE ".exe"
#else
#define EXE ""
#endif

enum { AK_SSHD, AK_OPEN, AK_WIN, AK_DROPBEAR };

#endif
