/* 平台层 · macOS / Linux / OpenWrt */
#ifndef _WIN32
#define _GNU_SOURCE
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <glob.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/select.h>

static void child_fds(int outfd)
{
    int nul = open("/dev/null", O_RDWR);
    dup2(nul, 0);
    dup2(outfd >= 0 ? outfd : nul, 1);
    dup2(nul, 2);
    if (nul > 2) close(nul);
    signal(SIGPIPE, SIG_DFL); signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGCHLD, SIG_DFL);
}

int plat_spawn_bg(const char *const *argv, proc_t *p)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { child_fds(-1); execvp(argv[0], (char *const *)argv); _exit(127); }
    p->id = pid;
    return 0;
}

int plat_run(const char *const *argv, char *out, size_t cap, int timeout_s)
{
    return plat_run_in(argv, NULL, 0, out, cap, timeout_s);
}

int plat_run_in(const char *const *argv, const char *in, size_t inlen, char *out, size_t cap, int timeout_s)
{
    int fd[2], ifd[2] = { -1, -1 };
    if (pipe(fd)) return -1;
    if (in && pipe(ifd)) { close(fd[0]); close(fd[1]); return -1; }
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); if (in) { close(ifd[0]); close(ifd[1]); } return -1; }
    if (pid == 0) {
        close(fd[0]); child_fds(fd[1]);
        if (in) { close(ifd[1]); dup2(ifd[0], 0); close(ifd[0]); }
        execvp(argv[0], (char *const *)argv); _exit(127);
    }
    close(fd[1]);
    if (in) {                                             /* 输入都很小(回报正文), 一次写完再收输出 */
        close(ifd[0]);
        signal(SIGPIPE, SIG_IGN);
        size_t o = 0;
        while (o < inlen) { ssize_t k = write(ifd[1], in + o, inlen - o); if (k <= 0) break; o += (size_t)k; }
        close(ifd[1]);
    }
    size_t n = 0; int timed = 0;
    time_t end = time(NULL) + timeout_s;
    for (;;) {
        long left = (long)(end - time(NULL));
        if (left <= 0) { timed = 1; break; }
        fd_set rs; FD_ZERO(&rs); FD_SET(fd[0], &rs);
        struct timeval tv = { left, 0 };
        int r = select(fd[0] + 1, &rs, NULL, NULL, &tv);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { timed = 1; break; }
        char tmp[4096];
        ssize_t k = read(fd[0], tmp, sizeof tmp);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        if (out && n + 1 < cap) {
            size_t c = (size_t)k < cap - 1 - n ? (size_t)k : cap - 1 - n;
            memcpy(out + n, tmp, c); n += c;
        }
    }
    close(fd[0]);
    if (out) out[n] = 0;
    if (timed) kill(pid, SIGKILL);
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (timed) return -2;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int plat_run_tty(const char *const *argv)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { signal(SIGINT, SIG_DFL); execvp(argv[0], (char *const *)argv); _exit(127); }
    void (*old)(int) = signal(SIGINT, SIG_IGN);           /* Ctrl-C 给 ssh, 别把我们自己杀了 */
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    signal(SIGINT, old);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int plat_alive(proc_t *p)
{
    if (p->id <= 0) return 0;
    int st;
    pid_t r = waitpid((pid_t)p->id, &st, WNOHANG);
    if (r == 0) return 1;
    p->id = 0;
    return 0;
}

void plat_kill(proc_t *p)
{
    if (p->id <= 0) return;
    kill((pid_t)p->id, SIGTERM);
    for (int i = 0; i < 20; i++) {                        /* 最多等 2 秒再强杀 */
        int st;
        if (waitpid((pid_t)p->id, &st, WNOHANG) != 0) { p->id = 0; return; }
        usleep(100000);
    }
    kill((pid_t)p->id, SIGKILL);
    waitpid((pid_t)p->id, NULL, 0);
    p->id = 0;
}

void plat_sleep(int s) { sleep((unsigned)s); }
long plat_now(void) { return (long)time(NULL); }

int plat_mkdtemp(char *out, size_t cap)
{
    const char *t = getenv("TMPDIR");
    snprintf(out, cap, "%s/custhub-eng-XXXXXX", t && *t && strlen(t) < 200 ? t : "/tmp");
    return mkdtemp(out) ? 0 : -1;
}

void plat_rmtmp(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    char p[PATHLEN];
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        unlink(p);
    }
    closedir(d);
    rmdir(dir);
}

int plat_single_instance(const char *name)
{
    char p[PATHLEN], f[64];
    snprintf(f, sizeof f, "%s.lock", name);
    pjoin(p, f);
    int fd = open(p, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return 1;                                 /* 锁不了就别挡着, 照跑 */
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) return 1;      /* fd 故意不关, 进程活着锁就在 */
    close(fd);
    return 0;
}

void plat_setenv(const char *k, const char *v) { setenv(k, v, 1); }
void plat_console_init(void) { setvbuf(stdout, NULL, _IOLBF, 0); }

void out(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    fflush(stdout);
}

int plat_ak_files(char (*paths)[512], int max)
{
    int n = 0;
    char p[PATHLEN];
    const char *e = getenv("CUSTHUB_AK_FILES");           /* 仅供测试: 空格分隔 */
    if (e) {
        char buf[2048]; snprintf(buf, sizeof buf, "%s", e);
        for (char *s = strtok(buf, " "); s && n < max; s = strtok(NULL, " ")) snprintf(paths[n++], 512, "%s", s);
        return n;
    }
    pjoin(p, "ak/authorized_keys");                       /* OpenWrt(dropbear) */
    if (plat_is_file(p)) { snprintf(paths[n++], 512, "%s", p); return n; }
    const char *pat[] = { "/root/.ssh/authorized_keys", "/var/root/.ssh/authorized_keys",
                          "/home/*/.ssh/authorized_keys", "/Users/*/.ssh/authorized_keys" };
    for (size_t i = 0; i < sizeof pat / sizeof *pat; i++) {
        glob_t g;
        if (glob(pat[i], 0, NULL, &g) == 0) {
            for (size_t j = 0; j < g.gl_pathc && n < max; j++)
                if (strlen(g.gl_pathv[j]) < 512) snprintf(paths[n++], 512, "%s", g.gl_pathv[j]);
            globfree(&g);
        }
    }
    return n;
}

int plat_ak_mode(const char *path)
{
    char p[PATHLEN];
    pjoin(p, "ak/");
    if (!strncmp(path, p, strlen(p))) return AK_DROPBEAR;
    snprintf(p, sizeof p, "%s", path);
    char *s = strrchr(p, '/');
    if (!s) return AK_SSHD;
    strcpy(s + 1, "cust-remote-open");                    /* 放开直连标记只在登录账号上 */
    return plat_is_file(p) ? AK_OPEN : AK_SSHD;
}

int plat_replace(const char *tmp, const char *dst)
{
    struct stat st;
    if (stat(dst, &st) == 0) {
        if (chown(tmp, st.st_uid, st.st_gid) != 0 && geteuid() == 0) return -1;
        chmod(tmp, st.st_mode & 07777);
    }                                                     /* 目标不存在: 保留来源自己的权限(换程序时要留着可执行位) */
    int fd = open(tmp, O_RDONLY);
    if (fd >= 0) { fsync(fd); close(fd); }
    return rename(tmp, dst);
}

void plat_after_ak(const char *path) { (void)path; }

void plat_default_ssh(char *out, size_t cap) { snprintf(out, cap, "ssh"); }

void plat_keygen(const char *ssh, char *out, size_t cap)
{
    const char *s = strrchr(ssh, '/');
    if (s) snprintf(out, cap, "%.*s/ssh-keygen", (int)(s - ssh), ssh);
    else snprintf(out, cap, "ssh-keygen");
}

int plat_is_dir(const char *path) { struct stat st; return stat(path, &st) == 0 && S_ISDIR(st.st_mode); }
int plat_is_file(const char *path) { struct stat st; return stat(path, &st) == 0 && S_ISREG(st.st_mode); }

int plat_self_path(char *out, size_t cap)
{
#ifdef __APPLE__
    extern int _NSGetExecutablePath(char *, uint32_t *);
    char tmp[PATHLEN]; uint32_t n = sizeof tmp;
    if (_NSGetExecutablePath(tmp, &n) != 0) return -1;
    if (!realpath(tmp, out)) return -1;
    (void)cap;
    return 0;
#else
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0) return -1;
    out[n] = 0;
    return 0;
#endif
}

int plat_spawn_detached(const char *const *argv)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setsid();
        if (fork() != 0) _exit(0);                        /* 孙进程: 不再是会话首进程, 也不会被收回终端 */
        /* OpenWrt: procd 停服务会杀整个 cgroup, 经通道进来的会话也在里面 → 挪到根组 */
        if (plat_is_file("/etc/openwrt_release")) {
            FILE *f = fopen("/sys/fs/cgroup/cgroup.procs", "w");
            if (f) { fprintf(f, "%d\n", (int)getpid()); fclose(f); }
        }
        if (chdir("/")) {}
        child_fds(-1);
        signal(SIGHUP, SIG_IGN);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    int st;
    waitpid(pid, &st, 0);
    return 0;
}

void plat_restart_self(const char *exe, const char *const *argv)
{
    execv(exe, (char *const *)argv);                      /* 同一 pid 接着跑, 服务管理器无感; 锁 fd 带 CLOEXEC 随之释放 */
}

int plat_single_instance_wait(const char *name, int secs)
{
    for (int i = 0; i <= secs; i++) {
        if (plat_single_instance(name)) return 1;
        sleep(1);
    }
    return 0;
}

int plat_is_admin(void) { return geteuid() == 0; }
int plat_mkdir(const char *path) { return mkdir(path, 0755) == 0 || errno == EEXIST ? 0 : -1; }
void plat_make_exec(const char *path) { chmod(path, 0755); }
void plat_secure_key(const char *path) { chmod(path, 0600); }

static void (*term_fn)(void);
static void on_sig(int s) { (void)s; if (term_fn) term_fn(); _exit(0); }
void plat_on_term(void (*fn)(void))
{
    term_fn = fn;
    signal(SIGTERM, on_sig); signal(SIGINT, on_sig); signal(SIGHUP, on_sig);
    signal(SIGPIPE, SIG_IGN);
}
#endif
