/* 平台层 · Windows(Win7 起; 只用 XP/Vista 以来就有的 API) */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

static HANDLE g_job;

/* 子进程随我们一起死(守护被计划任务杀掉时不留孤儿 ssh); Win7 上若已在别的作业里会失败, 不影响 */
static void job_add(HANDLE h)
{
    if (!g_job) {
        g_job = CreateJobObjectA(NULL, NULL);
        if (g_job) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION li;
            memset(&li, 0, sizeof li);
            li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &li, sizeof li);
        }
    }
    if (g_job) AssignProcessToJobObject(g_job, h);
}

/* argv → 命令行(按 CommandLineToArgvW 的规则加引号) */
static int cmdline(const char *const *argv, char *out, size_t cap)
{
    size_t o = 0;
#define PUT(c) do { if (o + 2 >= cap) return -1; out[o++] = (c); } while (0)
    for (int i = 0; argv[i]; i++) {
        const char *a = argv[i];
        if (i) PUT(' ');
        if (*a && !strpbrk(a, " \t\"")) { while (*a) PUT(*a++); continue; }
        PUT('"');
        for (;;) {
            int bs = 0;
            while (*a == '\\') { bs++; a++; }
            if (!*a) { for (int k = 0; k < bs * 2; k++) PUT('\\'); break; }
            if (*a == '"') { for (int k = 0; k < bs * 2 + 1; k++) PUT('\\'); PUT('"'); }
            else { for (int k = 0; k < bs; k++) PUT('\\'); PUT(*a); }
            a++;
        }
        PUT('"');
    }
    out[o] = 0;
    return 0;
#undef PUT
}

static HANDLE nul_handle(void)
{
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    return CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
}

static int start_in(const char *const *argv, HANDLE in, HANDLE out, int console, PROCESS_INFORMATION *pi);
static int start(const char *const *argv, HANDLE out, int console, PROCESS_INFORMATION *pi)
{
    return start_in(argv, NULL, out, console, pi);
}

static int start_in(const char *const *argv, HANDLE in, HANDLE out, int console, PROCESS_INFORMATION *pi)
{
    char cl[8192];
    if (cmdline(argv, cl, sizeof cl)) return -1;
    STARTUPINFOA si;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    HANDLE nul = INVALID_HANDLE_VALUE;
    BOOL inherit = FALSE;
    if (!console) {
        nul = nul_handle();
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = in ? in : nul; si.hStdOutput = out ? out : nul; si.hStdError = nul;
        inherit = TRUE;
    }
    /* 先挂起: 挂进作业前不让它跑; 外层作业(sshd 会话/计划任务)允许就脱离它, Win7 不支持作业嵌套 */
    DWORD fl = CREATE_SUSPENDED | (console ? 0 : CREATE_NO_WINDOW);
    BOOL ok = CreateProcessA(NULL, cl, NULL, NULL, inherit, fl | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, pi);
    if (!ok) ok = CreateProcessA(NULL, cl, NULL, NULL, inherit, fl, NULL, NULL, &si, pi);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) return -1;
    job_add(pi->hProcess);
    ResumeThread(pi->hThread);
    return 0;
}

int plat_spawn_bg(const char *const *argv, proc_t *p)
{
    PROCESS_INFORMATION pi;
    if (start(argv, NULL, 0, &pi)) return -1;
    CloseHandle(pi.hThread);
    p->id = (intptr_t)pi.hProcess;
    return 0;
}

int plat_run(const char *const *argv, char *out, size_t cap, int timeout_s)
{
    return plat_run_in(argv, NULL, 0, out, cap, timeout_s);
}

int plat_run_in(const char *const *argv, const char *in, size_t inlen, char *out, size_t cap, int timeout_s)
{
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE rd, wr, ird = NULL, iwr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    if (in) {
        if (!CreatePipe(&ird, &iwr, &sa, (DWORD)inlen + 1024)) { CloseHandle(rd); CloseHandle(wr); return -1; }
        SetHandleInformation(iwr, HANDLE_FLAG_INHERIT, 0);
    }
    PROCESS_INFORMATION pi;
    if (start_in(argv, ird, wr, 0, &pi)) { CloseHandle(rd); CloseHandle(wr); if (in) { CloseHandle(ird); CloseHandle(iwr); } return -1; }
    CloseHandle(wr); CloseHandle(pi.hThread);
    if (in) {                                             /* 管道缓冲按输入大小建, 一次写完不会堵 */
        CloseHandle(ird);
        DWORD w = 0; WriteFile(iwr, in, (DWORD)inlen, &w, NULL);
        CloseHandle(iwr);
    }
    size_t n = 0; int timed = 0;
    DWORD end = GetTickCount() + (DWORD)timeout_s * 1000;
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) break;     /* 写端关了 = 读完 */
        if (avail) {
            char tmp[4096]; DWORD k = 0;
            if (!ReadFile(rd, tmp, avail < sizeof tmp ? avail : sizeof tmp, &k, NULL) || !k) break;
            if (out && n + 1 < cap) {
                size_t c = k < cap - 1 - n ? k : cap - 1 - n;
                memcpy(out + n, tmp, c); n += c;
            }
            continue;
        }
        if ((LONG)(GetTickCount() - end) >= 0) { timed = 1; break; }
        if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) {
            /* 进程已退出: 把剩下的读干净 */
            if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail) continue;
            break;
        }
    }
    CloseHandle(rd);
    if (out) out[n] = 0;
    DWORD code = (DWORD)-1;
    if (timed) TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 5000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return timed ? -2 : (int)code;
}

int plat_run_tty(const char *const *argv)
{
    PROCESS_INFORMATION pi;
    if (start(argv, NULL, 1, &pi)) return -1;
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return (int)code;
}

int plat_alive(proc_t *p)
{
    if (!p->id) return 0;
    if (WaitForSingleObject((HANDLE)p->id, 0) == WAIT_TIMEOUT) return 1;
    CloseHandle((HANDLE)p->id); p->id = 0;
    return 0;
}

void plat_kill(proc_t *p)
{
    if (!p->id) return;
    TerminateProcess((HANDLE)p->id, 1);
    WaitForSingleObject((HANDLE)p->id, 2000);
    CloseHandle((HANDLE)p->id); p->id = 0;
}

void plat_sleep(int s) { Sleep((DWORD)s * 1000); }
long plat_now(void) { return (long)time(NULL); }

int plat_mkdtemp(char *out, size_t cap)
{
    char t[MAX_PATH];
    if (!GetTempPathA(sizeof t, t)) return -1;
    for (int i = 0; i < 20; i++) {
        snprintf(out, cap, "%scusthub-eng-%lu-%lu-%d", t, GetCurrentProcessId(), GetTickCount(), i);
        if (CreateDirectoryA(out, NULL)) return 0;
    }
    return -1;
}

void plat_rmtmp(const char *dir)
{
    char pat[PATHLEN], p[PATHLEN];
    WIN32_FIND_DATAA fd;
    snprintf(pat, sizeof pat, "%s\\*", dir);
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            snprintf(p, sizeof p, "%s\\%s", dir, fd.cFileName);
            DeleteFileA(p);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir);
}

int plat_single_instance(const char *name)
{
    char n[128];
    /* 与旧 tun.ps1 同名: 迁移期两者不会同时跑; 测试目录(CUSTHUB_D)另起一把锁 */
    snprintf(n, sizeof n, "Global\\cust-remote-%s%s", name, getenv("CUSTHUB_D") ? "-test" : "");
    HANDLE m = CreateMutexA(NULL, FALSE, n);
    if (!m) return 1;
    DWORD r = WaitForSingleObject(m, 0);
    return r == WAIT_OBJECT_0 || r == WAIT_ABANDONED;
}

void plat_setenv(const char *k, const char *v) { SetEnvironmentVariableA(k, v); }

void plat_console_init(void) { SetConsoleOutputCP(CP_UTF8); }

/* Win7 的控制台对 UTF-8 多字节写入支持差: 是控制台就转成 UTF-16 用 WriteConsoleW */
void out(const char *fmt, ...)
{
    char buf[8192];
    va_list ap; va_start(ap, fmt); int n = vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof buf) n = sizeof buf - 1;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode, w;
    if (GetConsoleMode(h, &mode)) {
        static WCHAR wb[8192];
        int k = MultiByteToWideChar(CP_UTF8, 0, buf, n, wb, 8192);
        if (k > 0) { WriteConsoleW(h, wb, (DWORD)k, &w, NULL); return; }
    }
    WriteFile(h, buf, (DWORD)n, &w, NULL);
}

int plat_ak_files(char (*paths)[512], int max)
{
    const char *e = getenv("CUSTHUB_AK_FILES");
    if (e && max > 0) { snprintf(paths[0], 512, "%s", e); return 1; }
    const char *pd = getenv("ProgramData");
    if (max < 1) return 0;
    snprintf(paths[0], 512, "%s\\ssh\\administrators_authorized_keys", pd ? pd : "C:\\ProgramData");
    return 1;
}

int plat_ak_mode(const char *path) { (void)path; return AK_WIN; }

int plat_replace(const char *tmp, const char *dst)
{
    return MoveFileExA(tmp, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : -1;
}

/* sshd 只认管理员组 + SYSTEM 可写的 administrators_authorized_keys */
void plat_after_ak(const char *path)
{
    const char *av[] = { "icacls", path, "/inheritance:r", "/grant", "*S-1-5-32-544:F", "*S-1-5-18:F", NULL };
    plat_run(av, NULL, 0, 30);
}

void plat_default_ssh(char *out, size_t cap)
{
    const char *pf = getenv("ProgramFiles"), *sr = getenv("SystemRoot");
    snprintf(out, cap, "%s\\OpenSSH\\ssh.exe", pf ? pf : "C:\\Program Files");
    if (plat_is_file(out)) return;
    snprintf(out, cap, "%s\\System32\\OpenSSH\\ssh.exe", sr ? sr : "C:\\Windows");
    if (plat_is_file(out)) return;
    snprintf(out, cap, "ssh.exe");
}

void plat_keygen(const char *ssh, char *out, size_t cap)
{
    const char *s = strrchr(ssh, '\\');
    if (s) snprintf(out, cap, "%.*s\\ssh-keygen.exe", (int)(s - ssh), ssh);
    else snprintf(out, cap, "ssh-keygen.exe");
}

int plat_is_dir(const char *path)
{
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

int plat_is_file(const char *path)
{
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

void plat_on_term(void (*fn)(void)) { (void)fn; }   /* 子进程挂在作业对象上, 我们一死它们跟着死 */

int plat_self_path(char *out, size_t cap)
{
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    return n > 0 && n < cap ? 0 : -1;
}

/* 不挂进我们的作业, 能脱离外层作业就脱离; 我们退出、ssh 会话断开都不影响它 */
int plat_spawn_detached(const char *const *argv)
{
    char cl[8192];
    if (cmdline(argv, cl, sizeof cl)) return -1;
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    DWORD fl = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    BOOL ok = CreateProcessA(NULL, cl, NULL, NULL, FALSE, fl | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi);
    if (!ok) ok = CreateProcessA(NULL, cl, NULL, NULL, FALSE, fl, NULL, NULL, &si, &pi);
    if (!ok) return -1;
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}

/* 起新进程接班(它会等我们让出互斥锁)后退出; 退出码非 0, 计划任务的"失败重启"再兜一层底 */
void plat_restart_self(const char *exe, const char *const *argv)
{
    (void)exe;
    if (plat_spawn_detached(argv) == 0) ExitProcess(3);
}

int plat_single_instance_wait(const char *name, int secs)
{
    char n[128];
    snprintf(n, sizeof n, "Global\\cust-remote-%s%s", name, getenv("CUSTHUB_D") ? "-test" : "");
    HANDLE m = CreateMutexA(NULL, FALSE, n);
    if (!m) return 1;
    DWORD r = WaitForSingleObject(m, (DWORD)secs * 1000);
    return r == WAIT_OBJECT_0 || r == WAIT_ABANDONED;
}

int plat_is_admin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
    PSID g; BOOL m = FALSE;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g)) return 0;
    if (!CheckTokenMembership(NULL, g, &m)) m = FALSE;
    FreeSid(g);
    return m;
}

int plat_mkdir(const char *path) { return CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS ? 0 : -1; }
void plat_make_exec(const char *path) { (void)path; }

int plat_elevate_self(const char *args)
{
    char self[PATHLEN]; WCHAR wf[PATHLEN], wa[512];
    if (plat_self_path(self, sizeof self)) return 1;
    MultiByteToWideChar(CP_UTF8, 0, self, -1, wf, PATHLEN);
    MultiByteToWideChar(CP_UTF8, 0, args, -1, wa, 512);
    SHELLEXECUTEINFOW se; memset(&se, 0, sizeof se);
    se.cbSize = sizeof se; se.lpVerb = L"runas"; se.lpFile = wf; se.lpParameters = wa; se.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&se) ? 0 : 1;
}

/* ssh 要求私钥只有 SYSTEM/管理员组能碰; ssh-keygen 会给生成者单独留一条权限, 整份重写 ACL 并改属主 */
void plat_secure_key(const char *path)
{
    char who[300];
    const char *a1[] = { "icacls", path, "/setowner", "*S-1-5-32-544", NULL };
    const char *a2[] = { "icacls", path, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", NULL };
    plat_run(a1, NULL, 0, 30); plat_run(a2, NULL, 0, 30);
    const char *d = getenv("USERDOMAIN"), *u = getenv("USERNAME");
    if (d && u) {
        snprintf(who, sizeof who, "%s\\%s", d, u);
        const char *a3[] = { "icacls", path, "/remove:g", who, NULL };
        plat_run(a3, NULL, 0, 30);
    }
}
#endif
