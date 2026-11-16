/* 接入 / 卸载 · Windows(Win7 SP1 ~ Win11), 取代 client.ps1.tpl / uninstall.ps1.tpl
 * 只用 Win7 自带的: kernel32 advapi32 ws2_32 msvcrt ole32 oleaut32 shell32 user32
 * 系统工具照旧调用: msiexec / sc / icacls / schtasks / route / OpenSSH 自带的 install-sshd.ps1(绿色版)
 * 一行命令按系统位数下载对应的 exe: 32 位程序在 64 位系统上会被重定向 Program Files / System32 / 注册表 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <oleauto.h>
#include <initguid.h>
#include <netfw.h>
#include <shobjidl.h>
#include <sddl.h>
#define PSAPI_VERSION 2                         /* Win7 起 kernel32 自带(K32EnumProcesses), 不另依赖 psapi.dll */
#include <psapi.h>
#include "cr.h"
#include "plat.h"
#include "join.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define RK64 KEY_WOW64_64KEY

static WCHAR *W(const char *s)                           /* UTF-8 → UTF-16(轮换 4 个缓冲) */
{
    static WCHAR b[4][1024]; static int i;
    WCHAR *o = b[i++ & 3];
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, o, 1024)) o[0] = 0;
    return o;
}

static char *U8(const WCHAR *s)
{
    static char b[4][2048]; static int i;
    char *o = b[i++ & 3];
    if (!WideCharToMultiByte(CP_UTF8, 0, s, -1, o, 2048, NULL, NULL)) o[0] = 0;
    return o;
}

static int runw(const char *const *av, int t) { return plat_run(av, NULL, 0, t); }

static void env(const char *k, char *o, size_t cap, const char *def)
{
    const char *v = getenv(k);
    snprintf(o, cap, "%s", v && *v ? v : def);
}

static int is_system(void)
{
    HANDLE t; char buf[256]; DWORD n; int r = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return 0;
    if (GetTokenInformation(t, TokenUser, buf, sizeof buf, &n)) {
        LPSTR s = NULL;
        if (ConvertSidToStringSidA(((TOKEN_USER *)buf)->User.Sid, &s)) { r = !strcmp(s, "S-1-5-18"); LocalFree(s); }
    }
    CloseHandle(t);
    return r;
}

static void my_sid(char *o, size_t cap)
{
    HANDLE t; char buf[256]; DWORD n; o[0] = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return;
    if (GetTokenInformation(t, TokenUser, buf, sizeof buf, &n)) {
        LPSTR s = NULL;
        if (ConvertSidToStringSidA(((TOKEN_USER *)buf)->User.Sid, &s)) { snprintf(o, cap, "%s", s); LocalFree(s); }
    }
    CloseHandle(t);
}

/* ---------------- 系统识别 ---------------- */

typedef LONG (WINAPI *rtlgv_t)(OSVERSIONINFOW *);
static void win_ver(DWORD *maj, DWORD *min, DWORD *build)
{
    OSVERSIONINFOW v; memset(&v, 0, sizeof v); v.dwOSVersionInfoSize = sizeof v;
    rtlgv_t f = (rtlgv_t)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (f) f(&v);
    *maj = v.dwMajorVersion; *min = v.dwMinorVersion; *build = v.dwBuildNumber;
}

static const char *win_arch(void)
{
    SYSTEM_INFO si; GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return "64";
    case PROCESSOR_ARCHITECTURE_INTEL: return "32";
    default: return "arm";
    }
}

static void os_caption(char *o, size_t cap)
{
    HKEY k; WCHAR v[256]; DWORD n = sizeof v;
    snprintf(o, cap, "Windows");
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ | RK64, &k)) return;
    if (!RegQueryValueExW(k, L"ProductName", NULL, NULL, (BYTE *)v, &n)) snprintf(o, cap, "%s", U8(v));
    RegCloseKey(k);
}

/* ---------------- 服务 ---------------- */

static int svc_exists(const char *name)
{
    SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT), s;
    if (!m) return 0;
    s = OpenServiceA(m, name, SERVICE_QUERY_STATUS);
    if (s) CloseServiceHandle(s);
    CloseServiceHandle(m);
    return s != NULL;
}

static DWORD svc_state(const char *name, DWORD *exitc)
{
    SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT), s;
    SERVICE_STATUS st; DWORD r = 0;
    if (!m) return 0;
    if ((s = OpenServiceA(m, name, SERVICE_QUERY_STATUS))) {
        if (QueryServiceStatus(s, &st)) { r = st.dwCurrentState; if (exitc) *exitc = st.dwWin32ExitCode; }
        CloseServiceHandle(s);
    }
    CloseServiceHandle(m);
    return r;
}

static int svc_ctl(const char *name, int start)
{
    SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT), s;
    SERVICE_STATUS st; int ok = 0;
    if (!m) return 0;
    if ((s = OpenServiceA(m, name, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG))) {
        if (start == 2) ok = ChangeServiceConfigA(s, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        else if (start) ok = StartServiceA(s, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
        else ok = ControlService(s, SERVICE_CONTROL_STOP, &st) || GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
        CloseServiceHandle(s);
    }
    CloseServiceHandle(m);
    if (start != 2) {
        DWORD want = start ? SERVICE_RUNNING : SERVICE_STOPPED;
        for (int i = 0; i < 40 && svc_state(name, NULL) != want; i++) Sleep(500);
        return svc_state(name, NULL) == want;
    }
    return ok;
}

/* ---------------- 进程 ---------------- */

/* 结束可执行文件在某目录下的进程(旧 OpenSSH 目录里的 ssh.exe 会占着 dll) */
static void kill_under(const char *dir)
{
    char b[PATHLEN]; size_t dl = strlen(dir);
    DWORD ids[4096], n;
    if (!EnumProcesses(ids, sizeof ids, &n)) return;
    for (DWORD i = 0; i < n / sizeof(DWORD); i++) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, ids[i]);
        if (!h) continue;
        DWORD l = sizeof b;
        if (QueryFullProcessImageNameA(h, 0, b, &l) && !_strnicmp(b, dir, dl) && (b[dl] == '\\')) TerminateProcess(h, 1);
        CloseHandle(h);
    }
}

/* 旧脚本守护 / 网络节点(PowerShell 进程看不到命令行, 交给 WMI) */
static void kill_scripts(int node)
{
    const char *ps1 = "Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like '*cust-remote\\tun.ps1*' -or $_.CommandLine -like '*custtun@*' -or "
                      "(($_.Name -eq 'custhub.exe' -or $_.Name -eq 'cust-remote.exe') -and $_.CommandLine -like '* tun*') } | ForEach-Object { try { $_.Terminate() | Out-Null } catch {} }";
    const char *ps2 = "Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like '*cust-remote\\node\\node.ps1*' -or $_.ExecutablePath -like '*cust-remote\\node\\sing-box.exe' } | ForEach-Object { try { $_.Terminate() | Out-Null } catch {} }";
    const char *a[] = { "powershell", "-NoProfile", "-NonInteractive", "-Command", node ? ps2 : ps1, NULL };
    runw(a, 60);
}

/* ---------------- 注册表 ---------------- */

static int reg_exists(HKEY root, const WCHAR *path)
{
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | RK64, &k)) return 0;
    RegCloseKey(k);
    return 1;
}

static int reg_get(HKEY root, const WCHAR *path, const WCHAR *name, WCHAR *o, DWORD cap)
{
    HKEY k; DWORD n = cap * sizeof(WCHAR), t;
    o[0] = 0;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | RK64, &k)) return -1;
    LONG r = RegQueryValueExW(k, name, NULL, &t, (BYTE *)o, &n);
    RegCloseKey(k);
    if (r || (t != REG_SZ && t != REG_EXPAND_SZ)) { o[0] = 0; return -1; }
    o[cap - 1] = 0;
    return 0;
}

static int reg_set(HKEY root, const WCHAR *path, const WCHAR *name, const WCHAR *v)
{
    HKEY k;
    if (RegCreateKeyExW(root, path, 0, NULL, 0, KEY_SET_VALUE | RK64, NULL, &k, NULL)) return -1;
    LONG r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)v, (DWORD)((wcslen(v) + 1) * sizeof(WCHAR)));
    RegCloseKey(k);
    return r ? -1 : 0;
}

/* 卸载列表里按显示名前缀找 MSI 产品({GUID} 子键)并静默卸载; 64/32 两个视图都找 */
static void uninstall_products(const WCHAR *prefix)
{
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
    for (int v = 0; v < 2; v++) {
        HKEY k;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ | views[v], &k)) continue;
        WCHAR sub[256];
        for (DWORD i = 0;; i++) {
            DWORD sl = 256;
            if (RegEnumKeyExW(k, i, sub, &sl, NULL, NULL, NULL, NULL)) break;
            if (sub[0] != L'{') continue;
            HKEY s; WCHAR dn[512]; DWORD n = sizeof dn, t;
            if (RegOpenKeyExW(k, sub, 0, KEY_READ | views[v], &s)) continue;
            if (!RegQueryValueExW(s, L"DisplayName", NULL, &t, (BYTE *)dn, &n) && !wcsncmp(dn, prefix, wcslen(prefix))) {
                char g[300]; snprintf(g, sizeof g, "%s", U8(sub));
                const char *a[] = { "msiexec", "/x", g, "/qn", "/norestart", NULL };
                runw(a, 600);
            }
            RegCloseKey(s);
        }
        RegCloseKey(k);
    }
}

/* ---------------- 防火墙(COM, Win7~11 通用) ---------------- */

static INetFwPolicy2 *fw_open(void)
{
    INetFwPolicy2 *p = NULL;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwPolicy2, (void **)&p) != S_OK) return NULL;
    return p;
}

static int ssh_rule(const WCHAR *n)                       /* 名字带 OpenSSH / sshd, 且不是我们自己的 cust-* */
{
    return (wcsstr(n, L"OpenSSH") || wcsstr(n, L"sshd")) && wcsncmp(n, L"cust-", 5);
}

/* mode 0: 记下开着的 ssh 规则名(| 分隔); 1: 关掉它们; 2: 按 names 重新打开 */
static void fw_rules(int mode, char *names, size_t cap)
{
    INetFwPolicy2 *p = fw_open();
    if (!p) return;
    INetFwRules *rules = NULL; IUnknown *u = NULL; IEnumVARIANT *e = NULL;
    size_t l = 0;
    if (mode == 0 && names) names[0] = 0;
    if (INetFwPolicy2_get_Rules(p, &rules) == S_OK && INetFwRules_get__NewEnum(rules, &u) == S_OK &&
        IUnknown_QueryInterface(u, &IID_IEnumVARIANT, (void **)&e) == S_OK) {
        VARIANT v; ULONG got;
        VariantInit(&v);
        while (IEnumVARIANT_Next(e, 1, &v, &got) == S_OK && got == 1) {
            INetFwRule *r = NULL;
            if (v.vt == VT_DISPATCH && IDispatch_QueryInterface(v.pdispVal, &IID_INetFwRule, (void **)&r) == S_OK) {
                BSTR n = NULL; VARIANT_BOOL en = VARIANT_FALSE;
                if (INetFwRule_get_Name(r, &n) == S_OK && n) {
                    INetFwRule_get_Enabled(r, &en);
                    if (mode == 0 && en && ssh_rule(n) && names) {
                        if (l) sb_add(names, cap, &l, "|");
                        sb_add(names, cap, &l, U8(n));
                    } else if (mode == 1 && en && ssh_rule(n)) INetFwRule_put_Enabled(r, VARIANT_FALSE);
                    else if (mode == 2 && names) {
                        char nm[600]; snprintf(nm, sizeof nm, "|%s|", U8(n));
                        char all[4200]; snprintf(all, sizeof all, "|%s|", names);
                        if (strstr(all, nm)) INetFwRule_put_Enabled(r, VARIANT_TRUE);
                    }
                    SysFreeString(n);
                }
                INetFwRule_Release(r);
            }
            VariantClear(&v);
        }
    }
    if (mode != 0 && rules) {
        BSTR a = SysAllocString(L"cust-sshd"), b = SysAllocString(L"cust-icmp");
        INetFwRules_Remove(rules, a); INetFwRules_Remove(rules, b);
        SysFreeString(a); SysFreeString(b);
    }
    if (e) IEnumVARIANT_Release(e);
    if (u) IUnknown_Release(u);
    if (rules) INetFwRules_Release(rules);
    INetFwPolicy2_Release(p);
}

/* ---------------- 快捷方式 / 壁纸 ---------------- */

static void public_desktop(WCHAR *o)
{
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, o) != S_OK) wcscpy(o, L"C:\\Users\\Public\\Desktop");
}

static int shortcut_in(const WCHAR *dk, const char *name, const char *target, const char *args, const char *icon, const char *desc)
{
    WCHAR path[MAX_PATH];
    IShellLinkW *sl = NULL; IPersistFile *pf = NULL; int ok = -1;
    _snwprintf(path, MAX_PATH, L"%ls\\%ls", dk, W(name));
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl) != S_OK) return -1;
    IShellLinkW_SetPath(sl, W(target));
    IShellLinkW_SetArguments(sl, W(args));
    IShellLinkW_SetIconLocation(sl, W(icon), 0);
    IShellLinkW_SetDescription(sl, W(desc));
    if (IShellLinkW_QueryInterface(sl, &IID_IPersistFile, (void **)&pf) == S_OK) {
        ok = IPersistFile_Save(pf, path, TRUE) == S_OK ? 0 : -1;
        IPersistFile_Release(pf);
    }
    IShellLinkW_Release(sl);
    return ok;
}

static int shortcut(const char *name, const char *target, const char *args, const char *icon, const char *desc)
{
    WCHAR dk[MAX_PATH];
    public_desktop(dk);
    return shortcut_in(dk, name, target, args, icon, desc);
}

static void start_menu(WCHAR *o)
{
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_PROGRAMS, NULL, 0, o) != S_OK) o[0] = 0;
}

static void shortcut_rm(const char *name)
{
    WCHAR path[MAX_PATH], dk[MAX_PATH];
    public_desktop(dk);
    _snwprintf(path, MAX_PATH, L"%ls\\%ls", dk, W(name));
    DeleteFileW(path);
}

static void set_wallpaper(HKEY root, const WCHAR *key, const WCHAR *file, const WCHAR *style, const WCHAR *tile, int now)
{
    reg_set(root, key, L"Wallpaper", file);
    if (style && *style) reg_set(root, key, L"WallpaperStyle", style);
    if (tile && *tile) reg_set(root, key, L"TileWallpaper", tile);
    if (now) SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (void *)file, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
}

/* ---------------- 失败现场 / 收尾 ---------------- */

void join_diag(char *o, size_t cap)
{
    size_t l = strlen(o);
    static char b[8192];
    const char *a1[] = { "sc", "query", "sshd", NULL };
    if (plat_run(a1, b, sizeof b, 20) >= 0) { sb_add(o, cap, &l, "== sc query sshd ==\n"); sb_add(o, cap, &l, b); }
    char p[PATHLEN];
    pjoin(p, "tun-status.txt");
    if (read_file(p, b, sizeof b) > 0) { sb_add(o, cap, &l, "== tun-status ==\n"); sb_add(o, cap, &l, b); }
    pjoin(p, "tun.log");
    if (read_file(p, b, sizeof b) > 0) { sb_add(o, cap, &l, "== tun.log ==\n"); sb_add(o, cap, &l, b + (strlen(b) > 3000 ? strlen(b) - 3000 : 0)); }
}

void join_finish(int okk)
{
    /* 窗口可见时: 成功停 10 秒给人看一眼, 失败停住等人看完; SYSTEM(远程更新)窗口隐藏, 没人按回车, 不等 */
    if (J.silent || is_system()) return;
    if (okk) Sleep(10000);
    else { out("\n  按回车关闭窗口\n"); getchar(); }
}

/* sshd 起不来: 现场取证(状态/配置检查/前台调试输出)随失败日志传回 */
static void sshd_start_or_fail(const char *sshd_exe)
{
    if (svc_ctl("sshd", 1)) return;
    static char dg[16384], b[8192]; size_t l = 0; dg[0] = 0;
    const char *a1[] = { "sc", "qc", "sshd", NULL };
    const char *a2[] = { sshd_exe, "-t", NULL };
    if (plat_run(a1, b, sizeof b, 20) >= 0) { sb_add(dg, sizeof dg, &l, "== sc qc ==\n"); sb_add(dg, sizeof dg, &l, b); }
    if (plat_run(a2, b, sizeof b, 20) >= 0) { sb_add(dg, sizeof dg, &l, "== sshd -t ==\n"); sb_add(dg, sizeof dg, &l, b); }
    const char *a3[] = { sshd_exe, "-d", "-p", "50022", NULL };
    if (plat_run(a3, b, sizeof b, 4) != -1) { sb_add(dg, sizeof dg, &l, "== sshd -d ==\n"); sb_add(dg, sizeof dg, &l, b); }
    say("%s", dg);
    DWORD ec = 0; svc_state("sshd", &ec);
    jfail("sshd 服务启动失败 (退出码 %lu)", (unsigned long)ec);
}

/* ---------------- 接入 ---------------- */

static HANDLE g_once;

/* 只允许一份在跑: 同一条命令重复粘贴 → 忽略; 新令牌 → 结束旧的那份, 由本次接手 */
static void single_join(void)
{
    char own[PATHLEN], b[160];
    pjoin(own, "join.owner");
    g_once = CreateMutexA(NULL, FALSE, "Global\\custhub-join");
    DWORD r = WaitForSingleObject(g_once, 0);
    if (r != WAIT_OBJECT_0 && r != WAIT_ABANDONED) {
        Sleep(2000);
        if (read_file(own, b, sizeof b) > 0) {
            char tok[96]; unsigned long pid = 0;
            if (sscanf(b, "%95s %lu", tok, &pid) == 2) {
                if (!strcmp(tok, J.token)) { rep("warn", "这条命令已经在这台电脑上运行, 本次重复粘贴已忽略", NULL, 2, NULL); exit(0); }
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
                if (h) { TerminateProcess(h, 1); CloseHandle(h); }
                rep("warn", "结束了上一份没跑完的接入, 由本次接手", NULL, 2, NULL);
            }
        }
        r = WaitForSingleObject(g_once, 15000);
        if (r != WAIT_OBJECT_0 && r != WAIT_ABANDONED) { rep("fail", "上一份接入结束不掉, 请重启这台电脑后再粘贴一次", NULL, 2, NULL); exit(1); }
    }
    snprintf(b, sizeof b, "%s %lu\n", J.token, (unsigned long)GetCurrentProcessId());
    write_file(own, b, strlen(b));
}

static void elevate_or_continue(int argc, char **argv)
{
    if (plat_is_admin()) return;
    char self[PATHLEN], args[1024], line[300], cap[200];
    os_caption(cap, sizeof cap);
    snprintf(line, sizeof line, "%s (%s %s 位) 已运行, 等待 UAC 确认", getenv("COMPUTERNAME") ? getenv("COMPUTERNAME") : "?", cap, win_arch());
    rep("start", line, NULL, 2, NULL);
    doing("请在弹出的窗口点\"是\"");
    plat_self_path(self, sizeof self);
    snprintf(args, sizeof args, "join %s", argc > 1 ? argv[1] : "");
    SHELLEXECUTEINFOW se; memset(&se, 0, sizeof se);
    se.cbSize = sizeof se; se.lpVerb = L"runas";
    WCHAR wf[PATHLEN], wa[1024];
    MultiByteToWideChar(CP_UTF8, 0, self, -1, wf, PATHLEN);
    MultiByteToWideChar(CP_UTF8, 0, args, -1, wa, 1024);
    se.lpFile = wf; se.lpParameters = wa; se.nShow = J.silent ? SW_HIDE : SW_SHOWNORMAL;
    if (!ShellExecuteExW(&se)) jfail("UAC 点了\"否\"(取消), 重新运行并点\"是\"");
    exit(0);
}

static void disable_quickedit(void)
{
    /* 客户在窗口里点一下就进「选择」模式, 程序被冻住直到按回车; 本控制台本进程有效 */
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE); DWORD m;
    if (GetConsoleMode(h, &m)) SetConsoleMode(h, (m | 0x80) & ~0x40u);
}

static void edit_sshd_config(const char *cfg)
{
    static char b[MAXBUF], nw[MAXBUF];
    if (read_file(cfg, b, sizeof b) < 0) return;
    size_t l = 0; int found = 0; nw[0] = 0;
    char *cur = b, *ln;
    while ((ln = next_line(&cur))) {
        const char *s = ln; while (*s == '#' || *s == ' ' || *s == '\t') s++;
        if (!_strnicmp(s, "PasswordAuthentication", 22) && (s[22] == ' ' || s[22] == '\t')) {
            if (found++) continue;
            sb_add(nw, sizeof nw, &l, "PasswordAuthentication no\r\n");
            continue;
        }
        sb_add(nw, sizeof nw, &l, ln); sb_add(nw, sizeof nw, &l, "\r\n");
    }
    if (!found) { static char t[MAXBUF + 64]; snprintf(t, sizeof t, "PasswordAuthentication no\r\n%s", nw); write_file(cfg, t, strlen(t)); }
    else write_file(cfg, nw, l);
}

static void add_admin_key(const char *ak)
{
    static char b[MAXBUF];
    long n = read_file(ak, b, sizeof b);
    if (n < 0) { n = 0; b[0] = 0; }
    if (!strstr(b, J.pubkey)) {
        if ((size_t)n + strlen(J.pubkey) + 4 >= sizeof b) jfail("authorized_keys 太大");
        if (n && b[n - 1] != '\n') { b[n++] = '\r'; b[n++] = '\n'; }
        n += snprintf(b + n, sizeof b - (size_t)n, "%s\r\n", J.pubkey);
        if (write_file(ak, b, (size_t)n)) jfail("写不了 %s", ak);
    }
    const char *a[] = { "icacls", ak, "/inheritance:r", "/grant", "*S-1-5-32-544:F", "*S-1-5-18:F", NULL };
    runw(a, 30);
}

static int join_windows(int argc, char **argv)
{
    char pf[PATHLEN], pd[PATHLEN], sr[PATHLEN], cn[128], cap[200], line[600];
    env("ProgramFiles", pf, sizeof pf, "C:\\Program Files");
    env("ProgramData", pd, sizeof pd, "C:\\ProgramData");
    env("SystemRoot", sr, sizeof sr, "C:\\Windows");
    env("COMPUTERNAME", cn, sizeof cn, "?");
    disable_quickedit();
    say(""); say("==== 远程维护接入 ====");
    elevate_or_continue(argc, argv);
    plat_mkdir(g_dir);
    { const char *a[] = { "icacls", g_dir, "/inheritance:r", "/grant", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", NULL }; runw(a, 30); }
    single_join();
    cr_log("join.log", "==== 接入 %s, 令牌 %.8s… ====", CR_VERSION, J.token);
    DWORD maj, min, build; win_ver(&maj, &min, &build);
    const char *arch = win_arch();
    os_caption(cap, sizeof cap);
    snprintf(line, sizeof line, "%s (%s %s 位, build %lu) 已以管理员运行", cn, cap, arch, (unsigned long)build);
    rep("start", line, NULL, 2, NULL);

    if (!strcmp(arch, "arm")) jfail("ARM 版 Windows 暂不支持");
    if (maj == 6 && min == 1 && build < 7601) jfail("Win7 未装 SP1");
    const char *gen = maj >= 10 ? "new" : "legacy";

    /* 0. 安装前的样子(只在第一次记), 卸载时据此还原 */
    char wg[PATHLEN], st[PATHLEN], v[4096];
    snprintf(wg, sizeof wg, "%s\\WireGuard\\wireguard.exe", pf);
    pjoin(st, "state.txt");
    if (!plat_is_file(st)) {
        int had_ssh = svc_exists("sshd");
        static char rules[4096];
        fw_rules(0, rules, sizeof rules);
        char cfg[PATHLEN], bak[PATHLEN];
        snprintf(cfg, sizeof cfg, "%s\\ssh\\sshd_config", pd);
        pjoin(bak, "sshd_config.bak");
        if (had_ssh && plat_is_file(cfg)) CopyFileA(cfg, bak, FALSE);
        st_set("hadWG", plat_is_file(wg) ? "1" : "0");
        st_set("hadSSH", had_ssh ? "1" : "0");
        st_set("sshRules", rules);
        st_set("hadNNWO", reg_exists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Network\\NewNetworkWindowOff") ? "1" : "0");
    }

    /* 1. OpenSSH Server: Win10+ 新版 msi; 老系统 8.1 绿色版 + 官方 install-sshd.ps1 */
    char sshdir[PATHLEN], sshexe[PATHLEN], sys_ssh[PATHLEN];
    snprintf(sshdir, sizeof sshdir, "%s\\OpenSSH", pf);
    snprintf(sshexe, sizeof sshexe, "%s\\ssh.exe", sshdir);
    snprintf(sys_ssh, sizeof sys_ssh, "%s\\System32\\OpenSSH\\ssh.exe", sr);
    int own = st_get("hadSSH", v, sizeof v) == 0 && !strcmp(v, "0");
    int no_client = !plat_is_file(sshexe) && !plat_is_file(sys_ssh);
    /* 远程更新(keep_tun)时 sshd 刚经它登录过, 一定是好的, 老系统也不重装: 通道的 ssh.exe 正占着目录里的 dll */
    int reinstall = !svc_exists("sshd") || (own && !strcmp(gen, "legacy") && !J.keep_tun) || (no_client && !strcmp(gen, "new"));
    if (reinstall) {
        svc_ctl("sshd", 0);
        kill_under(sshdir); kill_scripts(1);
        Sleep(1000);
        char key[32], pkg[PATHLEN];
        snprintf(key, sizeof key, "ssh-%s-%s", gen, arch);
        get_pkg(key, pkg, sizeof pkg);
        doing("安装 OpenSSH");
        size_t pl = strlen(pkg);
        if (pl > 4 && !_stricmp(pkg + pl - 4, ".msi")) {
            const char *a[] = { "msiexec", "/i", pkg, "/qn", "/norestart", "ADDLOCAL=Server,Client", NULL };
            int r = plat_run(a, NULL, 0, 900);
            if (r != 0 && r != 3010) jfail("安装 OpenSSH 失败, msiexec 退出码 %d", r);
        } else {
            const char *rd[] = { "cmd", "/c", "rmdir", "/s", "/q", sshdir, NULL };
            if (plat_is_dir(sshdir)) runw(rd, 60);
            const char *xc[] = { "xcopy", pkg, sshdir, "/e", "/i", "/q", "/y", NULL };
            if (plat_run(xc, NULL, 0, 300) != 0) jfail("复制 OpenSSH 失败");
            char m[PATHLEN]; snprintf(m, sizeof m, "%s\\manifest.sha512", sshdir); DeleteFileA(m);
            doing("注册 OpenSSH 服务");
            char ins[PATHLEN]; snprintf(ins, sizeof ins, "%s\\install-sshd.ps1", sshdir);
            const char *a1[] = { "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ins, NULL };
            runw(a1, 120);
            const char *a2[] = { "sc", "sidtype", "sshd", "unrestricted", NULL };   /* Win7 默认不给服务独立 SID */
            runw(a2, 30);
            const char *a3[] = { "icacls", sshdir, "/grant", "*S-1-5-11:(OI)(CI)RX", NULL };   /* 特权分离子进程要能读 */
            runw(a3, 30);
            char hd[PATHLEN], hk[PATHLEN], kg[PATHLEN];
            snprintf(hd, sizeof hd, "%s\\ssh", pd); plat_mkdir(hd);
            snprintf(hk, sizeof hk, "%s\\ssh_host_ed25519_key", hd);
            snprintf(kg, sizeof kg, "%s\\ssh-keygen.exe", sshdir);
            if (!plat_is_file(hk)) { const char *a4[] = { kg, "-A", NULL }; runw(a4, 60); }
            /* 主机私钥只许 SYSTEM+管理员组, 否则 sshd 以 SYSTEM 运行时拒绝加载 → 服务 1067 */
            const char *types[] = { "ed25519", "ecdsa", "rsa", "dsa" };
            for (int i = 0; i < 4; i++) { snprintf(hk, sizeof hk, "%s\\ssh_host_%s_key", hd, types[i]); if (plat_is_file(hk)) plat_secure_key(hk); }
        }
    }
    svc_ctl("sshd", 2);
    char cfg[PATHLEN], def[PATHLEN], sshd_exe[PATHLEN];
    snprintf(cfg, sizeof cfg, "%s\\ssh\\sshd_config", pd);
    snprintf(def, sizeof def, "%s\\sshd_config_default", sshdir);
    snprintf(sshd_exe, sizeof sshd_exe, "%s\\sshd.exe", sshdir);
    if (!plat_is_file(sshd_exe)) snprintf(sshd_exe, sizeof sshd_exe, "%s\\System32\\OpenSSH\\sshd.exe", sr);
    if (!plat_is_file(cfg) && plat_is_file(def)) CopyFileA(def, cfg, TRUE);   /* 老版不会自己生成配置 */
    sshd_start_or_fail(sshd_exe);
    edit_sshd_config(cfg);
    char ak[PATHLEN]; snprintf(ak, sizeof ak, "%s\\ssh\\administrators_authorized_keys", pd);
    add_admin_key(ak);
    char psh[PATHLEN]; snprintf(psh, sizeof psh, "%s\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", sr);
    reg_set(HKEY_LOCAL_MACHINE, L"SOFTWARE\\OpenSSH", L"DefaultShell", W(psh));
    svc_ctl("sshd", 0);
    sshd_start_or_fail(sshd_exe);                         /* 改完配置重启, 起不来同样带取证 */
    ok("ssh", "[1/6] SSH 已就绪(只认我们的钥匙)");
    if (reinstall) { const char *a[] = { "schtasks", "/run", "/tn", "cust-node", NULL }; runw(a, 30); }

    /* 2. 反向通道 */
    {   /* 远程更新(keep_tun): 钥匙和回拨口不变, 守护换成本程序, 不再报钥匙 */
        doing(J.keep_tun ? "通道守护换成 custhub(保留原通道钥匙)" : "设置反向通道");
        char ssh[PATHLEN]; plat_default_ssh(ssh, sizeof ssh);
        if (!plat_is_file(ssh)) jfail("找不到 ssh.exe");
        char kg[PATHLEN], tk[PATHLEN], pub[PATHLEN], pl[512];
        plat_keygen(ssh, kg, sizeof kg);
        pjoin(tk, "tun_ed25519");
        snprintf(pub, sizeof pub, "%s.pub", tk);
        if (!plat_is_file(tk)) { const char *a[] = { kg, "-q", "-t", "ed25519", "-N", "", "-C", "cust-tun", "-f", tk, NULL }; runw(a, 60); }
        if (read_file(pub, pl, sizeof pl) < 0) jfail("生成反向通道密钥失败");
        plat_secure_key(tk);
        write_tunnel_files(ssh);
        kill_scripts(0);
        if (service_setup()) jfail("反向通道服务启动失败");
        if (!J.keep_tun) report_tunkey(pl);
        ok("tun", "[2/6] 反向通道已设置(回拨口 %s)", J.tunport);
    }

    /* 3. 旧版留下的 WireGuard 通道(已停用). 客户原来就有的 WireGuard 程序保留 */
    if (svc_exists("WireGuardTunnel$cust")) {
        doing("移除旧的 WireGuard 通道");
        const char *a[] = { wg, "/uninstalltunnelservice", "cust", NULL }; runw(a, 60); Sleep(3000);
    }
    char ep[PATHLEN], eb[128]; pjoin(ep, "ep.txt");
    if (read_file(ep, eb, sizeof eb) > 0) { eb[strcspn(eb, "\r\n")] = 0; if (eb[0]) { const char *a[] = { "route", "delete", eb, NULL }; runw(a, 30); } DeleteFileA(ep); }
    { char p[PATHLEN]; pjoin(p, "ep.ps1"); DeleteFileA(p); pjoin(p, "cust.conf"); DeleteFileA(p); }
    if (st_get("hadWG", v, sizeof v) == 0 && !strcmp(v, "0") && plat_is_file(wg)) uninstall_products(L"WireGuard");
    if (st_get("hadNNWO", v, sizeof v) == 0 && !strcmp(v, "0"))
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Network\\NewNetworkWindowOff");
    ok("wgclean", "[3/6] 旧 WireGuard 通道已清理(没有则跳过)");

    /* 4. 防火墙: 22 不对外开放(反向通道走本机回环, 防火墙不管), 关掉其它 sshd 全开规则 */
    fw_rules(1, NULL, 0);
    ok("fw", "[4/6] 防火墙已收紧(22 不对外开放)");

    /* 5. 桌面图标: 卸载 / 清理弹窗; 旧看门狗不再需要(新任务每 5 分钟自己拉起) */
    { const char *a[] = { "schtasks", "/delete", "/tn", "cust-remote-watchdog", "/f", NULL }; runw(a, 30); }
    char exe[PATHLEN]; pjoin(exe, "custhub.exe");
    { const char *a[] = { "icacls", exe, "/grant", "*S-1-5-32-545:RX", NULL }; runw(a, 30); }   /* 普通用户双击要能起来(再自己弹 UAC) */
    char shell32[PATHLEN];
    snprintf(shell32, sizeof shell32, "%s\\System32\\shell32.dll,131", sr);
    shortcut("卸载远程维护.lnk", exe, "remove", shell32, "关闭并卸载远程维护通道");
    /* 「工程师登录」: 公共桌面 + 开始菜单(以前指向 engineer.ps1) */
    snprintf(shell32, sizeof shell32, "%s\\System32\\shell32.dll,47", sr);
    shortcut("工程师登录.lnk", exe, "engineer", shell32, "工程师登录");
    { WCHAR sm[MAX_PATH]; start_menu(sm); if (sm[0]) shortcut_in(sm, "工程师登录.lnk", exe, "engineer", shell32, "工程师登录"); }
    snprintf(shell32, sizeof shell32, "%s\\System32\\shell32.dll,131", sr);
    /* 管理端「移除客户」仍按旧路径调 uninstall.ps1: 留个转发到本程序的壳 */
    char un[PATHLEN]; pjoin(un, "uninstall.ps1");
    const char *shim = "\xEF\xBB\xBF" "param([switch]$Force)\r\n& \"$env:ProgramData\\cust-remote\\custhub.exe\" remove $(if ($Force) { '-f' })\r\n";
    write_file(un, shim, strlen(shim));
    if (J.cleanup[0]) {
        static uint8_t cb[9216];
        char cl[PATHLEN]; pjoin(cl, "cleanup.ps1");
        long cn2 = b64_decode(J.cleanup, strlen(J.cleanup), cb + 3, sizeof cb - 3);
        if (cn2 > 0) { cb[0] = 0xEF; cb[1] = 0xBB; cb[2] = 0xBF; write_file(cl, (char *)cb, (size_t)cn2 + 3); }   /* UTF-8 带 BOM, PS 才认中文 */
        const char *a[] = { "icacls", cl, "/grant", "*S-1-5-32-545:RX", NULL }; runw(a, 30);
        snprintf(shell32, sizeof shell32, "%s\\System32\\shell32.dll,32", sr);
        snprintf(line, sizeof line, "-NoProfile -ExecutionPolicy Bypass -File \"%s\"", cl);
        shortcut("清理弹窗广告.lnk", psh, line, shell32, "清理弹窗广告和流氓推广(可恢复)");
    }
    ok("guard", "[5/6] 断线自恢复和桌面图标(卸载/清理弹窗)已设置");

    /* 换壁纸(失败只提示). SYSTEM 身份(远程更新)不碰 */
    int have_wp = 0;
    for (int i = 0; i < J.npkg; i++) if (!strcmp(J.pkg[i].key, "wallpaper")) have_wp = 1;
    if (have_wp && !is_system()) {
        char wp[PATHLEN], wst[PATHLEN], jpg[PATHLEN];
        snprintf(wp, sizeof wp, "%s\\cust-remote-wp", pd);   /* 单独目录: 资源管理器以普通权限读壁纸 */
        plat_mkdir(wp);
        { const char *a[] = { "icacls", wp, "/grant", "*S-1-5-32-545:(OI)(CI)RX", NULL }; runw(a, 30); }
        snprintf(wst, sizeof wst, "%s\\state.txt", wp);
        if (!plat_is_file(wst)) {
            WCHAR cur[MAX_PATH], sty[32], til[32]; char copy[PATHLEN] = "", sid[128];
            reg_get(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"Wallpaper", cur, MAX_PATH);
            reg_get(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"WallpaperStyle", sty, 32);
            reg_get(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"TileWallpaper", til, 32);
            if (cur[0] && GetFileAttributesW(cur) != INVALID_FILE_ATTRIBUTES) {
                const WCHAR *dot = wcsrchr(cur, L'.');
                snprintf(copy, sizeof copy, "%s\\original%s", wp, dot ? U8(dot) : "");
                CopyFileW(cur, W(copy), FALSE);
            }
            my_sid(sid, sizeof sid);
            static char sb[2048];
            snprintf(sb, sizeof sb, "wpPath=%s\r\nwpStyle=%s\r\nwpTile=%s\r\nwpSid=%s\r\n", copy, U8(sty), U8(til), sid);
            write_file(wst, sb, strlen(sb));
        }
        char got[PATHLEN];
        get_pkg("wallpaper", got, sizeof got);
        snprintf(jpg, sizeof jpg, "%s\\wallpaper.jpg", wp);
        if (CopyFileA(got, jpg, FALSE)) set_wallpaper(HKEY_CURRENT_USER, L"Control Panel\\Desktop", W(jpg), L"10", L"0", 1);   /* 10 = 填充 */
        else warn("换壁纸失败");
    }

    doing("等待通道连通");
    link_or_rollback(90);
    ok("link", "[6/6] 反向通道已连通");
    legacy_cleanup();
    char un2[128]; env("USERNAME", un2, sizeof un2, "?");
    report_done(un2, cn);
    say(""); say("==== 接入成功%s ====", J.silent ? "" : ", 窗口 10 秒后自动关闭");
    join_finish(1);
    return 0;
}

int join_platform(int argc, char **argv)
{
    J.os = OS_WIN;
    return join_windows(argc, argv);
}

/* ---------------- 卸载(custhub remove) ---------------- */

int cmd_remove(int argc, char **argv)
{
    int force = argc > 1 && !strcmp(argv[1], "-f");
    if (!plat_is_admin()) {                               /* 桌面图标双击: 自己弹 UAC */
        char self[PATHLEN]; WCHAR wf[PATHLEN];
        plat_self_path(self, sizeof self);
        MultiByteToWideChar(CP_UTF8, 0, self, -1, wf, PATHLEN);
        SHELLEXECUTEINFOW se; memset(&se, 0, sizeof se);
        se.cbSize = sizeof se; se.lpVerb = L"runas"; se.lpFile = wf; se.lpParameters = force ? L"remove -f" : L"remove"; se.nShow = SW_SHOWNORMAL;
        return ShellExecuteExW(&se) ? 0 : 1;
    }
    char pf[PATHLEN], pd[PATHLEN], v[4096];
    env("ProgramFiles", pf, sizeof pf, "C:\\Program Files");
    env("ProgramData", pd, sizeof pd, "C:\\ProgramData");
    out("\n==== 卸载远程维护 ====\n");
    const char *tasks[] = { "cust-remote-watchdog", "cust-uninstall", "cust-tun", "cust-node", "custhub-install" };
    for (int i = 0; i < 5; i++) { const char *a[] = { "schtasks", "/delete", "/tn", tasks[i], "/f", NULL }; runw(a, 30); }
    kill_scripts(1); kill_scripts(0);
    out("  √ [1/4] 断线自恢复任务和反向通道已删除\n");

    char wg[PATHLEN]; snprintf(wg, sizeof wg, "%s\\WireGuard\\wireguard.exe", pf);
    if (svc_exists("WireGuardTunnel$cust")) { const char *a[] = { wg, "/uninstalltunnelservice", "cust", NULL }; runw(a, 60); Sleep(3000); }
    char ep[PATHLEN], eb[128]; pjoin(ep, "ep.txt");
    if (read_file(ep, eb, sizeof eb) > 0) { eb[strcspn(eb, "\r\n")] = 0; if (eb[0]) { const char *a[] = { "route", "delete", eb, NULL }; runw(a, 30); } }
    int had_wg = st_get("hadWG", v, sizeof v) == 0 && !strcmp(v, "1");
    if (!had_wg) uninstall_products(L"WireGuard");
    out(had_wg ? "  √ [2/4] 隧道已删除(WireGuard 是原有的, 保留)\n" : "  √ [2/4] 隧道已删除, WireGuard 已卸载\n");

    char ak[PATHLEN]; static char b[MAXBUF], nw[MAXBUF];
    snprintf(ak, sizeof ak, "%s\\ssh\\administrators_authorized_keys", pd);
    if (read_file(ak, b, sizeof b) >= 0) {
        size_t l = 0; nw[0] = 0; char *cur = b, *ln;
        while ((ln = next_line(&cur))) { size_t n = strlen(ln); if (*ln && !(n >= 11 && !strcmp(ln + n - 11, "cust-remote"))) { sb_add(nw, sizeof nw, &l, ln); sb_add(nw, sizeof nw, &l, "\r\n"); } }
        write_file(ak, nw, l);
        const char *a[] = { "icacls", ak, "/inheritance:r", "/grant", "*S-1-5-32-544:F", "*S-1-5-18:F", NULL }; runw(a, 30);
    }
    if (st_get("hadSSH", v, sizeof v) == 0 && !strcmp(v, "1")) {
        char rules[4096] = "";
        st_get("sshRules", rules, sizeof rules);
        fw_rules(2, rules, sizeof rules);
        char bak[PATHLEN], cfg[PATHLEN];
        pjoin(bak, "sshd_config.bak"); snprintf(cfg, sizeof cfg, "%s\\ssh\\sshd_config", pd);
        if (plat_is_file(bak)) { CopyFileA(bak, cfg, FALSE); svc_ctl("sshd", 0); svc_ctl("sshd", 1); }
        out("  √ [3/4] 我们的 SSH 钥匙已删除(OpenSSH 是原有的, 保留并还原配置)\n");
    } else {
        fw_rules(2, NULL, 0);                              /* 只删 cust-* 规则 */
        svc_ctl("sshd", 0);
        uninstall_products(L"OpenSSH");
        char dst[PATHLEN], un[PATHLEN];
        snprintf(dst, sizeof dst, "%s\\OpenSSH", pf);
        snprintf(un, sizeof un, "%s\\uninstall-sshd.ps1", dst);
        if (plat_is_file(un)) {
            const char *a[] = { "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", un, NULL }; runw(a, 120);
            kill_under(dst);
            const char *r[] = { "cmd", "/c", "rmdir", "/s", "/q", dst, NULL }; runw(r, 60);
        }
        HKEY k;
        if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\OpenSSH", 0, KEY_SET_VALUE | RK64, &k)) { RegDeleteValueW(k, L"DefaultShell"); RegCloseKey(k); }
        out("  √ [3/4] OpenSSH 已卸载\n");
    }
    if (st_get("hadNNWO", v, sizeof v) == 0 && !strcmp(v, "0"))
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Network\\NewNetworkWindowOff");

    /* 恢复接入前的壁纸: 原文件挪到公共图片(我们的目录马上要删); 本人在操作就立即生效, 否则改该用户配置 */
    char wp[PATHLEN], wst[PATHLEN], wb[2048];
    snprintf(wp, sizeof wp, "%s\\cust-remote-wp", pd);
    snprintf(wst, sizeof wst, "%s\\state.txt", wp);
    if (read_file(wst, wb, sizeof wb) > 0) {
        char path[PATHLEN] = "", sty[32] = "", til[32] = "", sid[128] = "", me[128], file[PATHLEN] = "", pub[PATHLEN];
        char *cur = wb, *ln;
        while ((ln = next_line(&cur))) {
            if (!strncmp(ln, "wpPath=", 7)) snprintf(path, sizeof path, "%s", ln + 7);
            else if (!strncmp(ln, "wpStyle=", 8)) snprintf(sty, sizeof sty, "%s", ln + 8);
            else if (!strncmp(ln, "wpTile=", 7)) snprintf(til, sizeof til, "%s", ln + 7);
            else if (!strncmp(ln, "wpSid=", 6)) snprintf(sid, sizeof sid, "%s", ln + 6);
        }
        env("PUBLIC", pub, sizeof pub, "C:\\Users\\Public");
        if (path[0] && plat_is_file(path)) {
            const char *dot = strrchr(path, '.');
            snprintf(file, sizeof file, "%s\\Pictures\\original-wallpaper%s", pub, dot ? dot : "");
            CopyFileW(W(path), W(file), FALSE);
        }
        my_sid(me, sizeof me);
        if (!strcmp(sid, me)) { set_wallpaper(HKEY_CURRENT_USER, L"Control Panel\\Desktop", W(file), W(sty), W(til), 1); out("  √ 壁纸已恢复\n"); }
        else if (sid[0]) {
            WCHAR key[300]; _snwprintf(key, 300, L"%ls\\Control Panel\\Desktop", W(sid));
            if (reg_exists(HKEY_USERS, key)) { set_wallpaper(HKEY_USERS, key, W(file), W(sty), W(til), 0); out("  √ 壁纸已改回原样(该用户下次登录生效)\n"); }
        }
        const char *r[] = { "cmd", "/c", "rmdir", "/s", "/q", wp, NULL }; runw(r, 60);
    }
    shortcut_rm("卸载远程维护.lnk"); shortcut_rm("清理弹窗广告.lnk"); shortcut_rm("工程师登录.lnk");
    { WCHAR sm[MAX_PATH], p[MAX_PATH]; start_menu(sm); if (sm[0]) { _snwprintf(p, MAX_PATH, L"%ls\\%ls", sm, W("工程师登录.lnk")); DeleteFileW(p); } }
    /* 自己所在的目录(连同本程序)最后由一个独立进程延时删除 */
    char cmd[PATHLEN + 80];
    snprintf(cmd, sizeof cmd, "ping -n 6 127.0.0.1 >nul & rmdir /s /q \"%s\"", g_dir);
    const char *dl[] = { "cmd", "/c", cmd, NULL };
    plat_spawn_detached(dl);
    out("  √ [4/4] 桌面图标和安装文件已清理\n\n==== 远程维护已卸载 ====\n");
    if (!force) Sleep(8000);
    return 0;
}
#endif
