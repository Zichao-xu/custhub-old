/* 服务注册(SPEC §6: 注册系统服务由程序自己完成)
 *   install         把自己装进安装目录, 写 client.conf, 后台切换服务(沿用旧脚本守护的服务名 = 原地接管)
 *   install-finish  后台那一半: 备份旧服务定义 → 换成新的并重启 → 90 秒内没有通道就恢复旧的
 *   uninstall       注销服务(文件留着; 整套卸载仍用各平台 uninstall 脚本)
 * 切换必须放后台: 我们这条 ssh 多半就走在要被重启的通道上
 * 演练模式 CUSTHUB_SVC_DRY=1(测试用): 命令只记到 $D/dry/cmds.log, 服务文件写到 $D/dry/<原路径>,
 *   平台由 CUSTHUB_SVC_KIND=mac|systemd|procd 指定, 等通道的秒数由 CUSTHUB_WAIT 指定
 * 日志写 service.log(不用 install.log: 旧接入脚本的 UTF-16 记录叫这个名字) */
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

enum { K_NONE, K_WIN, K_MAC, K_SYSTEMD, K_PROCD };
#define MAC_PLIST "/Library/LaunchDaemons/com.custremote.tun.plist"
#define MAC_LABEL "system/com.custremote.tun"
#define SD_UNIT   "/etc/systemd/system/cust-remote-tun.service"
#define PROCD     "/etc/init.d/cust-remote-tun"

static int dry(void) { return getenv("CUSTHUB_SVC_DRY") != NULL; }

static int kind(void)
{
#ifdef _WIN32
    return K_WIN;
#else
    const char *k = getenv("CUSTHUB_SVC_KIND");
    if (k) return !strcmp(k, "mac") ? K_MAC : !strcmp(k, "systemd") ? K_SYSTEMD : !strcmp(k, "procd") ? K_PROCD : K_NONE;
    if (plat_is_dir("/Library/LaunchDaemons")) return K_MAC;
    if (plat_is_file("/etc/openwrt_release")) return K_PROCD;
    if (plat_is_file("/bin/systemctl") || plat_is_file("/usr/bin/systemctl")) return K_SYSTEMD;
    return K_NONE;
#endif
}

static void mkdir_p(const char *path)
{
    char p[PATHLEN];
    snprintf(p, sizeof p, "%s", path);
    for (char *s = p + 1; *s; s++)
        if (*s == '/' || *s == '\\') { char c = *s; *s = 0; plat_mkdir(p); *s = c; }
    plat_mkdir(p);
}

/* 服务文件的实际路径(演练时落到 $D/dry 下) */
static void real(char *out, const char *path)
{
    if (!dry()) { snprintf(out, PATHLEN, "%s", path); return; }
    char d[PATHLEN];
    pjoin(d, "dry");
    snprintf(out, PATHLEN, "%s%s", d, path);
    char dir[PATHLEN]; snprintf(dir, sizeof dir, "%s", out);
    char *s = strrchr(dir, '/'); if (s) { *s = 0; mkdir_p(dir); }
}

static int sys(const char *const *av)
{
    char line[2048]; size_t l = 0; line[0] = 0;
    for (int i = 0; av[i]; i++) { sb_add(line, sizeof line, &l, i ? " " : ""); sb_add(line, sizeof line, &l, av[i]); }
    if (dry()) {
        char p[PATHLEN]; pjoin(p, "dry/cmds.log");
        char d[PATHLEN]; pjoin(d, "dry"); mkdir_p(d);
        FILE *f = fopen(p, "ab"); if (f) { fprintf(f, "%s\n", line); fclose(f); }
        return 0;
    }
    static char outb[4096];
    int r = plat_run(av, outb, sizeof outb, 60);
#ifdef _WIN32
    {   /* 系统命令按 OEM 代码页(中文系统是 GBK)输出, 日志统一 UTF-8 */
        static WCHAR w[4096]; static char u[8192];
        int k = MultiByteToWideChar(CP_OEMCP, 0, outb, -1, w, 4096);
        if (k > 0 && WideCharToMultiByte(CP_UTF8, 0, w, -1, u, sizeof u, NULL, NULL) > 0) snprintf(outb, sizeof outb, "%s", u);
    }
#endif
    for (char *q = outb; *q; q++) if (*q == '\r' || *q == '\n') *q = ' ';
    cr_log("service.log", "$ %s → %d %s", line, r, outb);
    return r;
}

static int copy_file(const char *src, const char *dst)
{
    FILE *i = fopen(src, "rb");
    if (!i) return -1;
    char tmp[PATHLEN + 16];
    snprintf(tmp, sizeof tmp, "%s.cr-new", dst);
    FILE *o = fopen(tmp, "wb");
    if (!o) { fclose(i); return -1; }
    char buf[16384]; size_t n; int bad = 0;
    while ((n = fread(buf, 1, sizeof buf, i)) > 0) if (fwrite(buf, 1, n, o) != n) bad = 1;
    fclose(i);
    if (fclose(o) || bad) { remove(tmp); return -1; }
    if (plat_replace(tmp, dst)) { remove(tmp); return -1; }
    return 0;
}

/* 从旧脚本里取回拨口/ssh 路径(迁移用) */
static void from_old_scripts(char *port, char *ssh)
{
    static char buf[MAXBUF];
    char p[PATHLEN];
    pjoin(p, "tun.ps1");
    if (read_file(p, buf, sizeof buf) >= 0) {
        char *s;
        if (!port[0] && (s = strstr(buf, "$port = '"))) { s += 9; size_t n = strspn(s, "0123456789"); if (n && n < 6 && s[n] == '\'') memcpy(port, s, n), port[n] = 0; }
        if (!ssh[0] && (s = strstr(buf, "$ssh = '"))) { s += 8; char *e = strchr(s, '\''); if (e && e - s < PATHLEN && e > s) memcpy(ssh, s, (size_t)(e - s)), ssh[e - s] = 0; }
    }
    pjoin(p, "tun.sh");
    if (!port[0] && read_file(p, buf, sizeof buf) >= 0) {
        char *s = strstr(buf, "PORT=");
        if (s) { s += 5; size_t n = strspn(s, "0123456789"); if (n && n < 6) memcpy(port, s, n), port[n] = 0; }
    }
}

int install_copy_self(void)
{
    char self[PATHLEN], target[PATHLEN];
    pjoin(target, "custhub" EXE);
    if (plat_self_path(self, sizeof self)) return -1;
    if (!strcmp(self, target)) return 0;
    if (plat_is_file(target)) { char o[PATHLEN]; pjoin(o, "custhub.old" EXE); remove(o); plat_replace(target, o); }
    if (copy_file(self, target)) return -1;
    plat_make_exec(target);
    return 0;
}

static int svc_switch(const char *exe);
static void svc_restore(void);

/* 接入时: 换守护前是否有旧守护可回退(Windows 看旧 tun.ps1; 其他看切换时备份的服务定义) */
int service_had_prior(void)
{
    char p[PATHLEN];
#ifdef _WIN32
    pjoin(p, "tun.ps1");
#else
    pjoin(p, "svc.bak");
#endif
    return plat_is_file(p);
}

void service_restore(void) { svc_restore(); }

int service_setup(void)
{
    char exe[PATHLEN];
    pjoin(exe, "custhub" EXE);
    return svc_switch(exe);
}

int cmd_install(int argc, char **argv)
{
    char port[16] = "", ssh[PATHLEN] = "", p[PATHLEN];
    for (int i = 1; i + 1 < argc; i++) {
        if (!strcmp(argv[i], "--port") && all_digits(argv[i + 1], 5)) snprintf(port, sizeof port, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--ssh") && strlen(argv[i + 1]) < PATHLEN) snprintf(ssh, sizeof ssh, "%s", argv[++i]);
    }
    if (!dry() && !plat_is_admin()) { out("需要管理员 / root\n"); return 1; }
    if (kind() == K_NONE) { out("认不出这台机器的服务管理方式(launchd / systemd / procd / 计划任务)\n"); return 1; }
    if (kind() == K_PROCD) {
        char ini[PATHLEN]; real(ini, PROCD);
        if (!plat_is_file(ini)) { out("OpenWrt 首次接入仍用接入脚本(要配回环 dropbear); 这里只接管已有的 %s\n", PROCD); return 1; }
    }
    mkdir_p(g_dir);

    /* client.conf: 参数 > 已有配置 > 旧脚本; 其他已有的项原样保留 */
    conf_t c; conf_load(&c);
    static char old[4096], nw[4096]; size_t nl = 0; nw[0] = 0;
    pjoin(p, "client.conf");
    int had_port = 0, had_ssh = 0;
    if (read_file(p, old, sizeof old) >= 0) {
        char *cur = old, *l;
        while ((l = next_line(&cur))) {
            if (!strncmp(l, "port ", 5)) { had_port = 1; if (port[0]) continue; }
            if (!strncmp(l, "ssh ", 4)) { had_ssh = 1; if (ssh[0]) continue; }
            if (*l) { sb_add(nw, sizeof nw, &nl, l); sb_add(nw, sizeof nw, &nl, "\n"); }
        }
    }
    if (!port[0] && had_port) snprintf(port, sizeof port, "%s", c.port);
    char oport[16] = "", ossh[PATHLEN] = "";
    from_old_scripts(oport, ossh);
    if (!port[0]) snprintf(port, sizeof port, "%s", oport);
    if (!ssh[0] && !had_ssh && ossh[0]) snprintf(ssh, sizeof ssh, "%s", ossh);
    if (!port[0]) { out("不知道回拨口: 加 --port N(旧脚本和 client.conf 里都没找到)\n"); return 1; }
    char line[PATHLEN + 16];
    if (!had_port || strcmp(port, c.port)) { snprintf(line, sizeof line, "port %s\n", port); sb_add(nw, sizeof nw, &nl, line); }
    if (ssh[0]) { snprintf(line, sizeof line, "ssh %s\n", ssh); sb_add(nw, sizeof nw, &nl, line); }
    if (write_file(p, nw, nl)) { out("写不了 %s\n", p); return 1; }

    /* 程序本身装进安装目录(已经在那就不动) */
    char target[PATHLEN];
    pjoin(target, "custhub" EXE);
    if (install_copy_self()) { out("复制到 %s 失败\n", target); return 1; }
    char ver[256];
    const char *vav[] = { target, "version", NULL };
    if (plat_run(vav, ver, sizeof ver, 20) != 0) { out("%s 跑不起来\n", target); return 1; }
    ver[strcspn(ver, "\r\n")] = 0;
    out("已装好 %s(%s), 回拨口 %s\n", target, ver, port);

    if (dry()) return cmd_install_finish();
    int r = -1;
#ifdef _WIN32
    /* sshd 会话里起的进程会随会话(和通道)一起被清掉: 交给一次性 SYSTEM 计划任务跑 */
    char tr[PATHLEN + 32];
    snprintf(tr, sizeof tr, "%s install-finish", target);
    const char *c1[] = { "schtasks", "/create", "/tn", "custhub-install", "/ru", "SYSTEM", "/sc", "once", "/st", "00:00", "/f", "/tr", tr, NULL };
    const char *c2[] = { "schtasks", "/run", "/tn", "custhub-install", NULL };
    if (sys(c1) == 0) r = sys(c2);
#else
    if (kind() == K_SYSTEMD) {
        const char *sr[] = { "systemd-run", "--unit=custhub-install", "--collect", target, "install-finish", NULL };
        r = sys(sr);
    }
    if (r != 0) { const char *fav[] = { target, "install-finish", NULL }; r = plat_spawn_detached(fav); }
#endif
    if (r != 0) { out("起不了后台切换\n"); return 1; }
    out("3 秒后切换服务; 90 秒内没有通道连上会自动恢复旧服务。结果看 %s%sservice.log\n", g_dir, EXE[0] ? "\\" : "/");
    return 0;
}

/* ---------------- 各平台服务定义 ---------------- */

#ifdef _WIN32
static int win_task_new(const char *exe)
{
    char xml[4096], p[PATHLEN];
    int n = snprintf(xml, sizeof xml,
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
        "<RegistrationInfo><Description>custhub reverse tunnel</Description></RegistrationInfo>\r\n"
        "<Triggers>\r\n"
        "<BootTrigger><Enabled>true</Enabled></BootTrigger>\r\n"
        "<TimeTrigger><StartBoundary>2020-01-01T00:00:00</StartBoundary><Enabled>true</Enabled>"
        "<Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>\r\n"
        "</Triggers>\r\n"
        "<Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n"
        "<Settings>\r\n"
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
        "<AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>\r\n"
        "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
        "<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\r\n"
        "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>\r\n"
        "<RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun>\r\n"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>5</Priority>\r\n"
        "<RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>\r\n"
        "</Settings>\r\n"
        "<Actions Context=\"Author\"><Exec><Command>%s</Command><Arguments>tun</Arguments></Exec></Actions>\r\n"
        "</Task>\r\n", exe);
    if (n <= 0 || n >= (int)sizeof xml) return -1;
    /* schtasks /xml 要 UTF-16 */
    static WCHAR w[4200];
    w[0] = 0xFEFF;
    int k = MultiByteToWideChar(CP_ACP, 0, xml, n, w + 1, 4199);
    if (k <= 0) return -1;
    pjoin(p, "cust-tun.xml");
    if (write_file(p, (const char *)w, (size_t)(k + 1) * 2)) return -1;
    const char *c[] = { "schtasks", "/create", "/tn", "cust-tun", "/xml", p, "/f", NULL };
    int r = sys(c);
    if (!dry()) remove(p);                                 /* 演练时留着给测试检查 */
    return r;
}

static void win_kill_old(void)
{
    const char *ps[] = { "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like '*cust-remote\\tun.ps1*' -or $_.CommandLine -like '*custtun@*' -or "
        "(($_.Name -eq 'custhub.exe' -or $_.Name -eq 'cust-remote.exe') -and $_.CommandLine -like '* tun*') } | ForEach-Object { try { $_.Terminate() | Out-Null } catch {} }", NULL };
    const char *e[] = { "schtasks", "/end", "/tn", "cust-tun", NULL };
    sys(e); sys(ps);
}

static int svc_switch(const char *exe)
{
    win_kill_old();
    if (win_task_new(exe)) return -1;
    const char *r[] = { "schtasks", "/run", "/tn", "cust-tun", NULL };
    return sys(r);
}

static void svc_restore(void)
{
    char ps1[PATHLEN], tr[PATHLEN + 96];
    pjoin(ps1, "tun.ps1");
    win_kill_old();
    if (!plat_is_file(ps1)) { cr_log("service.log", "没有旧 tun.ps1, 无从恢复"); return; }
    snprintf(tr, sizeof tr, "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File %s", ps1);
    const char *c[] = { "schtasks", "/create", "/tn", "cust-tun", "/ru", "SYSTEM", "/sc", "onstart", "/f", "/tr", tr, NULL };
    const char *r[] = { "schtasks", "/run", "/tn", "cust-tun", NULL };
    sys(c); sys(r);
}

static void svc_commit(void)
{
    const char *c[] = { "schtasks", "/delete", "/tn", "cust-remote-watchdog", "/f", NULL };   /* 新任务自己每 5 分钟拉起, 旧看门狗不要了 */
    sys(c);
}

static void svc_cleanup(void)
{
    const char *c[] = { "schtasks", "/delete", "/tn", "custhub-install", "/f", NULL };
    sys(c);
}

int cmd_uninstall(void)
{
    if (!plat_is_admin()) { out("需要管理员\n"); return 1; }
    const char *e[] = { "schtasks", "/end", "/tn", "cust-tun", NULL };
    const char *d1[] = { "schtasks", "/delete", "/tn", "cust-tun", "/f", NULL };
    const char *d2[] = { "schtasks", "/delete", "/tn", "cust-remote-watchdog", "/f", NULL };
    sys(e); sys(d1); sys(d2); win_kill_old();
    out("已注销计划任务 cust-tun\n");
    return 0;
}

#else /* ---------------- POSIX ---------------- */

static const char *svc_file(int k) { return k == K_MAC ? MAC_PLIST : k == K_SYSTEMD ? SD_UNIT : PROCD; }

static int svc_apply(int k, const char *file)
{
    if (k == K_MAC) {
        const char *b1[] = { "launchctl", "bootout", MAC_LABEL, NULL };
        const char *b2[] = { "launchctl", "bootstrap", "system", file, NULL };
        sys(b1);                                           /* launchd 连同进程组(旧 tun.sh 的 ssh)一起停 */
        return sys(b2);
    }
    if (k == K_SYSTEMD) {
        const char *a[] = { "systemctl", "daemon-reload", NULL };
        const char *b[] = { "systemctl", "enable", "cust-remote-tun", NULL };
        const char *r[] = { "systemctl", "restart", "cust-remote-tun", NULL };
        sys(a); sys(b);
        return sys(r);
    }
    const char *s[] = { PROCD, "start", NULL };          /* procd: 只重启定义变了的实例(回环 dropbear 不动) */
    return sys(s);
}

static int svc_switch(const char *exe)
{
    int k = kind();
    char f[PATHLEN], bak[PATHLEN];
    static char cur[16384], nw[16384];
    real(f, svc_file(k));
    pjoin(bak, "svc.bak");
    long n = read_file(f, cur, sizeof cur);
    if (n >= 0 && write_file(bak, cur, (size_t)n)) return -1;
    if (n < 0) remove(bak);
    size_t l = 0;
    if (k == K_MAC) {
        l = (size_t)snprintf(nw, sizeof nw,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\"><dict>\n"
            "<key>Label</key><string>com.custremote.tun</string>\n"
            "<key>ProgramArguments</key><array><string>%s</string><string>tun</string></array>\n"
            "<key>RunAtLoad</key><true/>\n"
            "<key>KeepAlive</key><true/>\n"
            "<key>ThrottleInterval</key><integer>10</integer>\n"
            "<key>StandardErrorPath</key><string>%s/tun.err</string>\n"
            "</dict></plist>\n", exe, g_dir);
    } else if (k == K_SYSTEMD) {
        l = (size_t)snprintf(nw, sizeof nw,
            "[Unit]\nDescription=custhub reverse ssh tunnel\nAfter=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nExecStart=%s tun\nRestart=always\nRestartSec=10\nKillMode=control-group\n\n"
            "[Install]\nWantedBy=multi-user.target\n", exe);
    } else {
        /* OpenWrt: 只换 tun 实例那两处, 回环 dropbear 实例原样保留 */
        if (n < 0) return -1;
        char a1[PATHLEN + 64], a2[PATHLEN + 64], b1[PATHLEN + 64], b2[PATHLEN + 64];
        snprintf(a1, sizeof a1, "procd_set_param command /bin/sh %s/tun.sh", g_dir);
        snprintf(b1, sizeof b1, "procd_set_param command %s tun", exe);
        snprintf(a2, sizeof a2, "[ -x %s/tun.sh ]", g_dir);
        snprintf(b2, sizeof b2, "[ -x %s ]", exe);
        char *cp = cur;
        nw[0] = 0;
        int hit = 0;
        while (*cp) {
            const char *from = NULL, *to = NULL;
            if (!strncmp(cp, a1, strlen(a1))) { from = a1; to = b1; }
            else if (!strncmp(cp, a2, strlen(a2))) { from = a2; to = b2; }
            if (from) { if (sb_add(nw, sizeof nw, &l, to)) return -1; cp += strlen(from); hit++; continue; }
            char ch[2] = { *cp++, 0 };
            if (sb_add(nw, sizeof nw, &l, ch)) return -1;
        }
        if (hit != 2 && !strstr(cur, b1)) { cr_log("service.log", "%s 的格式认不出, 不改", PROCD); return -1; }
    }
    if (write_file(f, nw, l)) return -1;
    if (k == K_PROCD) plat_make_exec(f);
    return svc_apply(k, f);
}

static void svc_restore(void)
{
    int k = kind();
    char f[PATHLEN], bak[PATHLEN];
    static char buf[16384];
    real(f, svc_file(k));
    pjoin(bak, "svc.bak");
    long n = read_file(bak, buf, sizeof buf);
    if (n < 0) {                                           /* 原来没有服务: 撤掉新装的 */
        cr_log("service.log", "原来没有服务定义, 撤掉新装的");
        if (k == K_MAC) { const char *b[] = { "launchctl", "bootout", MAC_LABEL, NULL }; sys(b); }
        if (k == K_SYSTEMD) { const char *b[] = { "systemctl", "disable", "--now", "cust-remote-tun", NULL }; sys(b); }
        remove(f);
        return;
    }
    write_file(f, buf, (size_t)n);
    if (k == K_PROCD) plat_make_exec(f);
    svc_apply(k, f);
}

static void svc_commit(void) {}
static void svc_cleanup(void) {}

int cmd_uninstall(void)
{
    int k = kind();
    if (!dry() && !plat_is_admin()) { out("需要 root\n"); return 1; }
    char f[PATHLEN]; real(f, k == K_MAC ? MAC_PLIST : SD_UNIT);
    if (k == K_MAC) { const char *b[] = { "launchctl", "bootout", MAC_LABEL, NULL }; sys(b); remove(f); }
    else if (k == K_SYSTEMD) {
        const char *b[] = { "systemctl", "disable", "--now", "cust-remote-tun", NULL };
        const char *r[] = { "systemctl", "daemon-reload", NULL };
        sys(b); remove(f); sys(r);
    } else { out("OpenWrt 用 %s/uninstall.sh 整套卸载\n", g_dir); return 1; }
    out("已注销服务\n");
    return 0;
}
#endif

static int tunnel_up(void)
{
    char p[PATHLEN], buf[4096];
    pjoin(p, "tun-status.txt");
    if (read_file(p, buf, sizeof buf) < 0 || strncmp(buf, "# custhub ", 10)) return 0;   /* 只认本程序写的 */
    return strstr(buf, " up\n") != NULL || strstr(buf, " up\r\n") != NULL;
}

int cmd_install_finish(void)
{
    if (!plat_single_instance("install")) return 0;
    char exe[PATHLEN], st[PATHLEN];
    pjoin(exe, "custhub" EXE);
    pjoin(st, "tun-status.txt");
    const char *w = getenv("CUSTHUB_WAIT");
    int wait = w && all_digits(w, 4) ? atoi(w) : 90;
    if (!dry()) plat_sleep(3);                            /* 让发起 install 的那条 ssh 先回话 */
    cr_log("service.log", "切换服务 → %s tun", exe);
    remove(st);
    if (svc_switch(exe)) {
        cr_log("service.log", "写新服务失败, 恢复旧服务");
        svc_restore(); svc_cleanup();
        return 1;
    }
    for (int i = 0; i < wait; i++) {
        if (tunnel_up()) {
            svc_commit(); svc_cleanup();
            /* 改名前的二进制(cust-remote)用不着了 */
            const char *legacy[] = { "cust-remote" EXE, "cust-remote.old" EXE, "cust-remote.new" EXE, "cust-remote.bad" EXE };
            for (size_t j = 0; j < sizeof legacy / sizeof *legacy; j++) { char lp[PATHLEN]; pjoin(lp, legacy[j]); remove(lp); }
            cr_log("service.log", "成功: 新守护已有通道连上(%d 秒)", i);
            return 0;
        }
        plat_sleep(1);
    }
    cr_log("service.log", "%d 秒内没有通道连上, 恢复旧服务", wait);
    svc_restore(); svc_cleanup();
    return 1;
}
