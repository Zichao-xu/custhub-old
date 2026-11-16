/* custhub 客户机程序 · 入口
 *   custhub tun [--port N]        通道守护(系统服务里常驻)
 *   custhub engineer              工程师登录
 *   custhub trust-apply 文件      手动应用一份信任清单(调试/迁移)
 *   custhub verify 命名空间 钥匙文件 签名文件 <数据   验签, 等价 ssh-keygen -Y verify(测试用)
 *   custhub version */
#include "cr.h"
#include "plat.h"
#include <stdio.h>
#include <string.h>

static int cmd_verify(int argc, char **argv)
{
    if (argc != 5) return 2;
    static char kb[MAXBUF], sb[8192], data[MAXBUF];
    uint8_t keys[MAXKEYS][32];
    int nk = 0;
    if (read_file(argv[3], kb, sizeof kb) < 0 || read_file(argv[4], sb, sizeof sb) < 0) return 2;
    char *cur = kb, *l;
    while ((l = next_line(&cur)) && nk < MAXKEYS) {
        char b64[128];
        if (!find_ed25519(l, b64, sizeof b64) && !pub_from_b64(b64, keys[nk])) nk++;
    }
    size_t n = fread(data, 1, sizeof data, stdin);
    if (n == sizeof data) return 2;
    int ok = sshsig_verify(sb, (uint8_t *)data, n, argv[2], keys, nk);
    out(ok ? "ok\n" : "bad\n");
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    plat_console_init();
    cr_init_dir();
    const char *c = argc > 1 ? argv[1] : "";
    if (!strcmp(c, "tun")) return cmd_tun(argc - 1, argv + 1);
    if (!strcmp(c, "engineer")) return cmd_engineer();
    if (!strcmp(c, "verify")) return cmd_verify(argc, argv);
    if (!strcmp(c, "trust-apply") && argc == 3) {
        static char buf[MAXBUF];
        long n = read_file(argv[2], buf, sizeof buf);
        if (n == -2) { out("输入超长(上限 %d 字节), 拒\n", MAXBUF); return 2; }
        if (n < 0) return 2;
        int r = trust_apply(buf);
        out(r > 0 ? "已应用\n" : r == 0 ? "无需应用\n" : "没应用(见 trust.log)\n");
        return r < 0;
    }
    if (!strcmp(c, "version")) { out("custhub %s %s\n", CR_VERSION, CR_PLAT); return 0; }
    if (!strcmp(c, "upgrade") && argc == 4) return cmd_upgrade_file(argv[2], argv[3]);
    if (!strcmp(c, "install")) return cmd_install(argc - 1, argv + 1);
    if (!strcmp(c, "install-finish")) return cmd_install_finish();
    if (!strcmp(c, "uninstall")) return cmd_uninstall();
    if (!strcmp(c, "join")) return cmd_join(argc - 1, argv + 1);
    if (!strcmp(c, "remove")) return cmd_remove(argc - 1, argv + 1);
    out("用法:\n"
        "  custhub tun [--port N]       通道守护\n"
        "  custhub engineer             工程师登录\n"
        "  custhub trust-apply 文件     应用一份签名信任清单\n"
        "  custhub verify 命名空间 钥匙文件 签名文件 <数据\n"
        "                                   验签(等价 ssh-keygen -Y verify)\n"
        "  custhub install [--port N] [--ssh 路径]\n"
        "                                   装到安装目录并注册系统服务(接管旧脚本守护)\n"
        "  custhub uninstall            注销系统服务\n"
        "  custhub join 地址             接入(一行命令下载本程序后调用)\n"
        "  custhub remove [-f]          卸载远程维护, 还原安装前状态\n"
        "  custhub upgrade 清单 二进制   用本地签名发布清单手动升级\n"
        "  custhub version\n"
        "安装目录 %s; 配置 client.conf; 说明见 src/client/README.md\n", g_dir);
    return 2;
}
