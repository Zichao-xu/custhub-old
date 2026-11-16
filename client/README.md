# custhub · 客户机程序

程序名 `custhub`（2026-11-16 起；之前叫 cust-remote）。安装目录、服务名、互斥锁、旧管理钥匙注释仍沿用旧部署的 `cust-remote` / `cust-tun` 等名字，这样装新程序就是原地接管，不用动已部署的环境。

客户机上唯一的程序（SPEC §6），一个 C 二进制取代各平台脚本：

| 功能 | 取代 |
|---|---|
| 通道守护 `tun` | `tun.ps1` / `tun-mac.sh` / `tun-openwrt.sh` |
| 信任清单验签应用（守护里自动做；`trust-apply` 手动） | `trust-apply.ps1` / `.sh` |
| 工程师登录 `engineer` | `engineer.ps1` / `.sh` |
| 自升级（守护里自动做；`upgrade` 手动） | `client-upgrade.sh` 的分块推送 |
| 注册系统服务 `install` / `uninstall` | 各接入脚本里的服务注册 |

## 命令

```
custhub tun [--port N]        通道守护, 常驻
custhub engineer              工程师登录(交互)
custhub trust-apply 文件      从文件里截出签名信任清单 → 验签 → 应用
custhub verify 命名空间 钥匙文件 签名文件 <数据
                                  验签, 等价 ssh-keygen -Y verify(测试用)
custhub install [--port N] [--ssh 路径]
                                  装进安装目录并注册系统服务(原地接管旧脚本守护)
custhub uninstall             注销系统服务(文件留着)
custhub upgrade 清单 二进制    用本地签名发布清单手动升级(换上, 不重启)
custhub version               输出 "custhub 版本 平台"
```

退出码：`trust-apply` 已应用或无需应用 0，验签没过或写失败 1，读不了或输入超长 2；`verify` 通过 0，不通过 1，参数或文件有问题 2；`install` 切换成功 0，失败（已恢复旧服务）1；`upgrade` 换上或无需升级 0，清单或二进制不对 1。

### tun

对 `hubs.txt` 里每台中转保持一条反向通道 `ssh -N -R 127.0.0.1:<回拨口>:127.0.0.1:<本机 sshd 端口> custtun@中转`：

1. 每 5 秒重读 `hubs.txt`，按它重写 known_hosts——只认这些中转的主机钥匙，不认识就拒。
2. 某台中转没有通道时，先不带 `-N` 连一次（kick）：中转踢掉我们占着回拨口的旧连接，顺带发来签名信任清单，守护就地验签应用。
3. 再起 `-N -R` 长连接；连不上的中转 30 秒内不重试，不拖慢其他中转。
4. 从 `hubs.txt` 里删掉的中转：断开。
5. 只跑一个实例；守护退出时子 ssh 一起退出（POSIX 收到信号时逐个杀；Windows 靠作业对象）。

OpenWrt（安装目录下有 `ak/`，或 `ssh` 指向 dbclient）用 dropbear 的参数，known_hosts 写在 `$D/.ssh/known_hosts`，子进程的 `HOME` 设为 `$D`。

`tun --takeover`：升级、回滚时接班用，等上一个进程让出单实例锁（最多 60 秒）再起。

### 自升级

守护约每 10 分钟向正连着的中转取一次**发布清单** `http://中转:http_port/pkg/client/release.txt`（主钥匙签名，命名空间 `custhub-release`），重连做 kick 时也顺带看一次。清单的来历见 spec §6.1：发布者在公开 GitHub 项目建 Release，中转每 10 分钟自己去拉（或从别的中转拉）、验签后放到 `/pkg/client/`。

```
custhub-release v1
version 0.2.0
file <平台> <字节数> <sha512 十六进制>     每个平台一行
--sig-- / 签名 / --end--
```

1. 版本比自己新、有本平台那一行、验签通过（用 `master.pub`）、这个版本没回滚满 2 次 → 从同一台中转下载 `http://中转:http_port/pkg/client/custhub-<版本>-<平台>[.exe]`。HTTP 是明文，但哈希在签名清单里，篡改过不了核对。
2. 核对大小 + SHA-512，再让新程序跑一次 `version`，必须报出对的版本号。
3. 换上：当前程序改名为 `custhub.old`，新的改名就位（Windows 也允许给运行中的 exe 改名）。
4. 重启进新版：Mac/Linux 原地 exec（同一 pid，服务管理器无感）；Windows 起新进程接班后退出（退出码 3，计划任务的失败重启再兜一层）。
5. 试用期：`upgrade.pending` 记 "旧版本 新版本 启动次数"。有通道连上 8 秒以上 → 转正（删掉 pending）。120 秒内没有通道，或连续启动 3 次还在试用 → 回滚到 `.old`，`upgrade.bad` 记一次。
6. 同一版本下载或核对失败后 10 分钟内不再试。

平台名编译时写死（`CR_PLAT`，同构建产物名）；本机开发版是 `dev`，正式清单里不会有，永不自升级。自升级后新进程只从 `client.conf` 读回拨口，所以靠 `--port` 参数跑的守护要先 `install`。

发布：`hub/client-release.sh`（先 `build.sh`，再 `python3 passkey.py unlock`）——签清单，在公开 GitHub 项目建 Release `vX.Y.Z`（附各平台程序 + `custhub.release`），不推任何中转。测试时可设 `CUSTHUB_POLL=秒数` 缩短首次轮询的等待。

### 服务注册（install）

1. 要管理员 / root。
2. 写 `client.conf`：回拨口按 `--port` > 已有 `client.conf` > 旧 `tun.sh`（`PORT=`）/ `tun.ps1`（`$port = '…'`）的顺序取；ssh 路径按 `--ssh` > 已有配置 > 旧 `tun.ps1`（`$ssh = '…'`）。其他已有的项原样保留。
3. 把自己复制成 `$D/custhub[.exe]`（已在那就不动），跑一次 `version` 确认能起。切换成功后删掉改名前留下的 `cust-remote[.exe]` 等旧二进制。
4. 后台切换（`install-finish`）——我们这条 ssh 多半就走在要被重启的通道上：Windows 交给一次性 SYSTEM 计划任务 `custhub-install`；systemd 用 `systemd-run`；其他脱离会话起（OpenWrt 还会挪出 procd 的 cgroup）。
5. 切换：备份旧服务定义到 `svc.bak` → 写新的并重启 → 90 秒内 `tun-status.txt` 出现 `up` 即成功，否则恢复旧的。

| 平台 | 服务 | 新定义 | 失败时恢复 |
|---|---|---|---|
| Windows | 计划任务 `cust-tun` | XML：开机 + 每 5 分钟拉起、不限运行时长（默认 72 小时会被停）、失败 1 分钟后重启；成功后删旧看门狗 `cust-remote-watchdog` | 按 `client.ps1` 原样重建跑 `tun.ps1` 的任务 |
| macOS | LaunchDaemon `com.custremote.tun` | `KeepAlive`，直接跑程序 | `svc.bak` |
| Linux | systemd `cust-remote-tun` | `Restart=always` | `svc.bak`；原来没有就撤掉 |
| OpenWrt | procd `/etc/init.d/cust-remote-tun` | 只换 tun 实例的两处，回环 dropbear 实例不动；首次接入仍用接入脚本 | `svc.bak` |

### 信任清单规则

与旧 `trust-apply` 脚本一致：

- 要维护的 authorized_keys = 候选文件里含旧管理钥匙注释 `cust-remote` 或标记 `custhub-trust:` 的那些（运行时找，不写死账号）。候选文件：
  - Mac/Linux：`/root`、`/var/root`、`/home/*`、`/Users/*` 下的 `.ssh/authorized_keys`
  - OpenWrt：`$D/ak/authorized_keys`
  - Windows：`%ProgramData%\ssh\administrators_authorized_keys`
- 验签钥匙 = 这些文件里旧管理钥匙或 `custhub-trust:master` 的行（`cert-authority` 行不算）；任一段签名通过即可。只认 ed25519 + sha512，命名空间 `custhub-trust`。
- 必须以 `--end--` 收尾，残缺的不应用；版本号只升不降。
- 只替换带 `custhub-trust:` 的行，其他行原样保留，所以清单再错也锁不死旧管理钥匙。
- 每条按账号写法生成：

| 账号 | key | ca |
|---|---|---|
| 普通（sshd） | `from="127.0.0.1,::1" 公钥` | `cert-authority,from="127.0.0.1,::1" 公钥` |
| 放开直连（同目录有 `cust-remote-open`） | `公钥` | `cert-authority,from="127.0.0.1,::1" 公钥` |
| Windows | `公钥` | `cert-authority 公钥` |
| dropbear | `公钥` | 跳过（不认证书） |

- 文件先写临时文件再换上：POSIX 保留原属主和权限；Windows 换上后 `icacls` 收紧为仅管理员组 + SYSTEM。
- 应用成功后另存 `master.pub`：工程师登录以普通用户运行，读不到 root 的 authorized_keys，用它验节点目录。

### engineer

1. 用 `ssh-keygen` 现做临时钥匙。
2. 输入手机验证器 6 位数 → 依次 POST 到各中转 `http://中转:8443/cgi-bin/login` 换 2 小时证书；某台回 403（码错）就不再问别的中转。
3. 经中转 `dir-get` 取节点目录，用主公钥（`master.pub`，没有再读 authorized_keys）验签，命名空间 `custhub-dir`。验签没过就换下一台；本机还没有主公钥时照用，并提示"未验签"。
4. 列出机器和在线状态 → 选一台 → `ssh -o ProxyJump=中转 用户@127.0.0.1 -p 回拨口`。
5. 退出时删掉临时目录（钥匙和证书）。

OpenWrt 上不支持。已知问题：登录请求走明文 HTTP，同一网络里能截包的人可以替换公钥拿走证书（与旧脚本相同，待中转端改）。

## 安装目录 `$D`

| 平台 | 路径 |
|---|---|
| Windows | `%ProgramData%\cust-remote` |
| macOS | `/Library/CustRemote` |
| Linux / OpenWrt | `/opt/cust-remote` |

macOS 判断依据是 `/Library/CustRemote` 是否存在，不存在就用 `/opt/cust-remote`。

### 读的文件

| 文件 | 内容 |
|---|---|
| `client.conf` | 配置，见下 |
| `hubs.txt` | 每行 `地址 端口 ssh-ed25519 公钥`；格式不对的行跳过 |
| `sshport` | 本机 sshd 端口（旧 OpenWrt 安装写的；`client.conf` 没写 `sshport` 时用） |
| `tun_ed25519` / `tun_key` | 通道钥匙（`client.conf` 没写 `key` 时依次找） |
| `ak/` | 存在即视为 OpenWrt（dropbear） |

### 写的文件

| 文件 | 内容 |
|---|---|
| `hubs_known` | known_hosts（OpenSSH） |
| `.ssh/known_hosts` | known_hosts（dropbear） |
| `tun-status.txt` | 每行 `中转 up|connecting|down` |
| `trust.ver` | 已应用的信任清单版本 |
| `master.pub` | 主公钥 |
| `tun.log` / `trust.log` | 日志，超过 1MB 从头写 |
| `custhub[.exe]`、`custhub.old` / `.new` / `.bad` | 程序本身；换下的旧版（回滚用）/ 下载中的新版 / 回滚换下的版本 |
| `upgrade.pending` / `upgrade.bad` / `upgrade.log` | 试用期状态 / 回滚过的版本和次数 / 升级日志 |
| `svc.bak` / `service.log` | 切换前的服务定义 / 服务切换日志（不叫 install.log：那是旧接入脚本的 UTF-16 记录） |
| `install.lock` | 安装切换的单实例锁（POSIX） |
| `tun.lock` | 单实例锁（POSIX）；Windows 用互斥锁 `Global\cust-remote-tun`，与旧 `tun.ps1` 同名，两者不会同时跑 |

## client.conf

一行一项 `键 值`，`#` 开头为注释；没写的项按本机情况推断。

| 键 | 含义 | 默认 |
|---|---|---|
| `port` | 本机在中转上的回拨口 | 无，`tun` 必填（或 `--port N`） |
| `sshport` | 本机 sshd 端口 | `sshport` 文件，再没有就 22 |
| `ssh` | ssh 客户端路径 | Windows：`%ProgramFiles%\OpenSSH\ssh.exe` → `%SystemRoot%\System32\OpenSSH\ssh.exe`；其他：`PATH` 里的 `ssh`；OpenWrt：`dbclient` |
| `key` | 通道私钥 | `$D/tun_ed25519`，没有就 `$D/tun_key` |
| `http_port` | 中转的 HTTP 端口（工程师登录、下载发布物） | 8443 |

`ssh` 路径里含 `dbclient` 即按 dropbear 处理。`engineer` 用的 `ssh-keygen` 取 `ssh` 的同一目录。

## 环境变量

只供测试，正式安装不要设：

| 变量 | 作用 |
|---|---|
| `CUSTHUB_D` | 改安装目录。Windows 上单实例互斥锁随之改名为 `Global\cust-remote-tun-test`，测试不会被在跑的守护挡住 |
| `CUSTHUB_AK_FILES` | 指定要维护的 authorized_keys，替代上面的候选文件。Mac/Linux 可写多个（空格分隔）；Windows 只认一个路径 |
| `CUSTHUB_SVC_DRY` | 设了就是演练模式：`install` / `uninstall` 的系统命令只记到 `$D/dry/cmds.log`，服务文件写到 `$D/dry/<原路径>`，不需要 root，切换同步做 |
| `CUSTHUB_SVC_KIND` | 演练时指定平台：`mac` / `systemd` / `procd` |
| `CUSTHUB_WAIT` | 切换后等通道的秒数（默认 90） |

## 构建

```bash
./build.sh native   # 本机一份 ./custhub, 开发测试用
./build.sh          # 全平台 → ../../pkg/client/, 打印大小和 sha256
```

测试用的变量：`native` 模式下 `OUTBIN=路径 VER=版本号` 编一份"别的版本"，`PLAT=` 改平台名；全平台模式下 `OUTDIR=目录 VER=版本号 ONLY=平台名前缀`（如 `ONLY=win`）。

依赖：zig（Linux、macOS 交叉编译和 Windows 链接）、本机 clang（编 Windows 目标）、Windows sysroot。

Windows 版链系统自带的 `msvcrt.dll`，不链 UCRT（没打 KB2999226 补丁的 Win7 没有 UCRT）。sysroot 取 llvm-mingw 20261104 的 msvcrt 版，放在 `$MINGW`（默认 `~/.cache/llvm-mingw-msvcrt-20261104`），下载地址和 sha256 写在 `build.sh` 开头。构建会检查 exe 只依赖 kernel32 / ws2_32 / msvcrt / advapi32。

| 目标 | 产物 |
|---|---|
| Windows x64 / x86 | `custhub-版本-win-x64.exe` / `win-x86.exe` |
| macOS arm64 / x86_64 | `mac-arm64` / `mac-x64` |
| Linux amd64 / arm64（musl 静态） | `linux-amd64` / `linux-arm64` |
| OpenWrt armv5 / mips / mipsel（musl 静态，软浮点） | `linux-armv5` / `linux-mips` / `linux-mipsel` |

版本号在 `cr.h` 的 `CR_VERSION`。

## 测试

```bash
./test.sh
```

用临时钥匙、假 ssh 和本机 HTTP 服务，不碰真机器，共 48 项：验签与 ssh-keygen 互通、清单应用规则、防重放、超长输入、dropbear 格式、守护的起停、退避、单实例；自升级（拒收、换上、回滚、转正、kick → 下载 → 换上的全流程）；服务注册演练（systemd / OpenWrt / macOS 的切换与恢复、旧脚本迁移）。

Windows 没有进仓库的测试脚本，已在 Win7 x64（PowerShell 2.0）上实测：验签、应用、ACL、kick 输出抓取、守护起停、单实例、子进程随守护退出（16 项）；手动升级、运行中改名回滚 + 接班、转正、install 演练、计划任务 XML 被系统接受（17 项）。

## 代码

| 文件 | 内容 |
|---|---|
| `main.c` | 入口和子命令 |
| `tun.c` | 通道守护 |
| `trust.c` | 签名文件解析、信任清单应用、主公钥 |
| `sshsig.c` | `ssh-keygen -Y sign` 签名校验 |
| `engineer.c` | 工程师登录 |
| `http.c` | 最小 HTTP/1.0 客户端（登录 POST、下载发布物 GET） |
| `upgrade.c` | 自升级：发布清单、下载核对、换上、试用期与回滚 |
| `install.c` | 服务注册：install / install-finish / uninstall |
| `util.c` | 安装目录、读写文件、base64、配置 |
| `posix.c` / `win.c` | 平台层：进程、文件替换、控制台 |
| `vendor/` | Monocypher 4.0.2（含可选 ed25519 模块）；官网与 GitHub 两份源码核对一致 |

约定：输入一律用定长缓冲解析，超长就拒；密码学只调 Monocypher；SSH 只调系统的 ssh / dbclient。
