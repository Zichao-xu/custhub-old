#!/usr/bin/env python3
# admin.py — 任意一台自有机器(Mac/Linux)凭口令变成管理机(SPEC §4): 不需要这台 Mac 上的任何文件
#   python3 admin.py setup 中转地址    输入口令 → 解锁 → 从中转取签名节点目录 → 验签 → 写好 ssh 配置; 之后 ssh c-N
#   python3 admin.py unlock            以后每次用前解锁(默认 8 小时)
#   python3 admin.py refresh           重新取目录(新接入了客户机时)
#   python3 admin.py list              目录里的客户机
#   python3 admin.py route c-N         (ssh 的 ProxyCommand 用) 找它在线的中转, 经回拨口接过去
# 需要: python3、ssh、ssh-keygen、ssh-agent; 和 passkey.py 放在同一目录
# 文件都在 ~/.custhub/; ssh 配置写在 ~/.ssh/config 的 "# custhub-admin begin/end" 段里(重跑会整段替换)
import base64, os, re, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import passkey

H = os.path.expanduser("~/.custhub")
DIR, MPUB, KH, KHN = (os.path.join(H, n) for n in ("dir", "master.pub", "known_hosts", "known_hosts_nodes"))
CFG = os.path.expanduser("~/.ssh/config")
BEGIN, END = "# custhub-admin begin", "# custhub-admin end"
TUN_BASE = 22000


def ssh_hub(host, port, cmd, strict=True, timeout=8):
    o = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % timeout, "-o", "IdentitiesOnly=yes", "-i", MPUB,
         "-o", "UserKnownHostsFile=" + KH, "-o", "StrictHostKeyChecking=" + ("yes" if strict else "accept-new"),
         "-o", "ControlPath=none", "-p", str(port), "custhub@" + host, cmd]
    return subprocess.run(o, capture_output=True, text=True)


def parse(text):
    """签名目录 → (数据原文, 签名)"""
    m = re.search(r"(custhub-dir v1\n.*?)--sig--\n(.*?)--end--", text, re.S)
    if not m: raise SystemExit("✘ 中转没给出节点目录(Mac 上还没 trust.sh publish?)")
    return m.group(1), m.group(2)


def verify(data, sig, pub):
    with tempfile.TemporaryDirectory() as t:
        open(t + "/d", "w").write(data); open(t + "/s", "w").write(sig)
        open(t + "/a", "w").write("custhub " + " ".join(pub.split()[:2]) + "\n")
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", t + "/a", "-I", "custhub", "-n", "custhub-dir", "-s", t + "/s"],
                           stdin=open(t + "/d"), capture_output=True)
        return r.returncode == 0


def load():
    if not os.path.exists(DIR): raise SystemExit("还没 setup: python3 admin.py setup 中转地址")
    hubs, nodes = [], []
    for l in open(DIR).read().splitlines():
        f = l.split(" ")
        if f[0] == "hub" and len(f) == 5: hubs.append((f[1], f[2], f[3] + " " + f[4]))
        if f[0] == "node" and len(f) == 6: nodes.append((f[1], int(f[2]), f[3], f[4], base64.b64decode(f[5]).decode("utf-8", "replace")))
    return hubs, nodes


def fetch(seed_host, seed_port=22):
    """从一台中转取目录; 验签通过后用目录里的中转主机钥匙重写 known_hosts(首连是 TOFU, 验签后即被目录校正)"""
    pub = open(MPUB).read().strip()
    tried = [(seed_host, seed_port)]
    if os.path.exists(DIR): tried += [(h, p) for h, p, _ in load()[0]]
    for h, p in tried:
        r = ssh_hub(h, p, "dir-get", strict=os.path.exists(DIR))
        if r.returncode or "custhub-dir v1" not in r.stdout: continue
        data, sig = parse(r.stdout)
        if not verify(data, sig, pub): raise SystemExit("✘ 节点目录签名不对, 不采用(中转被动过?)")
        open(DIR, "w").write(data)
        open(KH, "w").write("".join(("%s %s\n" % (hh, k)) if pp == "22" else ("[%s]:%s %s\n" % (hh, pp, k)) for hh, pp, k in load()[0]))
        # 首连记下的钥匙必须和签名目录里的一致, 否则刚才那台是冒充的
        if r.returncode == 0 and ssh_hub(h, p, "info").returncode:
            raise SystemExit("✘ 中转 %s 的主机钥匙和签名目录不符" % h)
        return
    raise SystemExit("✘ 哪台中转都取不到目录(没解锁? 中转地址不对? 主钥匙还没推到中转跳板账号?)")


def write_config():
    hubs, nodes = load()
    me = os.path.abspath(__file__)
    blk = [BEGIN + " (admin.py 生成, 重跑会整段替换)"]
    for a, port, user, os_, name in nodes:
        blk += ["Host " + a, "    HostKeyAlias " + a, "    User " + user,
                "    ProxyCommand %s %s route %s" % (sys.executable, me, a),
                "    IdentityFile " + MPUB, "    IdentitiesOnly yes",
                "    UserKnownHostsFile " + KHN, "    StrictHostKeyChecking accept-new", "    ConnectTimeout 15"]
    blk.append(END)
    os.makedirs(os.path.dirname(CFG), exist_ok=True)
    cur = open(CFG).read() if os.path.exists(CFG) else ""
    cur = re.sub(r"(?ms)^" + re.escape(BEGIN) + r".*?^" + re.escape(END) + r"\n?", "", cur)
    # 放在最前面: ssh 配置先匹配者生效; 这台机器上若已有同名 Host(比如原管理 Mac), 则仍以原有的为准
    if re.search(r"(?m)^Host c-\d+", cur): open(CFG, "w").write(cur.rstrip("\n") + "\n\n" + "\n".join(blk) + "\n")
    else: open(CFG, "w").write("\n".join(blk) + "\n\n" + cur)
    os.chmod(CFG, 0o600)
    return len(nodes)


def route(alias):
    hubs, nodes = load()
    n = [x for x in nodes if x[0] == alias]
    if not n: sys.exit("目录里没有 " + alias)
    port = n[0][1]
    for h, p, _ in hubs:
        r = ssh_hub(h, p, "tun-list", timeout=5)
        if any(l.split("\t")[1:3] == [str(port), "1"] for l in r.stdout.splitlines() if l.count("\t") >= 3):
            os.execvp("ssh", ["ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", MPUB, "-o", "UserKnownHostsFile=" + KH,
                              "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=none", "-p", p, "-W", "127.0.0.1:%d" % port, "custhub@" + h])
    sys.exit("%s 现在没有在线的回拨口(关机/断网?)" % alias)


def main(a):
    c = a[1] if len(a) > 1 else ""
    os.makedirs(H, mode=0o700, exist_ok=True)
    if c == "setup":
        host = a[2] if len(a) > 2 else sys.exit("用法: admin.py setup 中转地址")
        seed, pub = passkey.derive(passkey.ask())
        open(MPUB, "w").write(passkey.pub_line(pub) + "\n")
        r = subprocess.run(["ssh-add", "-t", "28800", "-"], input=passkey.priv_pem(seed, pub), text=True, capture_output=True)
        if r.returncode: sys.exit("✘ ssh-add 失败(ssh-agent 没开?): " + r.stderr.strip())
        del seed
        fetch(host)
        print("✓ 已解锁 8 小时 · 节点目录验签通过 · 写入 %d 台客户机的 ssh 配置 → 现在可以 ssh c-N" % write_config())
    elif c == "unlock":
        passkey.unlock(float(a[2]) if len(a) > 2 else 8)
    elif c == "refresh":
        hubs = load()[0]
        fetch(hubs[0][0], hubs[0][1]); print("✓ 目录已更新, %d 台客户机" % write_config())
    elif c == "list":
        for x in load()[1]: print("%-6s %-4s %-14s %s" % (x[0], x[3], x[2], x[4]))
    elif c == "route":
        route(a[2])
    else:
        print(open(__file__).read().split("\nimport")[0].replace("# ", "").split("\n", 1)[1]); sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
