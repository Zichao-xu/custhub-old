#!/usr/bin/env python3
# passkey.py — 管理口令(SPEC §4)最小实现: 只用 Python 标准库, 自有机器(Mac/Linux)上跑
#   passkey.py gen [--trust]  生成新口令(随机 12 个词), 抄完回车清屏, 输出主公钥; --trust 直接记进信任清单
#   passkey.py pub            输入口令 → 输出主公钥(给节点写进信任列表用)
#   passkey.py unlock [小时]  输入口令 → 主钥匙放进 ssh-agent(默认 8 小时后自动删), 之后 ssh c-N 直接用
#   passkey.py lock           立即从 ssh-agent 删掉主钥匙
#   passkey.py status         是否已解锁
# 派生: 口令 → scrypt(n=2^17,r=8,p=1, 固定盐 + 用途标签) → 32 字节种子 → ed25519
#   盐固定: 口令本身有 ~128 位随机熵, 不靠盐防彩虹表; 固定才能"任意机器只凭口令"解锁
#   用途标签: ssh = 登录; 以后新增用途只换标签, 不换口令
# 私钥只经 stdin 交给 ssh-add, 不写盘
import getpass, hashlib, os, secrets, struct, subprocess, sys, base64

SALT = b"custhub-mesh-v1"
COMMENT = "custhub-master"

# ---------- ed25519(只需要由种子算公钥) ----------
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)

def _xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P: x = x * I % P
    return P - x if x % 2 else x

BY = 4 * pow(5, P - 2, P) % P
BASE = (_xrecover(BY), BY, 1, _xrecover(BY) * BY % P)

def _add(a, b):
    x1, y1, z1, t1 = a; x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P; B = (y1 + x1) * (y2 + x2) % P
    C = t1 * 2 * D * t2 % P; Dd = z1 * 2 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)

def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1: q = _add(q, pt)
        pt = _add(pt, pt); s >>= 1
    return q

def ed25519_pub(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8; a |= 1 << 254
    x, y, z, _ = _mul(a, BASE)
    zi = pow(z, P - 2, P); x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")

# ---------- 派生 ----------
def norm(phrase):
    return " ".join(phrase.lower().split())

def derive(phrase, label="ssh"):
    seed = hashlib.scrypt(norm(phrase).encode(), salt=SALT + b"/" + label.encode(), n=2**17, r=8, p=1, maxmem=2**28, dklen=32)
    return seed, ed25519_pub(seed)

# ---------- OpenSSH 格式 ----------
def _s(b): return struct.pack(">I", len(b)) + b

def pub_line(pub):
    return "ssh-ed25519 " + base64.b64encode(_s(b"ssh-ed25519") + _s(pub)).decode() + " " + COMMENT

def priv_pem(seed, pub):
    blob = _s(b"ssh-ed25519") + _s(pub)
    chk = secrets.token_bytes(4)
    sec = chk + chk + _s(b"ssh-ed25519") + _s(pub) + _s(seed + pub) + _s(COMMENT.encode())
    sec += bytes(range(1, 1 + (-len(sec)) % 8))
    raw = b"openssh-key-v1\0" + _s(b"none") + _s(b"none") + _s(b"") + struct.pack(">I", 1) + _s(blob) + _s(sec)
    b = base64.b64encode(raw).decode()
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(b[i:i + 70] for i in range(0, len(b), 70)) + "\n-----END OPENSSH PRIVATE KEY-----\n"

# ---------- 口令生成 ----------
def wordlist():
    # 系统词典里 4~6 个字母的纯小写词; 熵按词表大小实算, 不够 128 位就多给几个词
    for f in ("/usr/share/dict/words", "/usr/share/dict/american-english"):
        try:
            with open(f) as fh:
                ws = sorted({w.strip() for w in fh if w.strip().isalpha() and w.strip().islower() and 4 <= len(w.strip()) <= 6})
            if len(ws) >= 2048: return ws
        except OSError: pass
    sys.exit("找不到系统词典(/usr/share/dict/words)")

def gen():
    import math
    ws = wordlist(); n = max(12, math.ceil(128 / math.log2(len(ws))))
    phrase = " ".join(secrets.choice(ws) for _ in range(n))
    print("新口令(只显示这一次, 抄下来离线保存; 别截图, 别发给任何人或 AI):\n\n  " + phrase + "\n")
    print("强度: %d 个词 × 词表 %d ≈ %d 位" % (n, len(ws), int(n * math.log2(len(ws)))))
    if sys.stdin.isatty():
        input("\n抄好后按回车(会清屏, 口令不留在屏幕和回滚记录里)…")
        sys.stdout.write("\033[H\033[2J\033[3J"); sys.stdout.flush()
    pl = pub_line(derive(phrase)[1]); del phrase
    print("✓ 口令已生成并清屏\n主公钥:\n" + pl)
    if "--trust" in sys.argv:   # 直接记进信任清单(覆盖旧的 master)
        subprocess.run([os.path.join(os.path.dirname(os.path.abspath(__file__)), "hub", "trust.sh"), "add", "master", "key", pl], check=True)

def ask():
    p = os.environ.get("CUSTHUB_PASSPHRASE") or getpass.getpass("口令: ")
    if len(norm(p).split()) < 8: sys.exit("口令不对: 至少 8 个词")
    return p

def in_agent():
    r = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True)
    return any(l.endswith(" " + COMMENT) for l in r.stdout.splitlines())

def lock():
    r = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True)
    for l in r.stdout.splitlines():
        if l.endswith(" " + COMMENT):
            subprocess.run(["ssh-add", "-d", "-"], input=l + "\n", text=True, capture_output=True)
    print("✓ 已上锁")

def unlock(hours):
    seed, pub = derive(ask())
    r = subprocess.run(["ssh-add", "-t", str(int(hours * 3600)), "-"], input=priv_pem(seed, pub), text=True, capture_output=True)
    if r.returncode: sys.exit("✘ ssh-add 失败: " + r.stderr.strip())
    print("✓ 已解锁 %g 小时 · 主公钥 %s…" % (hours, pub_line(pub)[12:40]))

def main(a):
    c = a[1] if len(a) > 1 else ""
    if c == "gen": gen()
    elif c == "pub": print(pub_line(derive(ask())[1]))
    elif c == "unlock": unlock(float(a[2]) if len(a) > 2 else 8)
    elif c == "lock": lock()
    elif c == "status": print("已解锁" if in_agent() else "未解锁")
    elif c == "_pem": seed, pub = derive(ask()); sys.stdout.write(priv_pem(seed, pub))   # 仅测试用
    else:
        print(open(__file__).read().split("\nimport")[0].replace("# ", "").split("\n", 1)[1]); sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
