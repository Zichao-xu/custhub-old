#!/usr/bin/env python3
# otp.py — 中转上的验证器登录签发服务(SPEC §4.7): 只听 127.0.0.1, 由 httpd.py 转发 POST /cgi-bin/login
#   请求正文: 第 1 行 = 客户机临时生成的公钥(ssh-ed25519 ...), 第 2 行 = 验证器 6 位数
#   通过 → 用本机 CA 签一张短期 ssh 证书(可登录账号见 principals 文件, 默认 2 小时)原样返回; 不通过 → 403, 不说原因
# 防护: 每个验证码只能用一次; 10 分钟内失败满 5 次 → 锁 15 分钟(全局, 不按来源区分, 宁可误伤也不给人慢慢猜)
# 以独立账号 custotp 跑, CA 私钥和验证器密钥只有它能读; 不碰其它任何东西
#   python3 otp.py serve              跑服务(systemd)
#   python3 otp.py code               打印当前验证码(排查用, 只有 root/custotp 能跑)
import base64, hashlib, hmac, os, struct, subprocess, sys, tempfile, threading, time, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

O = os.environ.get("OTP_DIR", "/var/lib/custhub-otp")
PORT = int(os.environ.get("OTP_PORT", "51881"))
HOURS = int(os.environ.get("OTP_HOURS", "2"))
PUB = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]{68}( [A-Za-z0-9._@-]{0,64})?$")
lock = threading.Lock()
fails, used = [], {}     # 失败时间戳; 已用过的(时间片, 码)
locked_until = 0.0


def secret():
    with open(os.path.join(O, "totp.secret")) as f:
        s = f.read().strip().upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def totp(key, step):
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)


def check(code):
    """允许前后各一个 30 秒时间片(手机时间略偏也能用); 同一个码只认一次"""
    global locked_until
    now = time.time()
    with lock:
        if now < locked_until:
            return False
        for k in [k for k, t in used.items() if now - t > 120]:
            del used[k]
        key, st = secret(), int(now // 30)
        for s in (st, st - 1, st + 1):
            if hmac.compare_digest(totp(key, s), code) and (s, code) not in used:
                used[(s, code)] = now
                return True
        fails[:] = [t for t in fails if now - t < 600] + [now]
        if len(fails) >= 5:
            locked_until, fails[:] = now + 900, []
        return False


def sign(pub, who):
    with tempfile.TemporaryDirectory() as t:
        p = os.path.join(t, "k.pub")
        with open(p, "w") as f:
            f.write(pub + "\n")
        # 可登录的账号名 = Mac 推来的目录里各客户机的登录账号 + custhub(中转跳板)
        with open(os.path.join(O, "principals")) as f:
            pr = f.read().strip()
        r = subprocess.run(["ssh-keygen", "-q", "-s", os.path.join(O, "ca"), "-I", "otp-%d-%s" % (time.time(), who),
                            "-n", pr, "-V", "-5m:+%dh" % HOURS, p], capture_output=True)
        if r.returncode:
            raise RuntimeError(r.stderr.decode(errors="replace"))
        with open(os.path.join(t, "k-cert.pub")) as f:
            return f.read()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *a):
        pass

    def reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/login" or self.client_address[0] != "127.0.0.1":
            return self.reply(404)
        n = min(int(self.headers.get("Content-Length") or 0), 1024)
        lines = self.rfile.read(n).decode("ascii", "replace").replace("\r", "").split("\n")
        who = re.sub(r"[^0-9a-f.:]", "", self.headers.get("X-Peer", ""))[:45]
        pub, code = (lines + ["", ""])[:2]
        if not PUB.match(pub.strip()) or not re.fullmatch(r"\d{6}", code.strip()):
            return self.reply(400)
        ok = check(code.strip())
        sys.stderr.write("%s login %s from %s\n" % (time.strftime("%F %T"), "ok" if ok else "FAIL", who or "?"))
        if not ok:
            return self.reply(403)
        try:
            return self.reply(200, sign(pub.strip(), who.replace(":", "_")).encode())
        except Exception as e:
            sys.stderr.write("sign: %r\n" % e)
            return self.reply(500)


if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else ""
    if c == "serve":
        ThreadingHTTPServer.daemon_threads = True
        ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
    elif c == "code":
        print(totp(secret(), int(time.time() // 30)))
    else:
        sys.exit("用法: otp.py serve | code")
