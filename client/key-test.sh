#!/usr/bin/env bash
# 退役旧管理钥匙的真机式验证(Debian 容器里起真的 sshd, 不碰真机器): ./key-test.sh
#   1 主钥匙只放公钥文件、私钥在 ssh-agent: ssh -i 公钥 能登   2 agent 里没有(没解锁)就登不进
#   3 custhub 应用带 retire 的清单: 旧钥匙登不进, 主钥匙照登   4 清单没带主钥匙行时不退役
set -u
if [ "${1:-}" != inside ]; then
  cd "$(dirname "$0")/../.."
  exec docker run --rm -v "$PWD":/src:ro debian:bookworm-slim bash /src/src/client/key-test.sh inside
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq gcc libc6-dev openssh-server openssh-client >/dev/null 2>&1
cp -r /src /w; cd /w/src/client
gcc -std=c99 -O2 -D_DEFAULT_SOURCE -DMESH_IN_CUSTHUB -DCR_PLAT='"linux-amd64"' -o /tmp/custhub \
  main.c util.c sshsig.c trust.c tun.c meshd.c engineer.c http.c upgrade.c install.c join.c join_win.c posix.c win.c \
  vendor/monocypher.c vendor/monocypher-ed25519.c ../mesh/{util,noise,link,hop,disc,app,main}.c || exit 1
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
K=/root/k; mkdir -p $K /run/sshd /root/.ssh /opt/cust-remote; chmod 700 /root/.ssh
ssh-keygen -q -t ed25519 -N '' -C cust-remote -f $K/old
ssh-keygen -q -t ed25519 -N '' -C master -f $K/master
ssh-keygen -A >/dev/null; /usr/sbin/sshd -o PermitRootLogin=prohibit-password
# 客户机现状: 旧管理钥匙 + 信任清单写的主钥匙行(只认本机来源)
{ cat $K/old.pub; echo "from=\"127.0.0.1,::1\" $(cut -d' ' -f1,2 $K/master.pub) custhub-trust:master"; } >/root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
S=(-F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o LogLevel=ERROR)
cp $K/master.pub $K/mk.pub; cp $K/master.pub $K/mk; chmod 600 $K/mk   # 两个文件都只是公钥(切换后的管理身份就这样放)
eval "$(ssh-agent -s)" >/dev/null

echo "== 主钥匙: 盘上只有公钥, 私钥在 agent"
ok "没解锁(agent 空)登不进" '! ssh "${S[@]}" -i $K/mk root@127.0.0.1 true'
ssh-add -q $K/master
ok "解锁后 ssh -i 公钥文件 能登" 'ssh "${S[@]}" -i $K/mk root@127.0.0.1 true'
ok "旧钥匙现在也能登(切换前)" 'ssh "${S[@]}" -i $K/old root@127.0.0.1 true'

echo "== custhub 应用带退役指令的清单"
pk(){ cut -d' ' -f1,2 "$1.pub"; }
bundle(){  # bundle 版本 [带主钥匙行=1]
  { echo "custhub-trust-bundle v1"; echo "version $1"; [ "${2:-1}" = 1 ] && echo "key $(pk $K/master) custhub-trust:master"; echo "retire cust-remote"; } >/tmp/d
  cat /tmp/d; ssh-keygen -Y sign -q -n custhub-trust -f $K/master /tmp/d; echo "--sig--"; cat /tmp/d.sig; rm -f /tmp/d.sig; echo "--end--"
}
cp /root/.ssh/authorized_keys /tmp/ak.keep
bundle 10 0 >/tmp/b0; CUSTHUB_D=/opt/cust-remote /tmp/custhub trust-apply /tmp/b0 >/dev/null 2>&1
ok "清单没带主钥匙行: 不退役, 旧钥匙照登" 'ssh "${S[@]}" -i $K/old root@127.0.0.1 true'
cp /tmp/ak.keep /root/.ssh/authorized_keys; rm -f /opt/cust-remote/trust.ver
bundle 11 >/tmp/b1; CUSTHUB_D=/opt/cust-remote /tmp/custhub trust-apply /tmp/b1 >/dev/null 2>&1
ok "退役后旧钥匙登不进" '! ssh "${S[@]}" -i $K/old root@127.0.0.1 true'
ok "主钥匙照登" 'ssh "${S[@]}" -i $K/mk root@127.0.0.1 true'
ssh-add -q -D
ok "锁上(agent 清空)后谁也登不进" '! ssh "${S[@]}" -i $K/mk root@127.0.0.1 true && ! ssh "${S[@]}" -i $K/old root@127.0.0.1 true'
echo "== 验证器证书(6 位数换来的 2 小时证书, 私钥只在 agent)与主钥匙并存"
ssh-keygen -q -t ed25519 -N '' -C ca -f $K/ca
cat /tmp/ak.keep >/root/.ssh/authorized_keys
echo "cert-authority,from=\"127.0.0.1,::1\" $(cut -d' ' -f1,2 $K/ca.pub) custhub-trust:hub-test" >>/root/.ssh/authorized_keys
ssh-keygen -q -t ed25519 -N '' -C session -f $K/s; ssh-keygen -q -s $K/ca -I otp-test -n root,custhub -V -5m:+2h $K/s.pub
cp $K/s-cert.pub $K/session-cert.pub
# 管理端 ssh 配置的写法: 两个 IdentityFile, 盘上都只是公开的东西
printf 'Host t\n  HostName 127.0.0.1\n  User root\n  IdentityFile %s\n  IdentityFile %s\n  IdentitiesOnly yes\n  BatchMode yes\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n' $K/mk $K/session-cert.pub >$K/cfg
ssh-add -q -D; ssh-add -q -t 7200 $K/s; rm -f $K/s   # 加进 agent(连同证书)后删掉私钥文件
ok "只有证书在 agent: 登得进" 'ssh -F $K/cfg t true'
ssh-add -q -D; ssh-add -q $K/master
ok "只有主钥匙在 agent: 登得进(同一份配置)" 'ssh -F $K/cfg t true'
ssh-add -q -D
ok "都没有: 登不进" '! ssh -F $K/cfg t true'
ssh-keygen -q -t ed25519 -N '' -C s2 -f $K/s2; ssh-keygen -q -s $K/ca -I old -n root -V 20200101:20200102 $K/s2.pub
ssh-add -q $K/s2 2>/dev/null; cp $K/s2-cert.pub $K/session-cert.pub
ok "过期证书登不进" '! ssh -F $K/cfg t true'
echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { cat /root/.ssh/authorized_keys; cat /opt/cust-remote/trust.log 2>/dev/null; }
