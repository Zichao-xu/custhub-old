#!/usr/bin/env bash
# 本机自测(不碰真机器): 签名清单与 trust.sh 同格式, 用 ssh-keygen 现做钥匙
#   ./test.sh        先 ./build.sh native
set -uo pipefail
cd "$(dirname "$0")"
B=$PWD/custhub; [ -x "$B" ] || ./build.sh native >/dev/null
W=$(mktemp -d); trap 'pkill -f "$W/fake-ssh" 2>/dev/null; kill $TP $HS 2>/dev/null; rm -rf "$W"' EXIT
TP=; HS=
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✓ $1"; else fail=$((fail+1)); echo "  ✗ $1"; fi; }

ssh-keygen -q -t ed25519 -N '' -C master -f "$W/master"
ssh-keygen -q -t ed25519 -N '' -C cust-remote -f "$W/old"
ssh-keygen -q -t ed25519 -N '' -C evil -f "$W/evil"
ssh-keygen -q -t ed25519 -N '' -C ca -f "$W/ca"
pk(){ awk '{print $1" "$2}' "$1.pub"; }

mkdir -p "$W/d" "$W/u1/.ssh" "$W/u2/.ssh" "$W/u3/.ssh"
export CUSTHUB_D=$W/d
# u1: 只有旧管理钥匙(初次); u2: 放开直连; u3: 和我们无关, 不该动
printf 'from="127.0.0.1,::1" %s cust-remote\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx someone\n' "$(pk "$W/old")" >"$W/u1/.ssh/authorized_keys"
cp "$W/u1/.ssh/authorized_keys" "$W/u2/.ssh/authorized_keys"; touch "$W/u2/.ssh/cust-remote-open"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx other" >"$W/u3/.ssh/authorized_keys"
export CUSTHUB_AK_FILES="$W/u1/.ssh/authorized_keys $W/u2/.ssh/authorized_keys $W/u3/.ssh/authorized_keys"

# mk 版本 签名钥匙... [ns=命名空间]  → 签名清单到 stdout
mk(){ local v=$1; shift; local ns=${NS:-custhub-trust}
  { echo "custhub-trust-bundle v1"; echo "version $v"
    echo "key $(pk "$W/master") custhub-trust:master"; echo "ca $(pk "$W/ca") custhub-trust:hub-test"
    echo "key ssh-ed25519 short custhub-trust:bad"; } >"$W/data"
  echo "kick output noise"; cat "$W/data"
  for k in "$@"; do ssh-keygen -Y sign -q -n "$ns" -f "$W/$k" "$W/data"; echo "--sig--"; cat "$W/data.sig"; rm -f "$W/data.sig"; done
  [ -z "${NOEND:-}" ] && echo "--end--"; true; }
apply(){ "$B" trust-apply "$W/b" >/dev/null 2>&1; }

echo "== 验签与 ssh-keygen 互通"
printf 'hello\n' >"$W/msg"; ssh-keygen -Y sign -q -n custhub-trust -f "$W/master" "$W/msg"
echo "custhub $(pk "$W/master")" >"$W/allowed"
ok "正确签名通过" '"$B" verify custhub-trust "$W/allowed" "$W/msg.sig" <"$W/msg" >/dev/null'
ok "改一个字节就拒" '! printf "hellp\n" | "$B" verify custhub-trust "$W/allowed" "$W/msg.sig" >/dev/null'
ok "命名空间不对就拒" '! "$B" verify custhub-dir "$W/allowed" "$W/msg.sig" <"$W/msg" >/dev/null'
echo "custhub $(pk "$W/evil")" >"$W/allowed2"
ok "不认识的钥匙就拒" '! "$B" verify custhub-trust "$W/allowed2" "$W/msg.sig" <"$W/msg" >/dev/null'

echo "== 信任清单应用"
mk 100 evil >"$W/b"; apply
ok "陌生钥匙签的不应用" '! grep -q custhub-trust: "$W/u1/.ssh/authorized_keys"'
NOEND=1 mk 100 old >"$W/b"; apply
ok "残缺(没有 --end--)不应用" '! grep -q custhub-trust: "$W/u1/.ssh/authorized_keys"'
NS=custhub-dir mk 100 old >"$W/b"; apply
ok "命名空间不对不应用" '! grep -q custhub-trust: "$W/u1/.ssh/authorized_keys"'
mk 100 evil old >"$W/b"; apply
ok "旧管理钥匙签的(第二段)应用" 'grep -q "^from=\"127.0.0.1,::1\" $(pk "$W/master") custhub-trust:master$" "$W/u1/.ssh/authorized_keys"'
ok "证书行带 from=" 'grep -q "^cert-authority,from=\"127.0.0.1,::1\" $(pk "$W/ca") custhub-trust:hub-test$" "$W/u1/.ssh/authorized_keys"'
ok "格式不对的条目丢掉" '! grep -q custhub-trust:bad "$W/u1/.ssh/authorized_keys"'
ok "旧管理钥匙和别的钥匙没动" 'grep -q " cust-remote$" "$W/u1/.ssh/authorized_keys" && grep -q " someone$" "$W/u1/.ssh/authorized_keys"'
ok "放开直连的账号不加 from=" 'grep -q "^$(pk "$W/master") custhub-trust:master$" "$W/u2/.ssh/authorized_keys"'
ok "无关账号没动" '[ "$(wc -l <"$W/u3/.ssh/authorized_keys")" -eq 1 ]'
ok "记下版本号" '[ "$(cat "$W/d/trust.ver")" = 100 ]'
ok "记下主公钥" 'grep -q "^$(pk "$W/master") custhub-trust:master$" "$W/d/master.pub"'
cp "$W/u1/.ssh/authorized_keys" "$W/before"
mk 100 master >"$W/b"; apply; mk 99 master >"$W/b"; apply
ok "同版本/旧版本不重放" 'cmp -s "$W/before" "$W/u1/.ssh/authorized_keys"'
mk 101 master >"$W/b"; apply
ok "主钥匙签的新版本应用" '[ "$(cat "$W/d/trust.ver")" = 101 ] && [ "$(grep -c custhub-trust: "$W/u1/.ssh/authorized_keys")" -eq 2 ]'
ok "重复应用不叠行" '[ "$(grep -c custhub-trust:master "$W/u1/.ssh/authorized_keys")" -eq 1 ]'
head -c 70000 /dev/zero | tr '\0' 'x' >"$W/b"; "$B" trust-apply "$W/b" >/dev/null 2>&1; r=$?
ok "超长输入拒收不崩" '[ $r -eq 2 ]'

echo "== dropbear(OpenWrt) 格式"
mkdir -p "$W/d/ak"; grep -v custhub-trust: "$W/u2/.ssh/authorized_keys" >"$W/d/ak/authorized_keys"
rm "$W/d/trust.ver"; mk 5 old >"$W/b"; CUSTHUB_AK_FILES="$W/d/ak/authorized_keys" "$B" trust-apply "$W/b" >/dev/null
ok "dropbear 不写 from= 和证书行" 'grep -q "^$(pk "$W/master") custhub-trust:master$" "$W/d/ak/authorized_keys" && ! grep -q cert-authority "$W/d/ak/authorized_keys"'
rm -rf "$W/d/ak"

echo "== 通道守护(假 ssh)"
# 假 ssh: 不带 -N = kick, 吐签名清单; 带 -N = 长连接, 记下参数后挂着
mk 200 master >"$W/kick.txt"
cat >"$W/fake-ssh" <<EOF
#!/bin/sh
case " \$* " in *" -N "*) echo "\$*" >>"$W/tun-args"; trap 'exit 0' TERM; while :; do sleep 1; done ;; esac
echo "\$*" >>"$W/kick-args"; cat "$W/kick.txt"
EOF
chmod +x "$W/fake-ssh"
touch "$W/d/tun_ed25519"
printf 'port 22099\nssh %s\n' "$W/fake-ssh" >"$W/d/client.conf"
K=$(pk "$W/ca" | cut -d' ' -f2)
printf 'hub-a.example 22 ssh-ed25519 %s\nhub-b.example 2222 ssh-ed25519 %s\n-bad 22 ssh-ed25519 %s\n' "$K" "$K" "$K" >"$W/d/hubs.txt"
"$B" tun >/dev/null 2>&1 & TP=$!
for i in $(seq 30); do [ -s "$W/d/tun-status.txt" ] && [ "$(wc -l <"$W/tun-args" 2>/dev/null)" -ge 2 ] 2>/dev/null && break; sleep 0.3; done
ok "两台中转各起一条 -R" '[ "$(grep -c "127.0.0.1:22099:127.0.0.1:22" "$W/tun-args")" -eq 2 ]'
ok "非法主机名(-bad)被拒" '! grep -q -- "-bad" "$W/tun-args" "$W/kick-args"'
ok "known_hosts 按端口写" 'grep -q "^hub-a.example ssh-ed25519 " "$W/d/hubs_known" && grep -q "^\[hub-b.example\]:2222 " "$W/d/hubs_known"'
ok "只认 known_hosts 里的主机钥匙" 'grep -q "StrictHostKeyChecking=yes" "$W/tun-args"'
ok "kick 发来的清单已应用" '[ "$(cat "$W/d/trust.ver")" = 200 ]'
ok "第二个守护起不来(单实例)" '"$B" tun; [ $? -eq 0 ] && [ "$(pgrep -f "$B tun" | wc -l | tr -d " ")" -eq 1 ]'
printf 'hub-a.example 22 ssh-ed25519 %s\n' "$K" >"$W/d/hubs.txt"
for i in $(seq 30); do [ "$(pgrep -f "$W/fake-ssh.*hub-b" | wc -l | tr -d ' ')" = 0 ] && break; sleep 0.3; done
ok "移出的中转断开" '[ "$(pgrep -f "$W/fake-ssh.*hub-b" | wc -l | tr -d " ")" = 0 ] && pgrep -f "$W/fake-ssh.*hub-a" >/dev/null'
pkill -f "$W/fake-ssh.*hub-a"; sleep 1
n0=$(grep -c hub-a "$W/tun-args"); sleep 6
ok "掉线 30 秒内不重连(退避)" '[ "$(grep -c hub-a "$W/tun-args")" -eq $n0 ] && grep -q "hub-a.example down" "$W/d/tun-status.txt"'
kill $TP; sleep 1
ok "守护退出时子进程一起退" '! pgrep -f "$W/fake-ssh" >/dev/null'
TP=

echo "== 自升级(手动 upgrade + 试用期)"
OUTBIN="$W/new-bin" VER=0.1.1 ./build.sh native >/dev/null
rel(){ local v=$1 f=$2 k=$3
  { echo "custhub-release v1"; echo "version $v"; echo "file dev $(wc -c <"$f" | tr -d ' ') $(shasum -a 512 "$f" | cut -d' ' -f1)"; } >"$W/rdata"
  cat "$W/rdata"; ssh-keygen -Y sign -q -n custhub-release -f "$W/$k" "$W/rdata"; echo "--sig--"; cat "$W/rdata.sig"; rm -f "$W/rdata.sig"; echo "--end--"; }
U=$W/u; mkdir -p "$U"; cp "$W/d/master.pub" "$U/"; cp "$B" "$U/custhub"; touch "$U/tun_ed25519"
printf 'port 22099\nssh %s\n' "$W/fake-ssh" >"$U/client.conf"
printf 'hub-a.example 22 ssh-ed25519 %s\n' "$K" >"$U/hubs.txt"
export CUSTHUB_D=$U
rel 0.1.1 "$W/new-bin" evil >"$W/r-evil"; "$B" upgrade "$W/r-evil" "$W/new-bin" >/dev/null; r=$?
ok "陌生钥匙签的发布清单拒" '[ $r -eq 1 ] && "$U/custhub" version | grep -q "^custhub 0.1.0"'
rel 0.1.1 "$W/new-bin" master >"$W/r1"; cp "$W/new-bin" "$W/new-bad"; echo x >>"$W/new-bad"
"$B" upgrade "$W/r1" "$W/new-bad" >/dev/null; r=$?
ok "哈希不符拒" '[ $r -eq 1 ] && "$U/custhub" version | grep -q "^custhub 0.1.0"'
rel 0.1.0 "$B" master >"$W/r0"; "$B" upgrade "$W/r0" "$B" >/dev/null; r=$?
ok "不比自己新的不装" '[ $r -eq 0 ] && [ ! -f "$U/upgrade.pending" ]'
"$B" upgrade "$W/r1" "$W/new-bin" >/dev/null; r=$?
ok "签名对、哈希对就换上" '[ $r -eq 0 ] && "$U/custhub" version | grep -q "^custhub 0.1.1" && "$U/custhub.old" version | grep -q "^custhub 0.1.0"'
ok "进入试用期" 'grep -q "^0.1.0 0.1.1 0" "$U/upgrade.pending"'
echo "0.1.0 0.1.1 3" >"$U/upgrade.pending"
"$U/custhub" tun >/dev/null 2>&1 & TP=$!
for i in $(seq 20); do "$U/custhub" version | grep -q "0.1.0" && break; sleep 0.3; done; sleep 1
ok "启动次数超了就回滚" '"$U/custhub" version | grep -q "^custhub 0.1.0" && [ ! -f "$U/upgrade.pending" ] && grep -q "^0.1.1 1" "$U/upgrade.bad"'
ok "回滚后旧版接着跑(原地 exec)" 'kill -0 $TP && ps -o command= -p $TP | grep -q "tun --takeover"'
kill $TP; wait $TP 2>/dev/null; pkill -f "$W/fake-ssh"; TP=
"$B" upgrade "$W/r1" "$W/new-bin" >/dev/null
"$U/custhub" tun >/dev/null 2>&1 & TP=$!
for i in $(seq 40); do grep -q 转正 "$U/upgrade.log" 2>/dev/null && break; sleep 0.5; done
ok "有通道连上就转正" 'grep -q "0.1.1 转正" "$U/upgrade.log" && [ ! -f "$U/upgrade.pending" ] && "$U/custhub" version | grep -q 0.1.1'
kill $TP; wait $TP 2>/dev/null; pkill -f "$W/fake-ssh"; TP=

echo "== 自升级(kick 发来清单 → HTTP 下载 → 换上 → 转正)"
rm -f "$U"/upgrade.* "$U/custhub.old" "$U/trust.ver"; cp "$B" "$U/custhub"
mkdir -p "$W/www/pkg/client"; cp "$W/new-bin" "$W/www/pkg/client/custhub-0.1.1-dev"
HP=$((18000 + RANDOM % 2000))
python3 -m http.server $HP --bind 127.0.0.1 -d "$W/www" >/dev/null 2>&1 & HS=$!
printf 'port 22099\nssh %s\nhttp_port %s\n' "$W/fake-ssh" $HP >"$U/client.conf"
printf '127.0.0.1 22 ssh-ed25519 %s\n' "$K" >"$U/hubs.txt"
{ mk 300 master; rel 0.1.1 "$W/new-bin" master; } >"$W/kick.txt"
sleep 1; "$U/custhub" tun >/dev/null 2>&1 & TP=$!
for i in $(seq 60); do grep -q 转正 "$U/upgrade.log" 2>/dev/null && break; sleep 0.5; done
ok "下载、核对、换上" 'grep -q "取到 0.1.1, 核对通过" "$U/upgrade.log" && "$U/custhub" version | grep -q 0.1.1'
ok "同一进程接着跑新版并转正" 'kill -0 $TP && grep -q "0.1.1 转正" "$U/upgrade.log"'
ok "信任清单照常应用" '[ "$(cat "$U/trust.ver")" = 300 ]'
kill $TP; wait $TP 2>/dev/null; kill $HS; pkill -f "$W/fake-ssh"; TP=; HS=

echo "== 自升级(守护定时轮询中转的 release.txt, 不靠 kick)"
rm -f "$U"/upgrade.* "$U/custhub.old"; cp "$B" "$U/custhub"
rel 0.1.1 "$W/new-bin" master >"$W/www/pkg/client/release.txt"
mk 301 master >"$W/kick.txt"                          # kick 只带信任清单
python3 -m http.server $HP --bind 127.0.0.1 -d "$W/www" >/dev/null 2>&1 & HS=$!
sleep 1; CUSTHUB_POLL=10 "$U/custhub" tun >/dev/null 2>&1 & TP=$!
for i in $(seq 60); do grep -q 转正 "$U/upgrade.log" 2>/dev/null && break; sleep 0.5; done
ok "轮询到 release.txt 就自升级" 'grep -q "取到 0.1.1, 核对通过" "$U/upgrade.log" && "$U/custhub" version | grep -q 0.1.1 && kill -0 $TP'
kill $TP; wait $TP 2>/dev/null; kill $HS; pkill -f "$W/fake-ssh"; TP=; HS=

echo "== 服务注册(演练模式, 不动本机服务)"
I=$W/i; mkdir -p "$I"; export CUSTHUB_D=$I CUSTHUB_SVC_DRY=1 CUSTHUB_WAIT=6
printf 'PORT=22042\n' >"$I/tun.sh"
up_later(){ (sleep 1.5; printf "# custhub test\nhub-a up\n" >"$I/tun-status.txt") & }
CUSTHUB_SVC_KIND=systemd "$B" install >/dev/null; r=$?
ok "从旧 tun.sh 取回拨口" 'grep -q "^port 22042$" "$I/client.conf"'
ok "程序装进安装目录" '"$I/custhub" version | grep -q "^custhub 0.1.0"'
ok "没通道 → 原来没服务就撤掉新装的" '[ $r -eq 1 ] && grep -q "systemctl restart cust-remote-tun" "$I/dry/cmds.log" && grep -q "systemctl disable --now cust-remote-tun" "$I/dry/cmds.log"'
UNIT=$I/dry/etc/systemd/system/cust-remote-tun.service
printf '[Service]\nExecStart=/bin/bash %s/tun.sh\n' "$I" >"$UNIT"; cp "$UNIT" "$W/unit.old"
touch "$I/cust-remote" "$I/cust-remote.old"   # 改名前的旧二进制
up_later; CUSTHUB_SVC_KIND=systemd "$B" install >/dev/null; r=$?
ok "切换成功后删掉改名前的 cust-remote 二进制" '[ ! -e "$I/cust-remote" ] && [ ! -e "$I/cust-remote.old" ]'
ok "systemd: 有通道 → 新服务留下" '[ $r -eq 0 ] && grep -q "^ExecStart=$I/custhub tun$" "$UNIT" && grep -q "^Restart=always" "$UNIT"'
cp "$W/unit.old" "$UNIT"
(sleep 1.5; echo "hub-a up" >"$I/tun-status.txt") & BW=$!   # 旧守护格式(没有标识行)的 up: 不能当成新守护连上
CUSTHUB_SVC_KIND=systemd "$B" install >/dev/null; r=$?; wait $BW 2>/dev/null
ok "旧守护残留的 up 不算连通 → 恢复旧服务" '[ $r -eq 1 ] && cmp -s "$UNIT" "$W/unit.old"'
cp "$W/unit.old" "$UNIT"
CUSTHUB_SVC_KIND=systemd "$B" install >/dev/null; r=$?
ok "systemd: 没通道 → 恢复旧服务" '[ $r -eq 1 ] && cmp -s "$UNIT" "$W/unit.old"'
INIT=$I/dry/etc/init.d/cust-remote-tun; mkdir -p "$(dirname "$INIT")"
printf '%s\n' 'start_service() {' '	procd_open_instance ssh' \
  "	procd_set_param command /usr/sbin/dropbear -F -s -k -p 127.0.0.1:2222 -D $I/ak" '	procd_close_instance' \
  "	[ -x $I/tun.sh ] || return 0" '	procd_open_instance tun' "	procd_set_param command /bin/sh $I/tun.sh" '	procd_close_instance' '}' >"$INIT"
up_later; CUSTHUB_SVC_KIND=procd "$B" install >/dev/null; r=$?
ok "OpenWrt: 只换 tun 实例, 回环 dropbear 不动" '[ $r -eq 0 ] && grep -q "procd_set_param command $I/custhub tun$" "$INIT" && grep -q "\[ -x $I/custhub \]" "$INIT" && grep -q "dropbear -F -s -k -p 127.0.0.1:2222" "$INIT" && ! grep -q tun.sh "$INIT"'
up_later; CUSTHUB_SVC_KIND=mac "$B" install >/dev/null; r=$?
PL=$I/dry/Library/LaunchDaemons/com.custremote.tun.plist
ok "macOS: LaunchDaemon 指向程序且常驻" '[ $r -eq 0 ] && grep -q "<string>$I/custhub</string><string>tun</string>" "$PL" && grep -q KeepAlive "$PL" && grep -q "launchctl bootstrap system" "$I/dry/cmds.log"'
up_later; CUSTHUB_SVC_KIND=systemd "$B" install --port 22077 >/dev/null
ok "--port 覆盖已有配置" '[ "$(grep -c "^port " "$I/client.conf")" -eq 1 ] && grep -q "^port 22077$" "$I/client.conf"'
unset CUSTHUB_SVC_DRY CUSTHUB_WAIT

echo; echo "通过 $pass, 失败 $fail"; [ $fail -eq 0 ]
