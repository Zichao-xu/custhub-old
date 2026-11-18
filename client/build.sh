#!/usr/bin/env bash
# 构建客户机程序 custhub(SPEC §6) → ../../pkg/client/
#   ./build.sh            全平台(zig 一处交叉编译)
#   ./build.sh native     只编本机一份到 ./custhub(开发/测试用; 平台名默认 dev, 永不自升级; PLAT=xx 可改)
# 密码学只用 vendor/ 里的 Monocypher 4.0.2(官网与 GitHub 两份源码已核对一致)
# Windows 不用 zig 自带的 mingw(它只链 UCRT, 没打 KB2999226 的 Win7 起不来), 改链系统自带的 msvcrt.dll:
#   头文件/库取 llvm-mingw 20261104 的 msvcrt 版(只用 sysroot, 与宿主无关), 本机 clang 编译 + zig lld-link 链接
#   sysroot 放 $MINGW(默认 ~/.cache/llvm-mingw-msvcrt-20261104); 没有就按下面的 URL 取一次:
#   https://github.com/mstorsjo/llvm-mingw/releases/download/20261104/llvm-mingw-20261104-msvcrt-ubuntu-22.04-x86_64.tar.xz
#   sha256 6e3342e2e0dfa56e9178f3c34b198f278bd5e603db4a759455d1439cc2230630; 解开后留 {x86_64,i686,generic}-w64-mingw32 include lib/clang
set -euo pipefail
cd "$(dirname "$0")"
V=$(sed -n 's/^#define CR_VERSION "\(.*\)"/\1/p' cr.h)
SRC=(main.c util.c sshsig.c trust.c tun.c meshd.c engineer.c http.c upgrade.c install.c join.c join_win.c posix.c win.c vendor/monocypher.c vendor/monocypher-ed25519.c
     ../mesh/util.c ../mesh/noise.c ../mesh/link.c ../mesh/hop.c ../mesh/disc.c ../mesh/app.c ../mesh/main.c)   # 网络层(design-v3), custhub mesh …
CF=(-std=c99 -Os -Wall -Wextra -Wno-unused-parameter -ffunction-sections -fdata-sections -DNDEBUG -DMESH_IN_CUSTHUB)

if [ "${1:-}" = native ]; then
  o=${OUTBIN:-custhub}   # 测试用: OUTBIN=输出路径 VER=版本号 编一份"别的版本"
  cc "${CF[@]}" -DCR_PLAT="\"${PLAT:-dev}\"" ${VER:+-DCR_VERSION="\"$VER\""} -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -o "$o" "${SRC[@]}"
  echo "$o ($(wc -c <"$o" | tr -d ' ') 字节)"; exit 0
fi

OUT=${OUTDIR:-../../pkg/client}; mkdir -p "$OUT"   # 测试用: OUTDIR=目录 VER=版本号 ONLY=平台名前缀(如 win)
[ -n "${VER:-}" ] && { V=$VER; CF+=(-DCR_VERSION="\"$VER\""); }
b(){  # b zig目标 输出名 [额外参数...]
  local t=$1 n=$2; shift 2
  case $n in ${ONLY:-}*) ;; *) return 0 ;; esac
  local ext=; case $t in *windows*) ext=.exe ;; esac
  local f="$OUT/custhub-$V-$n$ext"
  zig cc -target "$t" "${CF[@]}" -DCR_PLAT="\"$n\"" "$@" -o "$f" "${SRC[@]}"
  rm -f "$f".pdb "${f%.exe}.pdb"
  printf '%-16s %8s  %s\n' "$n" "$(wc -c <"$f" | tr -d ' ')" "$(shasum -a 256 "$f" | cut -d' ' -f1)"
}
MINGW=${MINGW:-$HOME/.cache/llvm-mingw-msvcrt-20261104}
w(){  # w x86_64|i686 输出名
  local t=$1 n=$2 m=x64 rt=$1 o; [ "$t" = i686 ] && { m=x86; rt=i386; }
  case $n in ${ONLY:-}*) ;; *) return 0 ;; esac
  [ -d "$MINGW/$t-w64-mingw32/lib" ] || { echo "缺 Windows sysroot: $MINGW(见脚本开头)" >&2; exit 1; }
  o=$(mktemp -d); local f="$OUT/custhub-$V-$n.exe" lb="$MINGW/$t-w64-mingw32/lib"
  for s in "${SRC[@]}"; do clang -target $t-w64-mingw32 --sysroot="$MINGW" "${CF[@]}" -D_WIN32_WINNT=0x0601 -DCR_PLAT="\"$n\"" -c -o "$o/$(echo "$s" | tr '/.' '__').o" "$s"; done
  zig lld-link -lldmingw -machine:$m -subsystem:console -entry:mainCRTStartup -opt:ref -debug:none -out:"$f" \
    "$lb/crt2.o" "$lb/crtbegin.o" "$o"/*.o "$lb/crtend.o" -libpath:"$lb" -libpath:"$(ls -d "$MINGW"/lib/clang/*/lib/windows)" \
    libws2_32.a libmingw32.a libclang_rt.builtins-$rt.a libmoldname.a libmingwex.a libmsvcrt.a libadvapi32.a libkernel32.a \
    libole32.a liboleaut32.a libshell32.a libuser32.a libuuid.a
  rm -f "$o"/*.o; rmdir "$o"
  # 只许依赖 Win7 自带的 DLL(查 PE 导入表; 运行时 GetModuleHandle 取的 ntdll 不算)
  local bad; bad=$(objdump -p "$f" | awk '/DLL Name:/{print $3}' | grep -viE '^(kernel32|ws2_32|msvcrt|advapi32|ole32|oleaut32|shell32|user32)\.dll$' || true)
  [ -z "$bad" ] || { echo "$n 依赖了 Win7 可能没有的 DLL: $bad" >&2; exit 1; }
  printf '%-16s %8s  %s\n' "$n" "$(wc -c <"$f" | tr -d ' ')" "$(shasum -a 256 "$f" | cut -d' ' -f1)"
}
POSIX=(-D_DEFAULT_SOURCE -Wl,--gc-sections -s)
w x86_64 win-x64
w i686   win-x86
b aarch64-macos         mac-arm64    -D_DARWIN_C_SOURCE
b x86_64-macos          mac-x64      -D_DARWIN_C_SOURCE
b x86_64-linux-musl     linux-amd64  "${POSIX[@]}" -static
b aarch64-linux-musl    linux-arm64  "${POSIX[@]}" -static
b arm-linux-musleabi    linux-armv5  "${POSIX[@]}" -static -mcpu=arm926ej_s
b mips-linux-musleabi   linux-mips   "${POSIX[@]}" -static -mcpu=mips32 -msoft-float
b mipsel-linux-musleabi linux-mipsel "${POSIX[@]}" -static -mcpu=mips32 -msoft-float
