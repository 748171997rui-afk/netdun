#!/bin/sh
# dun 一键安装：下载对应架构的二进制，然后打开菜单。sh、bash 都能跑，没有 curl 就用 wget
set -e
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "暂不支持 $(uname -m)"; exit 1 ;;
esac
url="https://github.com/byJoey/dun/releases/latest/download/dun-linux-$arch"
echo "下载 dun ($arch)"
mkdir -p /usr/local/bin
if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar "$url" -o /usr/local/bin/dun.new
elif command -v wget >/dev/null 2>&1; then
    wget -O /usr/local/bin/dun.new "$url"
else
    echo "需要 curl 或 wget，先装一个，比如 apk add curl"
    exit 1
fi
chmod +x /usr/local/bin/dun.new
mv -f /usr/local/bin/dun.new /usr/local/bin/dun
exec /usr/local/bin/dun "$@" </dev/tty
