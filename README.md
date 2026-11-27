

登录 VPS，执行：

```bash
bash <(curl -fsSL https://github.com/748171997rui-afk/netdun/releases/latest/download/install.sh)
```

Alpine 默认没有 bash 和 curl，换成这一条：

```sh
wget -qO- https://github.com/748171997rui-afk/netdun/releases/latest/download/install.sh | sh
```

菜单里选 `4` 三个一起装。中间会让你选 Cloudflare 凭据类型和域名，其他问题一路回车用默认值就行。装完屏幕上会打出订阅地址，复制进客户端就能用。

源码https://github.com/byJoey/dun修改了NET主机使用的问题
