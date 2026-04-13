# banip

用 `nftables` 禁止所有境外 IP 地址的 Rust 工具。

**不依赖 iptables / ip rule / blackhole**，纯 nftables 拦截。

## 工作原理

1. 从 GitHub 下载最新中国 IP CIDR 列表（基于 APNIC 数据）
2. 创建 nftables table `banip`，包含一个 `ipv4_addr` 类型的 named set（白名单）
3. 在 `route output` 和 `route prerouting` hook 上添加 drop 规则：
   - 目标 IP **在**白名单中 → 正常放行
   - 目标 IP **不在**白名单中且非本地地址 → 丢弃
   - 目标是本地地址（127.0.0.0/8 等）→ 放行

```
                   ┌──────────────────────────────────┐
  outgoing packet ──► nftables route output hook      │
                       │                               │
                       ├─ fib daddr type == local? ──Yes──► accept
                       │                               │
                       ├─ ip daddr ∈ @china set? ──Yes──► accept
                       │                               │
                       └─ No ──► drop
```

## 编译

```bash
cargo build --release
# 产物: target/release/banip
```

## 命令

### banip update

下载最新中国 IP 列表并重建 nftables set。如果当前已 enable，会自动先删除表再重建。

```bash
sudo banip update
sudo banip update --url https://your-server.com/china_cidr.txt
```

### banip enable

禁止非中国 IP 出入（创建 nftables table + set + drop 规则）。如果无本地 CIDR 缓存，自动执行 `update`。

```bash
sudo banip enable
```

### banip disable

取消封禁（删除整个 banip nftables table）。

```bash
sudo banip disable
```

### banip state

查看当前使能状态。

```bash
banip state
```

输出示例：
```
Status:     ENABLED
nft set:    china (exists)
Entries:    8200
Type:       ipv4_addr (interval)
Data dir:   /var/lib/banip
CIDR file:  present
Last update: 2026-04-11 22:00:00
```

## 全局参数

| 参数 | 短选项 | 说明 | 默认值 |
|------|--------|------|--------|
| `--set` | `-s` | nftables set 名称 | `china` |
| `--dir` | `-d` | 数据目录 | `/var/lib/banip` |

## 数据目录结构

```
/var/lib/banip/
├── cn_ip_cidr.txt   # 下载的中国 IP CIDR 列表
└── state.toml        # 持久化状态
```

## 数据源

默认使用 [isxpy/China-ip-range](https://github.com/isxpy/China-ip-range) 的 `cnip_cidr.txt`，数据来源于 APNIC 每日更新的 IP 地址分配数据库。

## 系统要求

- Linux 内核 4.x+（需支持 nftables）
- `nftables`
- Rust 1.70+（编译）

## License

MIT
