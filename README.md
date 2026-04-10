# banip

用 `ipset` + `ip rule` + blackhole 路由表禁止所有境外 IP 地址的 Rust 工具。

**不依赖 iptables / nftables**，纯路由层面拦截。

## 工作原理

1. 从 GitHub 下载最新中国 IP CIDR 列表（基于 APNIC 数据）
2. 生成 `ipset restore` 脚本，创建 `hash:net` 类型的 ipset 集合（白名单）
3. `enable` 时通过 `ip rule` 插入两条策略路由规则：
   - **prio 10000**: 匹配 ipset 白名单的流量 → `lookup main`（正常路由）
   - **prio 32765**: 所有其他流量 → `lookup table 100`（blackhole，内核直接丢弃）

```
                   ┌─────────────────────┐
  incoming packet ──►  ip rule prio 10000 ── match-set banip? ──Yes──► main table (正常)
                       │
                       No
                       ▼
                   ip rule prio 32765 ──► table 100 (blackhole) → 丢弃
```

## 编译

```bash
cargo build --release
# 产物: target/release/banip
```

## 命令

### banip update

下载最新中国 IP 列表并重建 ipset。如果当前已 enable，会自动先移除规则再重建。

```bash
sudo banip update
sudo banip update --url https://your-server.com/china_cidr.txt
```

### banip enable

禁止非中国 IP 出入（插入 ip rule + blackhole 路由）。如果 ipset 不存在，会从本地缓存自动构建。

```bash
sudo banip enable
```

### banip disable

取消封禁（移除 ip rule + blackhole 路由）。

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
ipset:      banip (exists)
Entries:    8200
Type:       hash:net
References: 1
Data dir:   /var/lib/banip
CIDR file:  present
Last update: 2026-04-10 23:30:00
```

## 全局参数

| 参数 | 短选项 | 说明 | 默认值 |
|------|--------|------|--------|
| `--set` | `-s` | ipset 集合名称 | `banip` |
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

- Linux 内核 4.x+（需支持 `ip rule` 的 `match-set` 扩展）
- `ipset` >= 6.x
- `iproute2`
- Rust 1.70+（编译）

## License

MIT
