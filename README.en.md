# banip

A Rust CLI tool that blocks all non-China IP addresses using `nftables`.

**No iptables / ip rule / blackhole dependency.** Pure nftables enforcement.

## How It Works

1. Downloads the latest China IP CIDR list from GitHub (based on APNIC data)
2. Creates an nftables table `banip` with a named set of type `ipv4_addr` (whitelist)
3. Adds drop rules on `route output` and `route prerouting` hooks:
   - Destination IP **in** whitelist → accept (normal routing)
   - Destination IP **not in** whitelist and not local → drop
   - Destination is local address (127.0.0.0/8, etc.) → accept

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

## Build

```bash
cargo build --release
# Output: target/release/banip
```

Cross-compile for Linux from Windows:

```bash
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```

## Usage

### banip update

Download the latest China IP CIDR list and rebuild nftables set. If currently enabled, the table is deleted and recreated.

```bash
sudo banip update
sudo banip update --url https://your-server.com/china_cidr.txt
```

### banip enable

Block all non-China IP traffic (create nftables table + set + drop rules). If no local CIDR cache exists, `update` runs automatically first.

```bash
sudo banip enable
```

### banip disable

Remove the block (delete the entire banip nftables table).

```bash
sudo banip disable
```

### banip state

Show current status.

```bash
banip state
```

Example output:
```
Status:     ENABLED
nft set:    china (exists)
Entries:    8200
Type:       ipv4_addr (interval)
Data dir:   /var/lib/banip
CIDR file:  present
Last update: 2026-04-11 22:00:00
```

## Global Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--set` | `-s` | nftables set name | `china` |
| `--dir` | `-d` | Data directory | `/var/lib/banip` |

## Data Directory

```
/var/lib/banip/
├── cn_ip_cidr.txt   # Downloaded China IP CIDR list
└── state.toml        # Persistent state
```

## Data Source

By default, uses [`cnip_cidr.txt`](https://github.com/isxpy/China-ip-range) from [isxpy/China-ip-range](https://github.com/isxpy/China-ip-range), sourced from the APNIC daily-updated IP allocation database.

## Requirements

- Linux kernel 4.x+ (with nftables support)
- `nftables`
- Rust 1.70+ (to compile)

## Testing

```bash
cargo test
```

Includes 80+ unit tests covering CIDR parsing, download URL building, nftables script generation, state persistence, and CLI argument parsing.

## License

MIT
