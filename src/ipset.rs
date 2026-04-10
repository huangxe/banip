use ipnet::Ipv4Net;
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::process::Command;

const BLACKHOLE_TABLE: u32 = 100;
const BLACKHOLE_TABLE_NAME: &str = "banip_blackhole";
const ROUTE_PRIO: u32 = 10000;

/// Information about an ipset.
#[derive(Debug, Default)]
pub struct SetInfo {
    pub elements: u64,
    pub typ: String,
    pub references: u64,
}

// ═══════════════════════════════════════════════════════════════════════
// ipset operations
// ═══════════════════════════════════════════════════════════════════════

/// Generate an ipset restore script.
pub fn generate_ipset_restore(set_name: &str, cn_cidrs: &[Ipv4Net]) -> String {
    let mut script = String::with_capacity(cn_cidrs.len() * 25 + 256);

    writeln!(script, "create {} hash:net family inet hashsize 65536 maxelem 131072", set_name).unwrap();

    for cidr in cn_cidrs {
        writeln!(script, "add {} {}", set_name, cidr).unwrap();
    }

    script
}

/// Execute ipset restore script via stdin pipe.
pub fn execute_ipset_restore(script: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("ipset")
        .arg("restore")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        let full = script.to_string();
        stdin.write_all(full.as_bytes())?;
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ipset restore failed:\n{}", stderr).into());
    }

    Ok(())
}

/// Check if an ipset with the given name exists.
pub fn set_exists(set_name: &str) -> bool {
    Command::new("ipset")
        .args(["list", "-n", set_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get information about an ipset.
pub fn get_set_info(set_name: &str) -> Option<SetInfo> {
    let output = Command::new("ipset")
        .args(["list", set_name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ipset_list_output(&stdout)
}

fn parse_ipset_list_output(output: &str) -> Option<SetInfo> {
    let mut info = SetInfo::default();

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Name:") {
            for part in line.split_whitespace() {
                match part {
                    "Type:" => {}
                    t if info.typ.is_empty() && !t.contains(':') && !t.contains("Name") => {
                        info.typ = t.to_string();
                    }
                    _ => {}
                }
            }
        }
        if line.starts_with("Type:") {
            info.typ = line.replace("Type:", "").trim().to_string();
        }
        if line.starts_with("References:") {
            let val = line.replace("References:", "").trim().parse().unwrap_or(0);
            info.references = val;
        }
        if line.starts_with("Number of entries:") {
            let val = line.replace("Number of entries:", "").trim().parse().unwrap_or(0);
            info.elements = val;
        }
        if line.starts_with("Members:") {
            break;
        }
    }

    if info.typ.is_empty() { None } else { Some(info) }
}

// ═══════════════════════════════════════════════════════════════════════
// Enable / Disable — pure ip rule + blackhole route, no iptables/nft
// ═══════════════════════════════════════════════════════════════════════
//
// Principle:
//   1. Create a routing table (table 100) with a single blackhole default route.
//      All traffic sent to this table is silently dropped by the kernel.
//
//   2. Add an ip rule with LOWER priority than existing rules:
//        ip rule add prio 32765 from 0.0.0.0/0 lookup banip_blackhole
//      This is a catch-all: traffic NOT matched by higher-priority rules
//      (including main/local tables) goes to blackhole.
//
//   3. Add an ip rule with HIGH priority for China IPs:
//        ip rule add prio 10000 lookup main
//      Combined with ipset match:
//        ip rule add prio 10000 from 0.0.0.0/0 not match-set banip dst lookup banip_blackhole
//
//   On kernels with ipset match support in ip rule:
//     ip rule add prio 10000 not from 0.0.0.0/0 match-set banip blackhole
//
//   For compatibility, we use TWO rules:
//     prio 10000: match-set banip → lookup main   (whitelist: China IPs → normal routing)
//     prio 32765: from 0.0.0.0/0 → lookup banip_blackhole  (catch-all: everything else → blackhole)
//

/// Enable: insert ip rules + blackhole route table.
pub fn enable_rules(set_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Ensure blackhole routing table exists
    ensure_blackhole_table()?;

    // 2. Insert whitelist rule: packets matching the ipset → use main routing table (normal)
    run_cmd("ip", &[
        "rule", "add",
        &format!("prio={}", ROUTE_PRIO),
        &format!("match-set={}", set_name),
        "lookup", "main",
    ])?;

    // 3. Insert catch-all blackhole rule: everything else → blackhole
    run_cmd("ip", &[
        "rule", "add",
        "prio=32765",
        "from", "0.0.0.0/0",
        "lookup", &BLACKHOLE_TABLE.to_string(),
    ])?;

    Ok(())
}

/// Disable: remove ip rules + blackhole route table.
pub fn disable_rules(set_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Remove whitelist rule (may need multiple attempts for duplicates)
    for _ in 0..5 {
        let output = Command::new("ip")
            .args([
                "rule", "del",
                &format!("prio={}", ROUTE_PRIO),
                &format!("match-set={}", set_name),
                "lookup", "main",
            ])
            .output()?;

        if !output.status.success() {
            break;
        }
    }

    // Remove catch-all blackhole rule
    for _ in 0..5 {
        let output = Command::new("ip")
            .args([
                "rule", "del",
                "prio=32765",
                "from", "0.0.0.0/0",
                "lookup", &BLACKHOLE_TABLE.to_string(),
            ])
            .output()?;

        if !output.status.success() {
            break;
        }
    }

    // Remove blackhole routing table entry
    for _ in 0..5 {
        let output = Command::new("ip")
            .args([
                "route", "flush",
                "table", &BLACKHOLE_TABLE.to_string(),
            ])
            .output()?;

        if !output.status.success() {
            break;
        }
    }

    Ok(())
}

/// Check if banip rules are currently active.
pub fn rules_active(set_name: &str) -> bool {
    let output = Command::new("ip")
        .args(["rule", "list"])
        .output()
        .ok();

    if let Some(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Check for our catch-all blackhole rule
            if !stdout.contains(&format!("lookup {}", BLACKHOLE_TABLE)) {
                return false;
            }
            // Also verify the whitelist rule exists
            return stdout.contains(&format!("match-set={}", set_name));
        }
    }

    false
}

/// Ensure the blackhole routing table is configured.
fn ensure_blackhole_table() -> Result<(), Box<dyn std::error::Error>> {
    // Add table entry to /etc/iproute2/rt_tables if not present
    let rt_tables = "/etc/iproute2/rt_tables";
    if let Ok(content) = std::fs::read_to_string(rt_tables) {
        if content.contains(BLACKHOLE_TABLE_NAME) {
            // Table already registered
        } else {
            let entry = format!("{}    {}\n", BLACKHOLE_TABLE, BLACKHOLE_TABLE_NAME);
            std::fs::OpenOptions::new()
                .append(true)
                .open(rt_tables)?
                .write_all(entry.as_bytes())?;
        }
    }

    // Add blackhole default route to the table
    run_cmd("ip", &[
        "route", "replace",
        "blackhole", "default",
        "table", &BLACKHOLE_TABLE.to_string(),
    ])?;

    Ok(())
}

/// Run a command, ignore "File exists" errors.
fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(cmd)
        .args(args)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "File exists" is ok (rule already present)
        if stderr.contains("File exists") || stderr.contains("already exists") {
            return Ok(());
        }
        return Err(format!("{} {:?} failed:\n{}", cmd, args, stderr).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_generate_script() {
        let cidrs = vec![
            Ipv4Net::new(Ipv4Addr::new(1, 0, 1, 0), 24).unwrap(),
            Ipv4Net::new(Ipv4Addr::new(1, 0, 2, 0), 23).unwrap(),
        ];
        let script = generate_ipset_restore("banip", &cidrs);

        assert!(script.contains("create banip hash:net"));
        assert!(script.contains("add banip 1.0.1.0/24"));
        assert!(script.contains("add banip 1.0.2.0/23"));
    }

    #[test]
    fn test_parse_ipset_list_output() {
        let output = r#"Name: banip
Type: hash:net
Revision: 7
Header: family inet hashsize 65536 maxelem 131072 bucketsize 12 initval 0x12345678
Size in memory: 1234
References: 2
Number of entries: 8200
Members:
1.0.1.0/24
"#;
        let info = parse_ipset_list_output(output).unwrap();
        assert_eq!(info.typ, "hash:net");
        assert_eq!(info.elements, 8200);
        assert_eq!(info.references, 2);
    }
}
