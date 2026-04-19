use ipnet::Ipv4Net;
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::process::Command;

const NFT_TABLE: &str = "banip";
const NFT_SET_NAME: &str = "china";

/// Information about an nftables set.
#[derive(Debug, Default)]
pub struct SetInfo {
    pub elements: u64,
    pub typ: String,
}

// ═══════════════════════════════════════════════════════════════════════
// nftables operations
// ═══════════════════════════════════════════════════════════════════════

/// Generate an nftables script to create the table, set, and rules.
/// Flushes existing set content before adding elements.
pub fn generate_nft_script(set_name: &str, cn_cidrs: &[Ipv4Net]) -> String {
    let mut script = String::with_capacity(cn_cidrs.len() * 25 + 2048);
    let table = NFT_TABLE;
    let set = set_name;

    // Create table (add if doesn't exist)
    writeln!(script, "add table inet {}", table).unwrap();

    // Create set with CIDR interval type, flush existing entries
    writeln!(
        script,
        "add set inet {} {} {{ type ipv4_addr; flags interval; size 131072; }}",
        table, set
    ).unwrap();
    writeln!(script, "flush set inet {} {}", table, set).unwrap();

    // Add CIDR elements
    for cidr in cn_cidrs {
        writeln!(script, "add element inet {} {} {{ {} }}", table, set, cidr).unwrap();
    }

    // Create chain in route output hook (drops non-China traffic at routing decision)
    // Using "route output" hook — evaluates after routing decision,
    // dropping packets whose destination is NOT in the China set.
    // We also exclude locally-generated packets destined for local addresses.
    writeln!(
        script,
        "add chain inet {} banip_out {{ type route hook output priority filter; policy accept; }}",
        table
    ).unwrap();

    // Rule 1: skip loopback / local-interface addresses (127.x, ::1, etc.)
    writeln!(
        script,
        "add rule inet {} banip_out fib daddr type local accept",
        table
    ).unwrap();

    // Rule 2: skip RFC 1918 private ranges (LAN, e.g. 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    writeln!(
        script,
        "add rule inet {} banip_out ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} accept",
        table
    ).unwrap();

    // Rule 3: skip CGNAT / Tailscale range (100.64.0.0/10)
    writeln!(
        script,
        "add rule inet {} banip_out ip daddr 100.64.0.0/10 accept",
        table
    ).unwrap();

    // Rule 4: skip link-local addresses (169.254.0.0/16)
    writeln!(
        script,
        "add rule inet {} banip_out ip daddr 169.254.0.0/16 accept",
        table
    ).unwrap();

    // Rule 5: drop if destination NOT in China set
    writeln!(
        script,
        "add rule inet {} banip_out ip daddr != @{} drop",
        table, set
    ).unwrap();

    script
}

/// Execute an nftables script via stdin pipe.
pub fn execute_nft_script(script: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Write script to a temp file and use nft -f <file> to avoid pipe issues with large scripts
    let tmp_path = format!("/tmp/banip_nft_{}.nft", std::process::id());
    std::fs::write(&tmp_path, script)?;

    let output = Command::new("nft")
        .args(["-f", &tmp_path])
        .output()?;

    let _ = std::fs::remove_file(&tmp_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nft failed:\n{}", stderr).into());
    }

    Ok(())
}

/// Check if the banip nftables table exists.
pub fn set_exists(set_name: &str) -> bool {
    // Check if the table exists by listing sets in the table
    let output = Command::new("nft")
        .args(["list", "sets"])
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains(&format!("inet {} {}", NFT_TABLE, set_name))
        }
        _ => false,
    }
}

/// Get information about the nftables set (element count).
pub fn get_set_info(set_name: &str) -> Option<SetInfo> {
    // Use JSON output for reliable parsing
    let output = Command::new("nft")
        .args(["-j", "list", "set", "inet", NFT_TABLE, set_name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_nft_json_output(&stdout)
}

/// Parse `nft -j list set` JSON output to extract element count.
fn parse_nft_json_output(output: &str) -> Option<SetInfo> {
    let mut info = SetInfo::default();
    info.typ = "ipv4_addr (interval)".to_string();

    // Simple JSON parsing without serde — look for "elem" array or "size" field
    // nft JSON format: { "nftables": [ ..., { "set": { "name": "china", "type": "ipv4_addr", "elem": [...] } } ] }
    if let Some(start) = output.find("\"elem\"") {
        // Find the array after "elem"
        let rest = &output[start..];
        // Count commas between [ and ] to determine element count
        if let Some(bracket_start) = rest.find('[') {
            let bracket_rest = &rest[bracket_start + 1..];
            let count = if bracket_rest.starts_with(']') {
                0
            } else {
                // Count commas + 1
                let bracket_end = bracket_rest.find(']').unwrap_or(bracket_rest.len());
                let array_content = &bracket_rest[..bracket_end];
                array_content.matches(',').count() + 1
            };
            info.elements = count as u64;
        }
    }

    if output.contains("\"set\"") && output.contains("ipv4_addr") {
        Some(info)
    } else {
        None
    }
}

/// Parse `nft list set` text output to extract element count (fallback).
pub fn parse_nft_set_output(output: &str) -> Option<SetInfo> {
    let mut info = SetInfo::default();
    info.typ = "ipv4_addr (interval)".to_string();

    for line in output.lines() {
        let line = line.trim();
        if line.contains("elements") {
            // Format 1: "elements = 8200"
            if let Some(pos) = line.find('=') {
                let count_str = line[pos + 1..].trim();
                if count_str.starts_with('{') {
                    // Format 2: "elements = { 1.0.1.0/24, 1.0.2.0/23 }"
                    // Count commas + 1
                    let end = count_str.find('}').unwrap_or(count_str.len());
                    let inner = &count_str[1..end];
                    if inner.trim().is_empty() {
                        info.elements = 0;
                    } else {
                        info.elements = inner.matches(',').count() as u64 + 1;
                    }
                } else {
                    if let Some(end) = count_str.find(|c: char| !c.is_ascii_digit()) {
                        info.elements = count_str[..end].parse().unwrap_or(0);
                    } else {
                        info.elements = count_str.parse().unwrap_or(0);
                    }
                }
            }
        }
    }

    // Only return Some if we found the set type marker
    if output.contains("set") && (output.contains("ipv4_addr") || output.contains("interval")) {
        Some(info)
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Enable / Disable — nftables only, no ip rule / blackhole / iptables
// ═══════════════════════════════════════════════════════════════════════
//
// Principle:
//   1. Create nftables table "banip" with:
//      - A set "china" of type ipv4_addr (interval) containing China CIDRs
//      - A chain in "route output" hook: drops outgoing packets whose
//        destination is NOT in the china set (except local addresses)
//      - A chain in "route prerouting" hook: same for forwarded traffic
//
//   2. "enable" = create the full nftables setup (table + set + rules)
//   3. "disable" = delete the entire "banip" table (removes everything)
//

/// Enable: create nftables table with China whitelist rules.
pub fn enable_rules(set_name: &str, cn_cidrs: &[Ipv4Net]) -> Result<(), Box<dyn std::error::Error>> {
    let script = generate_nft_script(set_name, cn_cidrs);
    execute_nft_script(&script)
}

/// Disable: delete the entire banip nftables table.
pub fn disable_rules(_set_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "No such file or directory" means table doesn't exist, which is fine
        if !stderr.contains("No such file") && !stderr.contains("not found") {
            return Err(format!("nft delete table failed:\n{}", stderr).into());
        }
    }

    Ok(())
}

/// Check if banip rules are currently active.
pub fn rules_active(set_name: &str) -> bool {
    let output = Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .output()
        .ok();

    match output {
        Some(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            check_rules_in_output(&stdout, set_name)
        }
        _ => false,
    }
}

/// Parse nftables table listing and check if banip rules are present.
pub fn check_rules_in_output(output: &str, set_name: &str) -> bool {
    output.contains(&format!("@{}", set_name)) && output.contains("drop")
}

/// Check if the table listing contains a drop rule referencing our set.
pub fn has_drop_rule(output: &str, set_name: &str) -> bool {
    check_rules_in_output(output, set_name)
}

/// Check if the set exists in the output.
pub fn has_whitelist_set(output: &str, set_name: &str) -> bool {
    output.contains(&format!("set {} {{", set_name))
        || output.contains(&format!("set {}", set_name))
}

/// Run a command and return the output.
fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(cmd)
        .args(args)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{} {:?} failed:\n{}", cmd, args, stderr).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ─── generate_nft_script ──────────────────────────────────────

    #[test]
    fn test_generate_script_basic() {
        let cidrs = vec![
            Ipv4Net::new(Ipv4Addr::new(1, 0, 1, 0), 24).unwrap(),
            Ipv4Net::new(Ipv4Addr::new(1, 0, 2, 0), 23).unwrap(),
        ];
        let script = generate_nft_script("china", &cidrs);

        assert!(script.contains("add table inet banip"));
        assert!(script.contains("add set inet banip china"));
        assert!(script.contains("type ipv4_addr"));
        assert!(script.contains("add element inet banip china { 1.0.1.0/24 }"));
        assert!(script.contains("add element inet banip china { 1.0.2.0/23 }"));
        assert!(script.contains("ip daddr != @china"));
        assert!(script.contains("drop"));
    }

    #[test]
    fn test_generate_script_custom_set_name() {
        let cidrs = vec![
            Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
        ];
        let script = generate_nft_script("my_whitelist", &cidrs);
        assert!(script.contains("add set inet banip my_whitelist"));
        assert!(script.contains("add element inet banip my_whitelist { 10.0.0.0/8 }"));
        assert!(script.contains("ip daddr != @my_whitelist"));
    }

    #[test]
    fn test_generate_script_empty_cidrs() {
        let script = generate_nft_script("china", &[]);
        assert!(script.contains("add table inet banip"));
        assert!(script.contains("add set inet banip china"));
        assert!(!script.contains("add element"));
    }

    #[test]
    fn test_generate_script_single_entry() {
        let cidrs = vec![
            Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap(),
        ];
        let script = generate_nft_script("china", &cidrs);
        // Should contain exactly one add element line
        let add_count = script.matches("add element").count();
        assert_eq!(add_count, 1);
    }

    #[test]
    fn test_generate_script_many_entries() {
        let cidrs: Vec<Ipv4Net> = (0..100)
            .map(|i| Ipv4Net::new(Ipv4Addr::new(i, 0, 0, 0), 8).unwrap())
            .collect();
        let script = generate_nft_script("china", &cidrs);
        let add_count = script.matches("add element").count();
        assert_eq!(add_count, 100);
    }

    #[test]
    fn test_generate_script_contains_flush() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        assert!(script.contains("flush set inet banip china"));
    }

    #[test]
    fn test_generate_script_contains_size() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        assert!(script.contains("size 131072"));
    }

    #[test]
    fn test_generate_script_contains_interval_flag() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        assert!(script.contains("flags interval"));
    }

    #[test]
    fn test_generate_script_has_route_output_chain() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        assert!(script.contains("type route hook output"));
    }

    #[test]
    fn test_generate_script_excludes_local_addresses() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        // fib local accept rule should be present (replaces the old "!= local drop" approach)
        assert!(script.contains("fib daddr type local accept"));
    }

    #[test]
    fn test_generate_script_exempts_rfc1918() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        // RFC 1918 private ranges must be accepted before the drop rule
        assert!(script.contains("10.0.0.0/8"));
        assert!(script.contains("172.16.0.0/12"));
        assert!(script.contains("192.168.0.0/16"));
    }

    #[test]
    fn test_generate_script_exempts_tailscale_cgnat() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        // CGNAT / Tailscale (100.64.0.0/10) must be accepted
        assert!(script.contains("100.64.0.0/10"));
    }

    #[test]
    fn test_generate_script_exempts_link_local() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        // Link-local (169.254.0.0/16) must be accepted
        assert!(script.contains("169.254.0.0/16"));
    }

    #[test]
    fn test_generate_script_exempt_rules_before_drop() {
        let cidrs = vec![Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 24).unwrap()];
        let script = generate_nft_script("china", &cidrs);
        // All accept rules must appear before the final drop rule
        let rfc1918_pos = script.find("192.168.0.0/16").unwrap();
        let tailscale_pos = script.find("100.64.0.0/10").unwrap();
        let drop_pos = script.rfind("drop").unwrap();
        assert!(rfc1918_pos < drop_pos, "RFC1918 accept must be before drop");
        assert!(tailscale_pos < drop_pos, "Tailscale accept must be before drop");
    }

    // ─── parse_nft_set_output ─────────────────────────────────────

    #[test]
    fn test_parse_nft_set_output_with_elements() {
        let output = r#"table inet banip {
    set china {
        type ipv4_addr
        flags interval
        elements = { 1.0.1.0/24, 1.0.2.0/23 }
    }
}"#;
        let info = parse_nft_set_output(output).unwrap();
        assert_eq!(info.elements, 2);
    }

    #[test]
    fn test_parse_nft_set_output_large_count() {
        let output = r#"table inet banip {
    set china {
        type ipv4_addr
        flags interval
        size 131072
        elements = { 1.0.1.0/24 }
    }
}
elements = 8200
"#;
        let info = parse_nft_set_output(output).unwrap();
        assert_eq!(info.elements, 8200);
    }

    #[test]
    fn test_parse_nft_set_output_zero_entries() {
        let output = r#"table inet banip {
    set china {
        type ipv4_addr
        flags interval
    }
}"#;
        let info = parse_nft_set_output(output).unwrap();
        assert_eq!(info.elements, 0);
    }

    #[test]
    fn test_parse_nft_set_output_empty_input() {
        let info = parse_nft_set_output("");
        assert!(info.is_none());
    }

    #[test]
    fn test_parse_nft_set_output_garbage() {
        let info = parse_nft_set_output("not an nft listing");
        assert!(info.is_none());
    }

    // ─── check_rules_in_output ────────────────────────────────────

    #[test]
    fn test_check_rules_both_present() {
        let output = r#"table inet banip {
    set china { ... }
    chain banip_out {
        ip daddr != @china fib daddr type != local drop
    }
}"#;
        assert!(check_rules_in_output(output, "china"));
    }

    #[test]
    fn test_check_rules_only_drop_no_set() {
        let output = "ip daddr != @other drop\n";
        assert!(!check_rules_in_output(output, "china"));
    }

    #[test]
    fn test_check_rules_neither_present() {
        assert!(!check_rules_in_output("table inet other { }", "china"));
    }

    #[test]
    fn test_check_rules_empty_output() {
        assert!(!check_rules_in_output("", "china"));
    }

    #[test]
    fn test_check_rules_different_set_name() {
        let output = r#"chain banip_out {
    ip daddr != @other_set fib daddr type != local drop
}"#;
        assert!(!check_rules_in_output(output, "china"));
    }

    // ─── has_drop_rule / has_whitelist_set ────────────────────────

    #[test]
    fn test_has_drop_rule_present() {
        let output = r#"chain banip_out {
    ip daddr != @china fib daddr type != local drop
}"#;
        assert!(has_drop_rule(output, "china"));
    }

    #[test]
    fn test_has_drop_rule_absent() {
        assert!(!has_drop_rule("chain banip_out { accept }", "china"));
    }

    #[test]
    fn test_has_whitelist_set_present() {
        let output = "set china {\n  type ipv4_addr\n}\n";
        assert!(has_whitelist_set(output, "china"));
    }

    #[test]
    fn test_has_whitelist_set_absent() {
        assert!(!has_whitelist_set("set other { }", "china"));
    }

    // ─── constants ─────────────────────────────────────────────────

    #[test]
    fn test_nft_table_name() {
        assert_eq!(NFT_TABLE, "banip");
    }

    #[test]
    fn test_nft_set_name_default() {
        assert_eq!(NFT_SET_NAME, "china");
    }
}
