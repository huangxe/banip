mod cidr;
mod download;
mod ipset;
mod state;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

const SET_NAME: &str = "banip";
const DATA_DIR: &str = "/var/lib/banip";
const CIDR_FILE: &str = "cn_ip_cidr.txt";

#[derive(Parser, Debug)]
#[command(name = "banip", about = "Ban all non-China IP addresses using ipset + ip rule blackhole", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Custom ipset set name (default: "banip")
    #[arg(short, long, global = true, default_value = SET_NAME)]
    set: String,

    /// Custom data directory (default: /var/lib/banip)
    #[arg(short, long, global = true, default_value = DATA_DIR)]
    dir: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Download the latest China IP CIDR list and rebuild ipset
    Update {
        /// Custom download URL
        #[arg(short, long)]
        url: Option<String>,
    },

    /// Enable: insert ip rule + blackhole route to block non-China traffic
    Enable,

    /// Disable: remove ip rule + blackhole route
    Disable,

    /// Show current banip status
    State,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Update { url } => cmd_update(&cli.dir, &cli.set, url),
        Commands::Enable => cmd_enable(&cli.dir, &cli.set),
        Commands::Disable => cmd_disable(&cli.dir, &cli.set),
        Commands::State => cmd_state(&cli.dir, &cli.set),
    }
}

// ─── update ────────────────────────────────────────────────────────────

fn cmd_update(data_dir: &str, set_name: &str, url: Option<String>) {
    require_root();

    let dir = PathBuf::from(data_dir);
    let cidr_path = dir.join(CIDR_FILE);

    // Ensure data directory exists
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
        eprintln!("Error creating directory '{}': {}", dir.display(), e);
        std::process::exit(1);
    });

    // Download
    let download_url = url.as_deref().unwrap_or(download::DEFAULT_CN_IP_URL);
    println!("banip update - downloading China IP CIDR list...");
    println!("  URL: {}", download_url);

    let content = download::download_cn_ip_list(download_url).unwrap_or_else(|e| {
        eprintln!("Download failed: {}", e);
        std::process::exit(1);
    });

    // Save to file
    std::fs::write(&cidr_path, &content).unwrap_or_else(|e| {
        eprintln!("Error writing '{}': {}", cidr_path.display(), e);
        std::process::exit(1);
    });

    // Parse
    let cidrs = cidr::parse_cidr_list(&content);
    if cidrs.is_empty() {
        eprintln!("Error: no valid CIDR ranges found.");
        std::process::exit(1);
    }

    println!("  Saved to: {}", cidr_path.display());
    println!("  Parsed {} CIDR ranges ({} IPs)", cidrs.len(), format_number(
        cidrs.iter().map(|c| c.hosts().count() as u64).sum()
    ));

    // If currently enabled, disable first, then rebuild
    let was_enabled = ipset::rules_active(set_name);
    if was_enabled {
        println!("  Temporarily disabling rules...");
        if let Err(e) = ipset::disable_rules(set_name) {
            eprintln!("Warning: disable_rules failed: {}", e);
        }
    }

    println!("  Rebuilding ipset...");
    let script = ipset::generate_ipset_restore(set_name, &cidrs);
    ipset::execute_ipset_restore(&script).unwrap_or_else(|e| {
        eprintln!("ipset restore failed: {}", e);
        std::process::exit(1);
    });

    if was_enabled {
        println!("  Re-enabling rules...");
        if let Err(e) = ipset::enable_rules(set_name) {
            eprintln!("Warning: re-enable failed: {}", e);
        }
    }

    // Update state
    state::save(data_dir, &state::BanipState {
        enabled: was_enabled,
        updated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        cidr_count: cidrs.len(),
        set_name: set_name.to_string(),
    });

    println!("Update done.");
}

// ─── enable ────────────────────────────────────────────────────────────

fn cmd_enable(data_dir: &str, set_name: &str) {
    require_root();

    // Check if already enabled
    if ipset::rules_active(set_name) {
        println!("Already enabled.");
        cmd_state(data_dir, set_name);
        return;
    }

    // Check if ipset exists
    let dir = PathBuf::from(data_dir);
    let cidr_path = dir.join(CIDR_FILE);

    if !ipset::set_exists(set_name) {
        if !cidr_path.exists() {
            println!("No local CIDR data found, running update first...");
            cmd_update(data_dir, set_name, None);
        } else {
            // Load CIDR data and create ipset
            println!("ipset not found, building from local cache...");
            let content = std::fs::read_to_string(&cidr_path).unwrap_or_else(|e| {
                eprintln!("Error reading '{}': {}", cidr_path.display(), e);
                std::process::exit(1);
            });

            let cidrs = cidr::parse_cidr_list(&content);
            if cidrs.is_empty() {
                eprintln!("Error: no valid CIDR ranges in cache. Running update...");
                cmd_update(data_dir, set_name, None);
            } else {
                println!("  Building ipset with {} entries...", cidrs.len());
                let script = ipset::generate_ipset_restore(set_name, &cidrs);
                ipset::execute_ipset_restore(&script).unwrap_or_else(|e| {
                    eprintln!("ipset restore failed: {}", e);
                    std::process::exit(1);
                });
            }
        }
    }

    // Insert ip rule + blackhole route
    ipset::enable_rules(set_name).unwrap_or_else(|e| {
        eprintln!("Enable failed: {}", e);
        std::process::exit(1);
    });

    // Update state
    let mut st = state::load(data_dir).unwrap_or_default();
    st.enabled = true;
    state::save(data_dir, &st);

    println!("Enabled. Non-China traffic is routed to blackhole.");
}

// ─── disable ───────────────────────────────────────────────────────────

fn cmd_disable(data_dir: &str, set_name: &str) {
    require_root();

    if !ipset::rules_active(set_name) {
        println!("Already disabled.");
        cmd_state(data_dir, set_name);
        return;
    }

    ipset::disable_rules(set_name).unwrap_or_else(|e| {
        eprintln!("Disable failed: {}", e);
        std::process::exit(1);
    });

    let mut st = state::load(data_dir).unwrap_or_default();
    st.enabled = false;
    state::save(data_dir, &st);

    println!("Disabled. ip rule + blackhole route removed.");
}

// ─── state ─────────────────────────────────────────────────────────────

fn cmd_state(data_dir: &str, set_name: &str) {
    let st = state::load(data_dir).unwrap_or_default();
    let active = ipset::rules_active(set_name);
    let set_exists = ipset::set_exists(set_name);
    let set_info = ipset::get_set_info(set_name);

    println!("Status:     {}", if active { "ENABLED" } else { "DISABLED" });
    println!("ipset:      {} ({})", set_name, if set_exists { "exists" } else { "not found" });

    if let Some(info) = set_info {
        println!("Entries:    {}", info.elements);
        println!("Type:       {}", info.typ);
        println!("References: {}", info.references);
    }

    println!("Data dir:   {}", data_dir);
    println!("CIDR file:  {}", if PathBuf::from(data_dir).join(CIDR_FILE).exists() { "present" } else { "missing" });
    println!("Last update: {}", if st.updated_at.is_empty() { "never" } else { &st.updated_at });

    if st.enabled != active {
        println!("\nWarning: stored state ({}) differs from runtime state ({}).",
            if st.enabled { "enabled" } else { "disabled" },
            if active { "enabled" } else { "disabled" }
        );
        println!("Run 'banip enable' or 'banip disable' to synchronize.");
    }
}

// ─── helpers ───────────────────────────────────────────────────────────

fn require_root() {
    if !is_root() {
        eprintln!("Error: root privileges required. Run with sudo.");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    true
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // ─── CLI parsing: subcommands ───────────────────────────────────

    #[test]
    fn test_cli_update() {
        let cli = Cli::parse_from(["banip", "update"]);
        match cli.command {
            Commands::Update { url } => assert!(url.is_none()),
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn test_cli_update_with_url() {
        let cli = Cli::parse_from(["banip", "update", "--url", "https://example.com/ips.txt"]);
        match cli.command {
            Commands::Update { url } => assert_eq!(url.unwrap(), "https://example.com/ips.txt"),
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn test_cli_enable() {
        let cli = Cli::parse_from(["banip", "enable"]);
        match cli.command {
            Commands::Enable => {}
            _ => panic!("expected Enable command"),
        }
    }

    #[test]
    fn test_cli_disable() {
        let cli = Cli::parse_from(["banip", "disable"]);
        match cli.command {
            Commands::Disable => {}
            _ => panic!("expected Disable command"),
        }
    }

    #[test]
    fn test_cli_state() {
        let cli = Cli::parse_from(["banip", "state"]);
        match cli.command {
            Commands::State => {}
            _ => panic!("expected State command"),
        }
    }

    // ─── CLI parsing: global options ────────────────────────────────

    #[test]
    fn test_cli_default_set_name() {
        let cli = Cli::parse_from(["banip", "state"]);
        assert_eq!(cli.set, SET_NAME);
    }

    #[test]
    fn test_cli_custom_set_name() {
        let cli = Cli::parse_from(["banip", "-s", "my_whitelist", "state"]);
        assert_eq!(cli.set, "my_whitelist");
    }

    #[test]
    fn test_cli_custom_set_name_long() {
        let cli = Cli::parse_from(["banip", "--set", "custom_set", "state"]);
        assert_eq!(cli.set, "custom_set");
    }

    #[test]
    fn test_cli_default_dir() {
        let cli = Cli::parse_from(["banip", "state"]);
        assert_eq!(cli.dir, DATA_DIR);
    }

    #[test]
    fn test_cli_custom_dir() {
        let cli = Cli::parse_from(["banip", "-d", "/tmp/banip", "state"]);
        assert_eq!(cli.dir, "/tmp/banip");
    }

    #[test]
    fn test_cli_custom_dir_long() {
        let cli = Cli::parse_from(["banip", "--dir", "/opt/banip", "state"]);
        assert_eq!(cli.dir, "/opt/banip");
    }

    #[test]
    fn test_cli_update_with_custom_dir_and_set() {
        let cli = Cli::parse_from(["banip", "-s", "test", "-d", "/tmp/test", "update"]);
        assert_eq!(cli.set, "test");
        assert_eq!(cli.dir, "/tmp/test");
    }

    // ─── format_number ──────────────────────────────────────────────

    #[test]
    fn test_format_number_zero() {
        assert_eq!(format_number(0), "0");
    }

    #[test]
    fn test_format_number_small() {
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(99), "99");
        assert_eq!(format_number(999), "999");
    }

    #[test]
    fn test_format_number_kilo() {
        assert_eq!(format_number(1_000), "1.00K");
        assert_eq!(format_number(1_500), "1.50K");
        assert_eq!(format_number(999_999), "1000.00K");
    }

    #[test]
    fn test_format_number_mega() {
        assert_eq!(format_number(1_000_000), "1.00M");
        assert_eq!(format_number(50_000_000), "50.00M");
        assert_eq!(format_number(999_999_999), "1000.00M");
    }

    #[test]
    fn test_format_number_giga() {
        assert_eq!(format_number(1_000_000_000), "1.00B");
        assert_eq!(format_number(4_294_967_296), "4.29B"); // Total IPv4
    }

    // ─── constants ──────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(SET_NAME, "banip");
        assert_eq!(DATA_DIR, "/var/lib/banip");
        assert_eq!(CIDR_FILE, "cn_ip_cidr.txt");
    }

    // ─── integration: update logic with cidr + state ────────────────

    #[test]
    fn test_update_logic_parse_and_save() {
        // Simulate what cmd_update does with CIDR data
        let mock_cidr_content = "1.0.1.0/24\n1.0.2.0/23\n10.0.0.0/8\n";
        let cidrs = cidr::parse_cidr_list(mock_cidr_content);
        assert_eq!(cidrs.len(), 3);

        let total_ips: u64 = cidrs.iter().map(|c| c.hosts().count() as u64).sum();
        assert!(total_ips > 0);

        // Verify format_number works with the count
        let formatted = format_number(cidrs.len() as u64);
        assert!(!formatted.is_empty());
    }

    #[test]
    fn test_update_logic_download_validate_flow() {
        // Verify download module validates content correctly
        let mock_content = "1.0.1.0/24\n1.0.2.0/23\n# comment\n\n";
        let valid_count = download::validate_cidr_content(mock_content);
        assert_eq!(valid_count, 2);

        let cidrs = cidr::parse_cidr_list(mock_content);
        assert_eq!(cidrs.len(), 2);
    }
}
