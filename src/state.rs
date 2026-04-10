use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const STATE_FILE: &str = "state.toml";

/// Persistent state for banip.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct BanipState {
    /// Whether the ban is currently enabled (rules inserted)
    pub enabled: bool,
    /// Timestamp of last update
    pub updated_at: String,
    /// Number of CIDR entries loaded
    pub cidr_count: usize,
    /// ipset set name
    pub set_name: String,
}

/// Save state to data_dir/state.toml
pub fn save(data_dir: &str, state: &BanipState) {
    let path = Path::new(data_dir).join(STATE_FILE);
    let toml_str = toml::to_string_pretty(state).unwrap_or_default();
    if let Err(e) = fs::write(&path, &toml_str) {
        eprintln!("Warning: could not save state: {}", e);
    }
}

/// Load state from data_dir/state.toml
pub fn load(data_dir: &str) -> Option<BanipState> {
    let path = Path::new(data_dir).join(STATE_FILE);
    let content = fs::read_to_string(&path).ok()?;
    toml::from_str(&content).ok()
}
