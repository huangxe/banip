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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_temp_dir() -> String {
        // Use thread ID to avoid collisions between parallel tests
        let tid = std::thread::current().id();
        let dir = std::env::temp_dir().join(format!("banip_test_{:?}_{}", tid, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().to_string()
    }

    fn cleanup_temp_dir(dir: &str) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_save_and_load() {
        let dir = setup_temp_dir();
        let state = BanipState {
            enabled: true,
            updated_at: "2026-04-11 00:30:00".to_string(),
            cidr_count: 8200,
            set_name: "banip".to_string(),
        };
        save(&dir, &state);
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.enabled, true);
        assert_eq!(loaded.updated_at, "2026-04-11 00:30:00");
        assert_eq!(loaded.cidr_count, 8200);
        assert_eq!(loaded.set_name, "banip");
        cleanup_temp_dir(&dir);
    }

    #[test]
    fn test_load_nonexistent() {
        let dir = "/tmp/banip_nonexistent_test_dir_12345";
        assert!(load(dir).is_none());
    }

    #[test]
    fn test_save_disabled_state() {
        let dir = setup_temp_dir();
        let state = BanipState {
            enabled: false,
            updated_at: "".to_string(),
            cidr_count: 0,
            set_name: "".to_string(),
        };
        save(&dir, &state);
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.enabled, false);
        assert_eq!(loaded.updated_at, "");
        cleanup_temp_dir(&dir);
    }

    #[test]
    fn test_save_overwrite() {
        let dir = setup_temp_dir();
        let state1 = BanipState {
            enabled: true,
            updated_at: "2026-01-01 00:00:00".to_string(),
            cidr_count: 100,
            set_name: "banip".to_string(),
        };
        save(&dir, &state1);

        let state2 = BanipState {
            enabled: false,
            updated_at: "2026-04-11 00:00:00".to_string(),
            cidr_count: 200,
            set_name: "banip".to_string(),
        };
        save(&dir, &state2);

        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.enabled, false);
        assert_eq!(loaded.updated_at, "2026-04-11 00:00:00");
        assert_eq!(loaded.cidr_count, 200);
        cleanup_temp_dir(&dir);
    }

    #[test]
    fn test_save_creates_toml_file() {
        let dir = setup_temp_dir();
        let state = BanipState {
            enabled: true,
            updated_at: "2026-04-11 00:00:00".to_string(),
            cidr_count: 50,
            set_name: "myset".to_string(),
        };
        save(&dir, &state);
        let path = Path::new(&dir).join(STATE_FILE);
        assert!(path.exists());
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("enabled = true"));
        assert!(content.contains("myset"));
        cleanup_temp_dir(&dir);
    }

    #[test]
    fn test_default_state() {
        let state = BanipState::default();
        assert_eq!(state.enabled, false);
        assert_eq!(state.updated_at, "");
        assert_eq!(state.cidr_count, 0);
        assert_eq!(state.set_name, "");
    }

    #[test]
    fn test_state_file_name() {
        assert_eq!(STATE_FILE, "state.toml");
    }
}
