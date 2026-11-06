use std::collections::HashSet;
use serde::{Deserialize, Serialize};

/// Policy rules governing sandbox execution boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub allow_raw_syscalls_in_unbacked_ram: bool,
    pub max_cumulative_risk_score: u32,
    pub canary_honeypot_paths: HashSet<String>,
    pub allowed_outbound_ips: HashSet<String>,
    pub ransomware_entropy_threshold: f64,
    pub ransomware_burst_write_limit: usize,
    pub enforce_strict_w_xor_x: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        let mut canaries = HashSet::new();
        // Cross-platform canary honeypots
        // Linux:
        canaries.insert("/root/.ssh/id_rsa".to_string());
        canaries.insert("/etc/shadow".to_string());
        canaries.insert("/etc/passwd".to_string());
        // macOS:
        canaries.insert("/Users/admin/Library/Keychains/login.keychain-db".to_string());
        canaries.insert("/var/db/dslocal/nodes/Default/users".to_string());
        // Windows:
        canaries.insert("C:\\Windows\\System32\\config\\SAM".to_string());
        canaries.insert("C:\\Users\\Admin\\.ssh\\id_rsa".to_string());

        Self {
            allow_raw_syscalls_in_unbacked_ram: false,
            max_cumulative_risk_score: 70,
            canary_honeypot_paths: canaries,
            allowed_outbound_ips: HashSet::new(), // Zero trust: block all external IPs by default
            ransomware_entropy_threshold: 7.4,
            ransomware_burst_write_limit: 3,
            enforce_strict_w_xor_x: true,
        }
    }
}
