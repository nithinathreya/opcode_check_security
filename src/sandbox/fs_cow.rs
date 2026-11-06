use std::collections::{HashMap, HashSet};
use crate::sandbox::policy::SandboxPolicy;
use crate::security::violations::SecurityViolation;
use crate::static_analysis::entropy::shannon_entropy;

/// Ephemeral Copy-on-Write (CoW) In-Memory Filesystem with Canary Honeypot Tripwires.
pub struct CowFilesystem {
    pub overlay: HashMap<String, Vec<u8>>,
    pub high_entropy_write_count: usize,
    pub canaries: HashSet<String>,
}

impl CowFilesystem {
    pub fn new(canary_paths: HashSet<String>) -> Self {
        Self {
            overlay: HashMap::new(),
            high_entropy_write_count: 0,
            canaries: canary_paths,
        }
    }

    /// Normalize paths across Windows backslashes and Unix slashes.
    fn normalize_path(path: &str) -> String {
        path.replace('\\', "/").to_lowercase()
    }

    /// Check if a path touches a canary honeypot tripwire.
    fn is_canary(&self, target_path: &str) -> bool {
        let norm_target = Self::normalize_path(target_path);
        for canary in &self.canaries {
            let norm_canary = Self::normalize_path(canary);
            if norm_target == norm_canary || norm_target.ends_with(&norm_canary) || norm_canary.ends_with(&norm_target) {
                return true;
            }
        }
        false
    }

    /// Intercept a file operation inside the sandboxed guest.
    pub fn handle_file_access(
        &mut self,
        pid: u32,
        path: &str,
        is_write: bool,
        data: &[u8],
        policy: &SandboxPolicy,
    ) -> Result<(), SecurityViolation> {
        // 1. Check Canary Honeypot Tripwires
        if self.is_canary(path) {
            return Err(SecurityViolation::CanaryHoneypotTouched {
                path: path.to_string(),
                pid,
                access_type: if is_write { "WRITE".into() } else { "READ".into() },
            });
        }

        // 2. Commit file writes to memory overlay and test for Ransomware encryption bursts
        if is_write {
            let write_entropy = shannon_entropy(data);
            self.overlay.insert(path.to_string(), data.to_vec());

            if write_entropy >= policy.ransomware_entropy_threshold {
                self.high_entropy_write_count += 1;
                if self.high_entropy_write_count >= policy.ransomware_burst_write_limit {
                    return Err(SecurityViolation::RansomwareMassEncryption {
                        path: path.to_string(),
                        write_entropy,
                        files_modified: self.high_entropy_write_count,
                    });
                }
            }
        }

        Ok(())
    }

    /// List of all files modified in the ephemeral overlay during execution.
    pub fn modified_files(&self) -> Vec<String> {
        self.overlay.keys().cloned().collect()
    }
}
