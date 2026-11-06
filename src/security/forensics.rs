use std::fmt;
use serde::{Deserialize, Serialize};
use crate::arch::types::TargetArch;
use crate::security::violations::SecurityViolation;

/// Forensic report generated when the AegisVM sandbox finishes or aborts execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxForensicReport {
    pub arch: TargetArch,
    pub binary_sha256: String,
    pub is_packed: bool,
    pub static_instructions_verified: usize,
    pub dynamic_ram_pages_verified: usize,
    pub virtual_clock_fast_forwarded_secs: u64,
    pub cow_files_modified: Vec<String>,
    pub captured_network_flows: Vec<String>,
    pub cumulative_risk_score: u32,
    pub max_risk_threshold: u32,
    pub verdict: Result<String, SecurityViolation>,
    pub ed25519_signature: Option<String>,
}

impl SandboxForensicReport {
    pub fn is_clean(&self) -> bool {
        self.verdict.is_ok()
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn print_summary(&self) {
        println!("╔═══════════════════════════════════════════════════════════════════════╗");
        println!("║                      AEGIS-VM FORENSIC DOSSIER                        ║");
        println!("╠═══════════════════════════════════════════════════════════════════════╣");
        println!("║ Architecture: {:<55} ║", format!("{:?}", self.arch));
        println!("║ SHA-256:      {:<55} ║", self.binary_sha256);
        println!("║ Packed/High-Entropy: {:<48} ║", if self.is_packed { "YES (Strict Unpacking Active)" } else { "NO (Clean Header)" });
        println!("║ Static Instructions Audited: {:<40} ║", self.static_instructions_verified);
        println!("║ Dynamic RAM Pages Introspected: {:<37} ║", self.dynamic_ram_pages_verified);
        println!("║ Virtual Clock Fast-Forward:     {:<37} ║", format!("+{} seconds (Time-Bomb Defused)", self.virtual_clock_fast_forwarded_secs));
        println!("║ Ephemeral CoW Writes:           {:<37} ║", format!("{} modified files (0 on host)", self.cow_files_modified.len()));
        println!("║ Network Sinks Intercepted:      {:<37} ║", format!("{} flows recorded", self.captured_network_flows.len()));
        println!("║ Cumulative Risk Score:          {:<37} ║", format!("{}/{} max threshold", self.cumulative_risk_score, self.max_risk_threshold));
        println!("╠═══════════════════════════════════════════════════════════════════════╣");

        match &self.verdict {
            Ok(msg) => {
                println!("║ VERDICT:  [PASS] VERIFIED SECURE & APPROVED                           ║");
                println!("║ Details:  {:<59} ║", msg);
                if let Some(sig) = &self.ed25519_signature {
                    let sig_display = if sig.len() > 50 { &sig[..50] } else { sig };
                    println!("║ Ed25519 Signature: {:<50} ║", format!("{}...", sig_display));
                }
            }
            Err(violation) => {
                println!("║ VERDICT:  [FAIL] 🛑 DROP & QUARANTINE                                  ║");
                println!("║ Violation: {:<58} ║", format!("{}", violation));
            }
        }
        println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    }
}

impl fmt::Display for SandboxForensicReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AegisVM Report [Arch: {:?}, Clean: {}, Risk: {}/{}, SHA256: {}]",
            self.arch,
            self.is_clean(),
            self.cumulative_risk_score,
            self.max_risk_threshold,
            self.binary_sha256
        )
    }
}
