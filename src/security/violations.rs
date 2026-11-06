use std::fmt;
use serde::{Deserialize, Serialize};
use crate::arch::types::TargetArch;

/// Security violations caught by the AegisVM verification engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityViolation {
    // ------------------------------------------------------------------------
    // STAGE 1: Static Opcode & Header Violations
    // ------------------------------------------------------------------------
    #[serde(rename = "unaligned_arm_instruction")]
    UnalignedArmInstruction { address: u64 },

    #[serde(rename = "forbidden_static_opcode")]
    ForbiddenStaticOpcode {
        arch: TargetArch,
        address: u64,
        mnemonic: String,
        reason: String,
    },

    #[serde(rename = "missing_arm_pac_or_bti")]
    MissingArmPacOrBtiLandingPad { function_addr: u64 },

    #[serde(rename = "suspicious_entropy_packed")]
    SuspiciousEntropyOrMissingText {
        section_name: String,
        entropy: f64,
    },

    #[serde(rename = "signature_rule_hit")]
    SignatureRuleHit {
        rule_name: String,
        description: String,
    },

    // ------------------------------------------------------------------------
    // STAGE 3A: Dynamic RAM Opcode Violations (Hypervisor Traps)
    // ------------------------------------------------------------------------
    #[serde(rename = "inline_hook_detected")]
    InlineHookDetected {
        gpa_or_ipa: u64,
        expected: Vec<u8>,
        actual: Vec<u8>,
        hook_type: String,
    },

    #[serde(rename = "unbacked_executable_shellcode")]
    UnbackedExecutableShellcode {
        gpa_or_ipa: u64,
        opcode_summary: String,
    },

    #[serde(rename = "self_modifying_code_violation")]
    SelfModifyingCodeViolation {
        gpa_or_ipa: u64,
        reason: String,
    },

    #[serde(rename = "ept_wx_violation")]
    EptWriteExecuteViolation {
        gpa_or_ipa: u64,
        attempted_access: String,
    },

    #[serde(rename = "hardware_cfi_violation")]
    HardwareCfiViolation {
        pc: u64,
        mechanism: String,
    },

    // ------------------------------------------------------------------------
    // STAGE 3B: Behavioral Sandbox Violations (Kernel / Telemetry Probes)
    // ------------------------------------------------------------------------
    #[serde(rename = "canary_honeypot_touched")]
    CanaryHoneypotTouched {
        path: String,
        pid: u32,
        access_type: String,
    },

    #[serde(rename = "ransomware_mass_encryption")]
    RansomwareMassEncryption {
        path: String,
        write_entropy: f64,
        files_modified: usize,
    },

    #[serde(rename = "process_hollowing_or_injection")]
    ProcessHollowingOrInjection {
        source_pid: u32,
        target_pid: u32,
        api: String,
    },

    #[serde(rename = "unauthorized_network_exfiltration")]
    UnauthorizedNetworkExfiltration {
        dst_ip: String,
        dst_port: u16,
        protocol: String,
    },

    #[serde(rename = "cumulative_risk_threshold_exceeded")]
    CumulativeRiskThresholdExceeded {
        score: u32,
        max_allowed: u32,
    },
}

impl SecurityViolation {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::UnalignedArmInstruction { .. }
            | Self::ForbiddenStaticOpcode { .. }
            | Self::MissingArmPacOrBtiLandingPad { .. }
            | Self::SuspiciousEntropyOrMissingText { .. }
            | Self::SignatureRuleHit { .. } => 10,

            Self::InlineHookDetected { .. }
            | Self::UnbackedExecutableShellcode { .. }
            | Self::SelfModifyingCodeViolation { .. }
            | Self::EptWriteExecuteViolation { .. }
            | Self::HardwareCfiViolation { .. } => 20,

            Self::CanaryHoneypotTouched { .. }
            | Self::RansomwareMassEncryption { .. }
            | Self::ProcessHollowingOrInjection { .. }
            | Self::UnauthorizedNetworkExfiltration { .. } => 30,

            Self::CumulativeRiskThresholdExceeded { .. } => 40,
        }
    }
}

impl fmt::Display for SecurityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityViolation::UnalignedArmInstruction { address } => {
                write!(f, "Unaligned ARM64 instruction fetch at 0x{:016X} (must be 4-byte aligned)", address)
            }
            SecurityViolation::ForbiddenStaticOpcode { arch, address, mnemonic, reason } => {
                write!(f, "Forbidden static opcode on {:?} at 0x{:016X}: '{}' ({})", arch, address, mnemonic, reason)
            }
            SecurityViolation::MissingArmPacOrBtiLandingPad { function_addr } => {
                write!(f, "Missing ARM64 PAC/BTI landing pad (PACIASP or BTI C) at function entry 0x{:016X}", function_addr)
            }
            SecurityViolation::SuspiciousEntropyOrMissingText { section_name, entropy } => {
                write!(f, "Suspicious section '{}' with high Shannon entropy {:.2} > 7.2 (packed/encrypted)", section_name, entropy)
            }
            SecurityViolation::SignatureRuleHit { rule_name, description } => {
                write!(f, "Security signature rule matched: '{}' - {}", rule_name, description)
            }
            SecurityViolation::InlineHookDetected { gpa_or_ipa, hook_type, .. } => {
                write!(f, "Live RAM inline trampoline hook detected at GPA 0x{:016X} (type: {})", gpa_or_ipa, hook_type)
            }
            SecurityViolation::UnbackedExecutableShellcode { gpa_or_ipa, opcode_summary } => {
                write!(f, "Unbacked executable shellcode in anonymous RAM at GPA 0x{:016X}: {}", gpa_or_ipa, opcode_summary)
            }
            SecurityViolation::SelfModifyingCodeViolation { gpa_or_ipa, reason } => {
                write!(f, "Self-modifying code trap at GPA 0x{:016X}: {}", gpa_or_ipa, reason)
            }
            SecurityViolation::EptWriteExecuteViolation { gpa_or_ipa, attempted_access } => {
                write!(f, "EPT/Stage-2 W^X policy violation at GPA 0x{:016X}: {}", gpa_or_ipa, attempted_access)
            }
            SecurityViolation::HardwareCfiViolation { pc, mechanism } => {
                write!(f, "Hardware Control Flow Integrity violation at PC 0x{:016X} via {}", pc, mechanism)
            }
            SecurityViolation::CanaryHoneypotTouched { path, pid, access_type } => {
                write!(f, "Canary Honeypot tripped! PID {} attempted {} on '{}'", pid, access_type, path)
            }
            SecurityViolation::RansomwareMassEncryption { path, write_entropy, files_modified } => {
                write!(f, "Ransomware burst encryption detected: modified {} files; '{}' entropy is {:.2}", files_modified, path, write_entropy)
            }
            SecurityViolation::ProcessHollowingOrInjection { source_pid, target_pid, api } => {
                write!(f, "Process injection/hollowing detected: PID {} injected into PID {} via '{}'", source_pid, target_pid, api)
            }
            SecurityViolation::UnauthorizedNetworkExfiltration { dst_ip, dst_port, protocol } => {
                write!(f, "Unauthorized C2 network exfiltration to {}:{} ({})", dst_ip, dst_port, protocol)
            }
            SecurityViolation::CumulativeRiskThresholdExceeded { score, max_allowed } => {
                write!(f, "Cumulative security risk score {} exceeded maximum threshold {}", score, max_allowed)
            }
        }
    }
}

impl std::error::Error for SecurityViolation {}
