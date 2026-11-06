use std::fmt;
use serde::{Deserialize, Serialize};

/// Target processor architecture supported by AegisVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetArch {
    X86_64,
    AArch64,
}

impl fmt::Display for TargetArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetArch::X86_64 => write!(f, "x86_64"),
            TargetArch::AArch64 => write!(f, "AArch64 (ARM64)"),
        }
    }
}

/// Architecture-agnostic representation of a decoded CPU instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub raw_bytes: Vec<u8>,
    pub is_syscall: bool,           // `syscall`/`int 0x80` (x86) or `svc #0`/`hvc` (ARM64)
    pub is_vm_or_timer_probe: bool, // `cpuid`/`rdtsc` (x86) or `mrs midr_el1`/`cntvct_el0` (ARM64)
    pub is_cache_flush: bool,       // `dc cvau` / `ic ivau` (ARM64 self-modifying code signal)
    pub is_cfi_landing_pad: bool,   // `endbr64` (x86 CET) or `paciasp`/`bti c` (ARM64 PAC/BTI)
    pub is_branch: bool,            // JMP/CALL/RET (x86) or B/BL/BR/BLR/RET (ARM64)
    pub branch_target: Option<u64>, // Target address if statically resolvable
}

/// Snapshot created during Stage 1 to verify RAM integrity during Stage 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticBaseline {
    pub arch: TargetArch,
    pub is_packed_or_high_entropy: bool,
    pub section_entropy: f64,
    /// Maps Guest Physical/Intermediate Address -> Original Disk `.text` Opcode Bytes
    pub code_page_baselines: std::collections::HashMap<u64, Vec<u8>>,
    pub total_instructions_audited: usize,
    pub cfg_node_count: usize,
    pub cfg_edge_count: usize,
    pub cfi_landing_pads_found: usize,
    pub entry_point: u64,
    pub binary_sha256: String,
}
