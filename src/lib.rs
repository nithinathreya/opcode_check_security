//! # AegisVM: Unified Rust Opcode Verifier & Behavioral MicroVM Sandbox
//!
//! A zero-trust binary verification and behavioral sandboxing engine supporting
//! **x86_64** and **ARM64 (AArch64 / Apple Silicon)** binaries running across
//! Linux, macOS, and Windows.
//!
//! ## Architecture Pipeline
//! 1. **Stage 1**: Multi-Arch Static Opcode & Control-Flow Gatekeeper
//!    - Universal binary parsing (`goblin` ELF, PE, Mach-O, Fat Fat Mach-O)
//!    - Section Shannon entropy analysis (packer & encrypted payload detection)
//!    - Full instruction decoding (`iced-x86` for x86_64, `bad64` & native decoder for ARM64)
//!    - Control Flow Graph (CFG) construction (`petgraph`)
//!    - PAC / BTI CFI landing pad verification
//!    - Immutable disk `.text` baseline generation
//! 2. **Stage 2**: Integrated Rust MicroVM & Behavioral Sandbox Environment
//!    - Guest physical RAM allocation with $W \oplus X$ EPT / Stage-2 MMU page tracking
//!    - Ephemeral Copy-on-Write (CoW) overlay filesystem
//!    - Honey-pot credential tripwires (`id_rsa`, `shadow`, Keychain, SAM)
//!    - Virtual TAP NIC sinkhole and PCAP packet recorder
//!    - Anti-evasion hardware spoofing (CPUID, SMBIOS, MIDR_EL1)
//! 3. **Stage 3**: Unified Runtime Loop (RAM Opcode Introspection + Behavioral Scoring)
//!    - Dynamic RAM diffing against disk baseline (inline trampoline hooks, ROP gadgets)
//!    - Disassembly and auditing of unbacked executable RAM (shellcode detection)
//!    - Fast-forwarding virtual clock to defuse time-bomb stalling evasions
//!    - Behavioral anomaly evaluation (ransomware entropy bursts, process injection, C2 flows)
//!    - Ed25519 cryptographic signing for verified-clean binaries

pub mod arch;
pub mod demo;
pub mod sandbox;
pub mod security;
pub mod static_analysis;

pub use arch::types::{NormalizedInstruction, StaticBaseline, TargetArch};
pub use arch::{ArchDisassembler, Arm64Disassembler, X86_64Disassembler};
pub use demo::DemoRunner;
pub use sandbox::engine::{AegisUnifiedSandbox, SandboxRuntimeEvent};
pub use sandbox::policy::SandboxPolicy;
pub use security::forensics::SandboxForensicReport;
pub use security::signer::AegisSigner;
pub use security::violations::SecurityViolation;
pub use static_analysis::gatekeeper::StaticGatekeeper;
use sha2::Digest;

/// High-level convenience function: run complete Stage 1 static audit on a binary.
pub fn static_audit(
    binary_bytes: &[u8],
    forced_arch: Option<TargetArch>,
    strict_syscall_check: bool,
) -> Result<StaticBaseline, SecurityViolation> {
    StaticGatekeeper::audit_binary(binary_bytes, forced_arch, strict_syscall_check)
}

/// High-level convenience function: run Stage 1 audit and detonate in Stage 2/3 sandbox.
pub fn verify_and_detonate(
    binary_bytes: &[u8],
    forced_arch: Option<TargetArch>,
    policy: Option<SandboxPolicy>,
    runtime_events: Vec<SandboxRuntimeEvent>,
) -> SandboxForensicReport {
    let p = policy.unwrap_or_default();
    match StaticGatekeeper::audit_binary(binary_bytes, forced_arch, false) {
        Ok(baseline) => {
            let disasm: std::sync::Arc<dyn ArchDisassembler> = match baseline.arch {
                TargetArch::X86_64 => std::sync::Arc::new(X86_64Disassembler),
                TargetArch::AArch64 => std::sync::Arc::new(Arm64Disassembler::default()),
            };
            let mut sandbox = AegisUnifiedSandbox::new(disasm, p);
            sandbox.detonate_in_sandbox(&baseline, runtime_events)
        }
        Err(violation) => {
            let arch = forced_arch.unwrap_or(TargetArch::X86_64);
            SandboxForensicReport {
                arch,
                binary_sha256: format!("{:x}", sha2::Sha256::digest(binary_bytes)),
                is_packed: false,
                static_instructions_verified: 0,
                dynamic_ram_pages_verified: 0,
                virtual_clock_fast_forwarded_secs: 0,
                cow_files_modified: Vec::new(),
                captured_network_flows: Vec::new(),
                cumulative_risk_score: 100,
                max_risk_threshold: p.max_cumulative_risk_score,
                verdict: Err(violation),
                ed25519_signature: None,
            }
        }
    }
}
