use std::sync::Arc;

use crate::arch::types::StaticBaseline;
use crate::arch::ArchDisassembler;
use crate::sandbox::anti_evasion::AntiEvasionEngine;
use crate::sandbox::fs_cow::CowFilesystem;
use crate::sandbox::memory::{GuestMemory, PagePermissions};
use crate::sandbox::network::VirtualTapNetwork;
use crate::sandbox::policy::SandboxPolicy;
use crate::sandbox::verifier::RamOpcodeVerifier;
use crate::security::forensics::SandboxForensicReport;
use crate::security::scoring::RiskScorer;
use crate::security::signer::AegisSigner;
use crate::security::violations::SecurityViolation;

/// Events emitted by the MicroVM Hypervisor (KVM, Applevisor, WHP, or Emulation) and Guest Sensors.
#[derive(Debug, Clone)]
pub enum SandboxRuntimeEvent {
    /// Hypervisor trapped an instruction fetch on newly written or unbacked RAM (EPT / Stage-2 Fault)
    Stage2MemoryExecuteTrap { gpa_or_ipa: u64, live_page_bytes: Vec<u8> },
    /// ARM64-Specific: Hypervisor trapped `DC CVAU` / `IC IVAU` cache maintenance (`HCR_EL2.TPU`)
    ArmCacheMaintenanceTrap { ipa: u64, unpacked_bytes: Vec<u8> },
    /// Hypervisor trapped an anti-VM or timer probe (`CPUID`, `RDTSC`, `MRS CNTVCT_EL0`)
    AntiAnalysisInstructionTrap { instruction: String },
    /// Intercepted sleep stall attempt (`nanosleep`, `clock_nanosleep`, `Sleep`)
    GuestSleepStallDetected { requested_seconds: u64 },
    /// VFS probe intercepted file operation inside ephemeral CoW overlay
    FileSystemActivity { pid: u32, path: String, is_write: bool, written_bytes: Vec<u8> },
    /// Task probe intercepted process creation or cross-process memory tampering
    ProcessActivity { source_pid: u32, target_pid: u32, syscall: String },
    /// Virtual TAP NIC intercepted outbound network packet
    NetworkActivity { pid: u32, dst_ip: String, dst_port: u16, protocol: String, payload_preview: Vec<u8> },
}

/// Unified AegisVM Behavioral Sandbox and Dynamic RAM Opcode Verification Engine.
pub struct AegisUnifiedSandbox {
    pub policy: SandboxPolicy,
    pub memory: GuestMemory,
    pub fs_cow: CowFilesystem,
    pub network: VirtualTapNetwork,
    pub anti_evasion: AntiEvasionEngine,
    pub verifier: RamOpcodeVerifier,
    pub scorer: RiskScorer,
    pub signer: AegisSigner,
    pub verified_ram_pages: usize,
}

impl AegisUnifiedSandbox {
    /// Initialize a new sandbox instance configured with architecture-specific disassembler and policy.
    pub fn new(disassembler: Arc<dyn ArchDisassembler>, policy: SandboxPolicy) -> Self {
        let page_size = disassembler.page_size();
        let max_score = policy.max_cumulative_risk_score;
        let canaries = policy.canary_honeypot_paths.clone();

        Self {
            policy,
            memory: GuestMemory::new(page_size),
            fs_cow: CowFilesystem::new(canaries),
            network: VirtualTapNetwork::new(),
            anti_evasion: AntiEvasionEngine::new(),
            verifier: RamOpcodeVerifier::new(disassembler),
            scorer: RiskScorer::new(max_score),
            signer: AegisSigner::generate(),
            verified_ram_pages: 0,
        }
    }

    /// Provision initial guest memory regions with disk baseline pages.
    pub fn provision_from_baseline(&mut self, baseline: &StaticBaseline) {
        for (&addr, bytes) in &baseline.code_page_baselines {
            self.memory.map_region(addr, bytes.len(), Some(bytes), PagePermissions::rx());
        }
    }

    /// Detonate and monitor untrusted binary execution inside the MicroVM event loop.
    pub fn detonate_in_sandbox(
        &mut self,
        baseline: &StaticBaseline,
        runtime_events: Vec<SandboxRuntimeEvent>,
    ) -> SandboxForensicReport {
        self.provision_from_baseline(baseline);

        for event in runtime_events {
            if let Err(violation) = self.process_runtime_event(baseline, event) {
                return self.build_report(baseline, Err(violation));
            }

            if self.scorer.is_breached() {
                return self.build_report(
                    baseline,
                    Err(SecurityViolation::CumulativeRiskThresholdExceeded {
                        score: self.scorer.cumulative_score,
                        max_allowed: self.scorer.max_allowed_score,
                    }),
                );
            }
        }

        self.build_report(
            baseline,
            Ok("Binary passed Static Opcode Gatekeeper, Dynamic RAM Introspection, and Behavioral Sandboxing.".to_string()),
        )
    }

    /// Dispatch and process an individual runtime event.
    pub fn process_runtime_event(
        &mut self,
        baseline: &StaticBaseline,
        event: SandboxRuntimeEvent,
    ) -> Result<(), SecurityViolation> {
        match event {
            // ----------------------------------------------------------------
            // PILLAR A: DYNAMIC RAM OPCODE VERIFICATION & CACHE TRAPS
            // ----------------------------------------------------------------
            SandboxRuntimeEvent::Stage2MemoryExecuteTrap { gpa_or_ipa, live_page_bytes }
            | SandboxRuntimeEvent::ArmCacheMaintenanceTrap { ipa: gpa_or_ipa, unpacked_bytes: live_page_bytes } => {
                self.verified_ram_pages += 1;

                let is_unbacked = self.verifier.audit_live_page(
                    gpa_or_ipa,
                    &live_page_bytes,
                    baseline,
                    &mut self.memory,
                    &self.policy,
                )?;

                if is_unbacked {
                    // Allocating new executable code at runtime (e.g., JIT or unpacker) adds risk points
                    self.scorer.add_risk(20, "Unbacked executable memory allocated dynamically");
                }

                Ok(())
            }

            // ----------------------------------------------------------------
            // PILLAR B: ANTI-EVASION & VIRTUAL CLOCK FAST-FORWARDING
            // ----------------------------------------------------------------
            SandboxRuntimeEvent::AntiAnalysisInstructionTrap { instruction } => {
                let _spoofed = self.anti_evasion.handle_instruction_probe(&instruction);
                self.scorer.add_risk(10, &format!("Probed anti-VM / timer hardware: '{}'", instruction));
                Ok(())
            }

            SandboxRuntimeEvent::GuestSleepStallDetected { requested_seconds } => {
                self.anti_evasion.fast_forward_clock(requested_seconds);
                self.scorer.add_risk(15, &format!("Sleep stall detected: fast-forwarded +{}s", requested_seconds));
                Ok(())
            }

            // ----------------------------------------------------------------
            // PILLAR C: BEHAVIORAL SANDBOX ANALYSIS (FS, PROCESS, NETWORK)
            // ----------------------------------------------------------------
            SandboxRuntimeEvent::FileSystemActivity { pid, path, is_write, written_bytes } => {
                self.fs_cow.handle_file_access(pid, &path, is_write, &written_bytes, &self.policy)
            }

            SandboxRuntimeEvent::ProcessActivity { source_pid, target_pid, syscall } => {
                let syscall_lower = syscall.to_lowercase();
                if syscall_lower.contains("ptrace_poketext")
                    || syscall_lower.contains("process_vm_writev")
                    || syscall_lower.contains("memfd_create")
                    || syscall_lower.contains("createremotethread")
                    || syscall_lower.contains("writeprocessmemory")
                {
                    return Err(SecurityViolation::ProcessHollowingOrInjection {
                        source_pid,
                        target_pid,
                        api: syscall,
                    });
                }
                Ok(())
            }

            SandboxRuntimeEvent::NetworkActivity { pid, dst_ip, dst_port, protocol, payload_preview } => {
                self.network.handle_packet(pid, &dst_ip, dst_port, &protocol, &payload_preview, &self.policy)
            }
        }
    }

    /// Construct final forensic report and sign binary if safe.
    pub fn build_report(
        &self,
        baseline: &StaticBaseline,
        verdict: Result<String, SecurityViolation>,
    ) -> SandboxForensicReport {
        let is_clean = verdict.is_ok();
        let ed25519_signature = if is_clean {
            Some(self.signer.sign_hex(baseline.binary_sha256.as_bytes()))
        } else {
            None
        };

        SandboxForensicReport {
            arch: baseline.arch,
            binary_sha256: baseline.binary_sha256.clone(),
            is_packed: baseline.is_packed_or_high_entropy,
            static_instructions_verified: baseline.total_instructions_audited,
            dynamic_ram_pages_verified: self.verified_ram_pages,
            virtual_clock_fast_forwarded_secs: self.anti_evasion.virtual_clock_offset_secs,
            cow_files_modified: self.fs_cow.modified_files(),
            captured_network_flows: self.network.pcap_flows.clone(),
            cumulative_risk_score: self.scorer.cumulative_score,
            max_risk_threshold: self.scorer.max_allowed_score,
            verdict,
            ed25519_signature,
        }
    }
}
