use std::sync::Arc;

use crate::arch::{Arm64Disassembler, X86_64Disassembler};
use crate::sandbox::engine::{AegisUnifiedSandbox, SandboxRuntimeEvent};
use crate::sandbox::policy::SandboxPolicy;
use crate::security::forensics::SandboxForensicReport;
use crate::static_analysis::gatekeeper::StaticGatekeeper;

pub struct DemoRunner;

impl DemoRunner {
    /// Scenario 1: Clean ARM64 Binary Executing in Sandbox (Passes & receives Ed25519 signature)
    pub fn run_scenario_clean_arm64() -> SandboxForensicReport {
        println!("\n▶ Running Scenario 1: Clean ARM64 Binary (Apple Silicon / KVM)");
        let arm_disasm = Arc::new(Arm64Disassembler::default());
        let mut sandbox = AegisUnifiedSandbox::new(arm_disasm, SandboxPolicy::default());

        // Valid ARM64 instructions: `paciasp` (0xD503233F) followed by `nop` (0xD503201F) and `ret` (0xD65F03C0)
        let clean_arm64_text: Vec<u8> = vec![
            0x3F, 0x23, 0x03, 0xD5, // paciasp (Pointer Authentication Code)
            0x1F, 0x20, 0x03, 0xD5, // nop
            0xC0, 0x03, 0x5F, 0xD6, // ret
            0x1F, 0x20, 0x03, 0xD5, // nop
        ];

        let baseline = StaticGatekeeper::audit_binary(&clean_arm64_text, Some(crate::arch::types::TargetArch::AArch64), false)
            .expect("Stage 1 static analysis must pass clean ARM64 code");

        let runtime_events = vec![
            SandboxRuntimeEvent::Stage2MemoryExecuteTrap {
                gpa_or_ipa: 0x1000_0000,
                live_page_bytes: clean_arm64_text.clone(),
            },
            SandboxRuntimeEvent::FileSystemActivity {
                pid: 101,
                path: "/tmp/app_cache.json".to_string(),
                is_write: true,
                written_bytes: b"{\"status\": \"ok\", \"healthy\": true}".to_vec(),
            },
        ];

        sandbox.detonate_in_sandbox(&baseline, runtime_events)
    }

    /// Scenario 2: Evasive ARM64 Malware (Time-Bomb + Cache Flush Shellcode)
    pub fn run_scenario_evasive_arm64_shellcode() -> SandboxForensicReport {
        println!("\n▶ Running Scenario 2: Evasive ARM64 Malware (Sleep Stalling + Cache Flush Shellcode)");
        let arm_disasm = Arc::new(Arm64Disassembler::default());
        let mut sandbox = AegisUnifiedSandbox::new(arm_disasm, SandboxPolicy::default());

        let clean_arm64_text: Vec<u8> = vec![
            0x3F, 0x23, 0x03, 0xD5, // paciasp
            0x1F, 0x20, 0x03, 0xD5, // nop
            0xC0, 0x03, 0x5F, 0xD6, // ret
            0x1F, 0x20, 0x03, 0xD5, // nop
        ];

        let baseline = StaticGatekeeper::audit_binary(&clean_arm64_text, Some(crate::arch::types::TargetArch::AArch64), false)
            .expect("Stage 1 static analysis baseline created");

        // Malware sleeps 3600s to outwait sandbox, then flushes cache on unpacked `svc #0` shellcode
        let evasive_events = vec![
            SandboxRuntimeEvent::GuestSleepStallDetected { requested_seconds: 3600 },
            SandboxRuntimeEvent::ArmCacheMaintenanceTrap {
                ipa: 0x3F00_0000, // Unbacked anonymous RAM region
                unpacked_bytes: vec![0x01, 0x00, 0x00, 0xD4], // `svc #0` raw syscall shellcode
            },
        ];

        sandbox.detonate_in_sandbox(&baseline, evasive_events)
    }

    /// Scenario 3: x86_64 Stealth Behavioral Attack (Clean Opcodes, Canary Honeypot Theft)
    pub fn run_scenario_x86_canary_theft() -> SandboxForensicReport {
        println!("\n▶ Running Scenario 3: x86_64 Behavioral Attack (Legitimate Opcodes + Canary Honeypot Theft)");
        let x86_disasm = Arc::new(X86_64Disassembler);
        let mut sandbox = AegisUnifiedSandbox::new(x86_disasm, SandboxPolicy::default());

        // Valid x86_64: `endbr64` (F3 0F 1E FA) + `nop` (90) + `ret` (C3)
        let clean_x86_text = vec![0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0xC3];

        let baseline = StaticGatekeeper::audit_binary(&clean_x86_text, Some(crate::arch::types::TargetArch::X86_64), false)
            .expect("Stage 1 static analysis must pass clean x86 code");

        let events = vec![
            SandboxRuntimeEvent::Stage2MemoryExecuteTrap {
                gpa_or_ipa: 0x1000_0000,
                live_page_bytes: clean_x86_text.clone(),
            },
            // Malware uses legitimate syscall wrappers to read credential canary
            SandboxRuntimeEvent::FileSystemActivity {
                pid: 204,
                path: "/root/.ssh/id_rsa".to_string(),
                is_write: false,
                written_bytes: Vec::new(),
            },
        ];

        sandbox.detonate_in_sandbox(&baseline, events)
    }

    /// Scenario 4: Cross-Platform Ransomware Mass Encryption Burst
    pub fn run_scenario_ransomware_mass_encryption() -> SandboxForensicReport {
        println!("\n▶ Running Scenario 4: Ransomware Burst Encryption (High-Entropy File Overwrite)");
        let x86_disasm = Arc::new(X86_64Disassembler);
        let mut sandbox = AegisUnifiedSandbox::new(x86_disasm, SandboxPolicy::default());

        let clean_x86_text = vec![0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0xC3];
        let baseline = StaticGatekeeper::audit_binary(&clean_x86_text, Some(crate::arch::types::TargetArch::X86_64), false)
            .unwrap();

        // High entropy encrypted buffer (AES / ChaCha20 simulation)
        let mut high_entropy_buf = Vec::with_capacity(1024);
        for i in 0..1024 {
            high_entropy_buf.push((i % 256) as u8);
        }

        let events = vec![
            SandboxRuntimeEvent::FileSystemActivity {
                pid: 400,
                path: "/home/user/documents/finance.xlsx".to_string(),
                is_write: true,
                written_bytes: high_entropy_buf.clone(),
            },
            SandboxRuntimeEvent::FileSystemActivity {
                pid: 400,
                path: "/home/user/documents/taxes.pdf".to_string(),
                is_write: true,
                written_bytes: high_entropy_buf.clone(),
            },
            SandboxRuntimeEvent::FileSystemActivity {
                pid: 400,
                path: "/home/user/documents/database.sqlite".to_string(),
                is_write: true,
                written_bytes: high_entropy_buf,
            },
        ];

        sandbox.detonate_in_sandbox(&baseline, events)
    }

    /// Scenario 5: Dynamic RAM Inline Trampoline Hook (Memory patching after disk load)
    pub fn run_scenario_inline_trampoline_hook() -> SandboxForensicReport {
        println!("\n▶ Running Scenario 5: Live RAM Inline Trampoline Hook (5-Byte JMP Patch)");
        let x86_disasm = Arc::new(X86_64Disassembler);
        let mut sandbox = AegisUnifiedSandbox::new(x86_disasm, SandboxPolicy::default());

        // Original disk text: 6 NOPs followed by RET
        let disk_text = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3];
        let baseline = StaticGatekeeper::audit_binary(&disk_text, Some(crate::arch::types::TargetArch::X86_64), false)
            .unwrap();

        // Live RAM: Patched with 5-byte JMP rel32 (0xE9 0x00 0x10 0x00 0x00)
        let live_patched_text = vec![0xE9, 0x00, 0x10, 0x00, 0x00, 0x90, 0xC3];

        let events = vec![SandboxRuntimeEvent::Stage2MemoryExecuteTrap {
            gpa_or_ipa: 0x1000_0000,
            live_page_bytes: live_patched_text,
        }];

        sandbox.detonate_in_sandbox(&baseline, events)
    }
}
