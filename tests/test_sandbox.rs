use std::sync::Arc;

use aegis_cli::arch::{Arm64Disassembler, X86_64Disassembler};
use aegis_cli::sandbox::engine::{AegisUnifiedSandbox, SandboxRuntimeEvent};
use aegis_cli::sandbox::policy::SandboxPolicy;
use aegis_cli::security::violations::SecurityViolation;
use aegis_cli::static_analysis::gatekeeper::StaticGatekeeper;
use aegis_cli::TargetArch;

#[test]
fn test_clean_arm64_sandbox_execution() {
    let arm_disasm = Arc::new(Arm64Disassembler::default());
    let mut sandbox = AegisUnifiedSandbox::new(arm_disasm, SandboxPolicy::default());

    let clean_arm64_text: Vec<u8> = vec![
        0x3F, 0x23, 0x03, 0xD5, // paciasp
        0x1F, 0x20, 0x03, 0xD5, // nop
        0xC0, 0x03, 0x5F, 0xD6, // ret
        0x1F, 0x20, 0x03, 0xD5, // nop
    ];

    let baseline = StaticGatekeeper::audit_binary(&clean_arm64_text, Some(TargetArch::AArch64), false)
        .expect("Baseline created");

    let benign_events = vec![
        SandboxRuntimeEvent::Stage2MemoryExecuteTrap {
            gpa_or_ipa: 0x1000_0000,
            live_page_bytes: clean_arm64_text.clone(),
        },
        SandboxRuntimeEvent::FileSystemActivity {
            pid: 100,
            path: "/tmp/benign_app.log".to_string(),
            is_write: true,
            written_bytes: b"App initialized normally".to_vec(),
        },
    ];

    let report = sandbox.detonate_in_sandbox(&baseline, benign_events);
    assert!(report.is_clean(), "Clean binary should pass sandbox verification");
    assert!(report.ed25519_signature.is_some(), "Clean binary must receive an Ed25519 signature");
    assert_eq!(report.virtual_clock_fast_forwarded_secs, 0);
}

#[test]
fn test_canary_honeypot_tripwire() {
    let x86_disasm = Arc::new(X86_64Disassembler);
    let mut sandbox = AegisUnifiedSandbox::new(x86_disasm, SandboxPolicy::default());

    let clean_code = vec![0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0xC3];
    let baseline = StaticGatekeeper::audit_binary(&clean_code, Some(TargetArch::X86_64), false).unwrap();

    let attack_events = vec![SandboxRuntimeEvent::FileSystemActivity {
        pid: 333,
        path: "/root/.ssh/id_rsa".to_string(),
        is_write: false,
        written_bytes: Vec::new(),
    }];

    let report = sandbox.detonate_in_sandbox(&baseline, attack_events);
    assert!(!report.is_clean());
    match report.verdict {
        Err(SecurityViolation::CanaryHoneypotTouched { path, pid, .. }) => {
            assert_eq!(path, "/root/.ssh/id_rsa");
            assert_eq!(pid, 333);
        }
        other => panic!("Expected CanaryHoneypotTouched, got {:?}", other),
    }
}

#[test]
fn test_evasion_time_bomb_fast_forwarding() {
    let arm_disasm = Arc::new(Arm64Disassembler::default());
    let mut sandbox = AegisUnifiedSandbox::new(arm_disasm, SandboxPolicy::default());

    let clean_code = vec![0x3F, 0x23, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6];
    let baseline = StaticGatekeeper::audit_binary(&clean_code, Some(TargetArch::AArch64), false).unwrap();

    let sleep_events = vec![
        SandboxRuntimeEvent::GuestSleepStallDetected { requested_seconds: 1800 },
        SandboxRuntimeEvent::GuestSleepStallDetected { requested_seconds: 1800 },
    ];

    let report = sandbox.detonate_in_sandbox(&baseline, sleep_events);
    assert!(report.is_clean());
    assert_eq!(report.virtual_clock_fast_forwarded_secs, 3600);
    assert_eq!(report.cumulative_risk_score, 30);
}

#[test]
fn test_unbacked_shellcode_trap() {
    let arm_disasm = Arc::new(Arm64Disassembler::default());
    let mut sandbox = AegisUnifiedSandbox::new(arm_disasm, SandboxPolicy::default());

    let clean_code = vec![0x3F, 0x23, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6];
    let baseline = StaticGatekeeper::audit_binary(&clean_code, Some(TargetArch::AArch64), false).unwrap();

    let shellcode_events = vec![SandboxRuntimeEvent::ArmCacheMaintenanceTrap {
        ipa: 0x4000_0000, // Anonymous unbacked RAM
        unpacked_bytes: vec![0x01, 0x00, 0x00, 0xD4], // raw `svc #0`
    }];

    let report = sandbox.detonate_in_sandbox(&baseline, shellcode_events);
    assert!(!report.is_clean());
    match report.verdict {
        Err(SecurityViolation::UnbackedExecutableShellcode { .. }) => {}
        other => panic!("Expected UnbackedExecutableShellcode, got {:?}", other),
    }
}

#[test]
fn test_process_injection_interception() {
    let x86_disasm = Arc::new(X86_64Disassembler);
    let mut sandbox = AegisUnifiedSandbox::new(x86_disasm, SandboxPolicy::default());

    let clean_code = vec![0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0xC3];
    let baseline = StaticGatekeeper::audit_binary(&clean_code, Some(TargetArch::X86_64), false).unwrap();

    let injection_events = vec![SandboxRuntimeEvent::ProcessActivity {
        source_pid: 1000,
        target_pid: 4,
        syscall: "ptrace_poketext".to_string(),
    }];

    let report = sandbox.detonate_in_sandbox(&baseline, injection_events);
    assert!(!report.is_clean());
    match report.verdict {
        Err(SecurityViolation::ProcessHollowingOrInjection { source_pid, target_pid, api }) => {
            assert_eq!(source_pid, 1000);
            assert_eq!(target_pid, 4);
            assert_eq!(api, "ptrace_poketext");
        }
        other => panic!("Expected ProcessHollowingOrInjection, got {:?}", other),
    }
}

#[test]
fn test_unauthorized_network_c2_block() {
    let x86_disasm = Arc::new(X86_64Disassembler);
    let mut sandbox = AegisUnifiedSandbox::new(x86_disasm, SandboxPolicy::default());

    let clean_code = vec![0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0xC3];
    let baseline = StaticGatekeeper::audit_binary(&clean_code, Some(TargetArch::X86_64), false).unwrap();

    let network_events = vec![SandboxRuntimeEvent::NetworkActivity {
        pid: 500,
        dst_ip: "198.51.100.23".to_string(),
        dst_port: 4444,
        protocol: "TCP".to_string(),
        payload_preview: b"GET /c2_beacon HTTP/1.1\r\n".to_vec(),
    }];

    let report = sandbox.detonate_in_sandbox(&baseline, network_events);
    assert!(!report.is_clean());
    match report.verdict {
        Err(SecurityViolation::UnauthorizedNetworkExfiltration { dst_ip, dst_port, protocol }) => {
            assert_eq!(dst_ip, "198.51.100.23");
            assert_eq!(dst_port, 4444);
            assert_eq!(protocol, "TCP");
        }
        other => panic!("Expected UnauthorizedNetworkExfiltration, got {:?}", other),
    }
}
