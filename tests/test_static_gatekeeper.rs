use aegis_cli::static_analysis::entropy::shannon_entropy;
use aegis_cli::static_analysis::gatekeeper::StaticGatekeeper;
use aegis_cli::TargetArch;

#[test]
fn test_shannon_entropy_calculation() {
    let zeros = vec![0u8; 512];
    assert_eq!(shannon_entropy(&zeros), 0.0);

    // Constant repeated byte
    let a_bytes = vec![b'A'; 1000];
    assert_eq!(shannon_entropy(&a_bytes), 0.0);

    // English text entropy is typically between 3.5 and 4.8
    let english = b"The quick brown fox jumps over the lazy dog. Security in Rust is robust and type-safe.";
    let h = shannon_entropy(english);
    assert!(h > 3.0 && h < 5.0, "Entropy of English text should be ~4.0, got {}", h);
}

#[test]
fn test_static_gatekeeper_rejects_forbidden_syscalls() {
    // x86 binary with direct raw `syscall` instruction
    let raw_syscall = vec![0x0F, 0x05, 0xC3];

    let result = StaticGatekeeper::audit_binary(&raw_syscall, Some(TargetArch::X86_64), true);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(format!("{}", err).contains("Forbidden static opcode"));
}

#[test]
fn test_static_gatekeeper_creates_baseline() {
    // Clean x86 code: endbr64, nop, ret
    let clean_code = vec![0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0xC3];

    let baseline = StaticGatekeeper::audit_binary(&clean_code, Some(TargetArch::X86_64), false)
        .expect("Baseline generation failed");

    assert_eq!(baseline.arch, TargetArch::X86_64);
    assert!(!baseline.is_packed_or_high_entropy);
    assert_eq!(baseline.total_instructions_audited, 3);
    assert!(baseline.code_page_baselines.contains_key(&0x1000_0000));
}
