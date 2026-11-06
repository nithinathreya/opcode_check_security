use aegis_cli::arch::{ArchDisassembler, Arm64Disassembler, X86_64Disassembler};
use aegis_cli::TargetArch;

#[test]
fn test_x86_disassembly_and_syscall_detection() {
    let disasm = X86_64Disassembler;
    assert_eq!(disasm.arch(), TargetArch::X86_64);
    assert_eq!(disasm.page_size(), 4096);

    // Assembly sequence:
    // endbr64 (F3 0F 1E FA)
    // cpuid   (0F A2)
    // rdtsc   (0F 31)
    // syscall (0F 05)
    // ret     (C3)
    let bytes = vec![
        0xF3, 0x0F, 0x1E, 0xFA, // endbr64
        0x0F, 0xA2,             // cpuid
        0x0F, 0x31,             // rdtsc
        0x0F, 0x05,             // syscall
        0xC3,                   // ret
    ];

    let instructions = disasm.decode_stream(&bytes, 0x400000).expect("Decoding failed");
    assert_eq!(instructions.len(), 5);

    assert!(instructions[0].is_cfi_landing_pad);
    assert!(instructions[1].is_vm_or_timer_probe);
    assert!(instructions[2].is_vm_or_timer_probe);
    assert!(instructions[3].is_syscall);
    assert!(instructions[4].is_branch);
}

#[test]
fn test_x86_trampoline_detection() {
    let disasm = X86_64Disassembler;
    let clean = vec![0x90; 16];

    // 5-byte JMP rel32 hook
    let hook_5b = vec![0xE9, 0x10, 0x20, 0x30, 0x40, 0x90, 0x90, 0x90];
    let detected = disasm.is_inline_trampoline(&hook_5b, &clean);
    assert_eq!(detected, Some("x86_5byte_jmp_rel32_trampoline".to_string()));

    // 6-byte indirect JMP [RIP+disp32] hook
    let hook_6b = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90];
    let detected_6b = disasm.is_inline_trampoline(&hook_6b, &clean);
    assert_eq!(detected_6b, Some("x86_6byte_rip_indirect_jmp_trampoline".to_string()));
}

#[test]
fn test_arm64_disassembly_and_pac_bti() {
    let disasm = Arm64Disassembler::default();
    assert_eq!(disasm.arch(), TargetArch::AArch64);

    // ARM64 sequence:
    // paciasp (0xD503233F)
    // bti c   (0xD503245F)
    // svc #0  (0xD4000001)
    // ic ivau (0xD50B7520)
    // ret     (0xD65F03C0)
    let bytes = vec![
        0x3F, 0x23, 0x03, 0xD5, // paciasp
        0x5F, 0x24, 0x03, 0xD5, // bti c
        0x01, 0x00, 0x00, 0xD4, // svc #0
        0x20, 0x75, 0x0B, 0xD5, // ic ivau
        0xC0, 0x03, 0x5F, 0xD6, // ret
    ];

    let instructions = disasm.decode_stream(&bytes, 0x10000000).expect("ARM64 decoding failed");
    assert_eq!(instructions.len(), 5);

    assert!(instructions[0].is_cfi_landing_pad);
    assert!(instructions[1].is_cfi_landing_pad);
    assert!(instructions[2].is_syscall);
    assert!(instructions[3].is_cache_flush);
    assert!(instructions[4].is_branch);
}

#[test]
fn test_arm64_trampoline_detection() {
    let disasm = Arm64Disassembler::default();
    let clean = vec![0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5]; // 2 NOPs

    // 16-byte LDR X16, #8 + BR X16 trampoline hook
    let hook_ldr_br = vec![
        0x50, 0x00, 0x00, 0x58, // LDR X16, #8
        0x00, 0x02, 0x1F, 0xD6, // BR X16
        0x00, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, // 64-bit target address
    ];

    let detected = disasm.is_inline_trampoline(&hook_ldr_br, &clean);
    assert_eq!(detected, Some("arm64_ldr_x16_br_x16_absolute_trampoline".to_string()));
}
