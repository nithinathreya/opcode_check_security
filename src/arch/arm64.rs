use super::{ArchDisassembler, NormalizedInstruction, TargetArch};
use crate::security::violations::SecurityViolation;

/// ARM64 (AArch64) instruction decoder, PAC/BTI landing pad validator, and trampoline detector.
pub struct Arm64Disassembler {
    pub apple_silicon_16k_pages: bool,
}

impl Default for Arm64Disassembler {
    fn default() -> Self {
        #[cfg(target_os = "macos")]
        let apple_silicon = true;
        #[cfg(not(target_os = "macos"))]
        let apple_silicon = false;

        Self {
            apple_silicon_16k_pages: apple_silicon,
        }
    }
}

impl ArchDisassembler for Arm64Disassembler {
    fn arch(&self) -> TargetArch {
        TargetArch::AArch64
    }

    fn page_size(&self) -> usize {
        if self.apple_silicon_16k_pages {
            16384 // 16KB Apple Silicon page
        } else {
            4096 // 4KB standard Linux/Windows ARM64 page
        }
    }

    fn decode_stream(&self, bytes: &[u8], base_addr: u64) -> Result<Vec<NormalizedInstruction>, SecurityViolation> {
        if bytes.len() % 4 != 0 {
            return Err(SecurityViolation::UnalignedArmInstruction { address: base_addr });
        }

        let mut instructions = Vec::with_capacity(bytes.len() / 4);

        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            let addr = base_addr + (i as u64 * 4);
            let insn = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

            // Try decoding with `bad64` for full instruction mnemonic and semantics
            let (mnemonic_str, is_sys, is_probe, is_cache, is_cfi, is_br, br_target) = match bad64::decode(insn, addr) {
                Ok(decoded) => {
                    let mnem = decoded.op().mnem().to_string();
                    let op = decoded.op();

                    // Check for supervisor call / hypervisor call / secure monitor call
                    let is_sys = matches!(op, bad64::Op::SVC | bad64::Op::HVC | bad64::Op::SMC);

                    // Check for MRS (system register probe, e.g. CNTVCT_EL0, MIDR_EL1)
                    let is_probe = matches!(op, bad64::Op::MRS);

                    // Check for instruction/data cache flushes (self-modifying code indicator)
                    let is_cache = matches!(op, bad64::Op::IC | bad64::Op::DC)
                        || insn == 0xD50B_7520  // `ic ivau, x0`
                        || insn == 0xD50B_7B20; // `dc cvau, x0`

                    // Check for PAC (Pointer Authentication) & BTI (Branch Target Identification)
                    let is_cfi = matches!(
                        op,
                        bad64::Op::PACIASP | bad64::Op::PACIBSP | bad64::Op::AUTIASP | bad64::Op::AUTIBSP | bad64::Op::BTI
                    ) || insn == 0xD503_233F   // `paciasp`
                      || insn == 0xD503_245F;  // `bti c`

                    // Check for branch instructions
                    let is_br = matches!(
                        op,
                        bad64::Op::B
                            | bad64::Op::BL
                            | bad64::Op::BR
                            | bad64::Op::BLR
                            | bad64::Op::RET
                            | bad64::Op::CBZ
                            | bad64::Op::CBNZ
                            | bad64::Op::TBZ
                            | bad64::Op::TBNZ
                    );

                    // Check if branch target is directly immediate
                    let target = if (insn >> 26) == 0b000101 || (insn >> 26) == 0b100101 {
                        // B or BL immediate: sign-extend 26-bit offset << 2
                        let imm26 = (insn & 0x03FF_FFFF) as i32;
                        let signed_offset = ((imm26 << 6) >> 4) as i64; // sign extend 26 bits
                        Some((addr as i64 + signed_offset) as u64)
                    } else {
                        None
                    };

                    (mnem, is_sys, is_probe, is_cache, is_cfi, is_br, target)
                }
                Err(_) => {
                    // Fallback to high-precision hardware bitmask decoder
                    let is_svc = (insn & 0xFFE0_001F) == 0xD400_0001; // `svc #imm`
                    let is_hvc = (insn & 0xFFE0_001F) == 0xD400_0002; // `hvc #imm`
                    let is_smc = (insn & 0xFFE0_001F) == 0xD400_0003; // `smc #imm`
                    let is_brk = (insn & 0xFFE0_001F) == 0xD420_0000; // `brk #imm`
                    let is_mrs_probe = (insn & 0xFFF0_0000) == 0xD530_0000; // `mrs xN, <sysreg>`
                    let is_ic_ivau = insn == 0xD50B_7520; // `ic ivau, x0`
                    let is_dc_cvau = insn == 0xD50B_7B20; // `dc cvau, x0`
                    let is_paciasp = insn == 0xD503_233F; // `paciasp`
                    let is_autiasp = insn == 0xD503_23BF; // `autiasp`
                    let is_bti_c = insn == 0xD503_245F;   // `bti c`
                    let is_b_imm = (insn >> 26) == 0b000101;
                    let is_ret = insn == 0xD65F_03C0;

                    let mnem = if is_svc {
                        "svc"
                    } else if is_hvc {
                        "hvc"
                    } else if is_smc {
                        "smc"
                    } else if is_brk {
                        "brk"
                    } else if is_ic_ivau {
                        "ic ivau"
                    } else if is_dc_cvau {
                        "dc cvau"
                    } else if is_paciasp {
                        "paciasp"
                    } else if is_autiasp {
                        "autiasp"
                    } else if is_bti_c {
                        "bti c"
                    } else if is_mrs_probe {
                        "mrs"
                    } else if is_ret {
                        "ret"
                    } else if is_b_imm {
                        "b"
                    } else {
                        "a64_op"
                    };

                    (
                        mnem.to_string(),
                        is_svc || is_hvc || is_smc,
                        is_mrs_probe,
                        is_ic_ivau || is_dc_cvau,
                        is_paciasp || is_autiasp || is_bti_c,
                        is_b_imm || is_ret,
                        None,
                    )
                }
            };

            instructions.push(NormalizedInstruction {
                address: addr,
                mnemonic: mnemonic_str,
                raw_bytes: chunk.to_vec(),
                is_syscall: is_sys,
                is_vm_or_timer_probe: is_probe,
                is_cache_flush: is_cache,
                is_cfi_landing_pad: is_cfi,
                is_branch: is_br,
                branch_target: br_target,
            });
        }

        Ok(instructions)
    }

    fn is_inline_trampoline(&self, live: &[u8], baseline: &[u8]) -> Option<String> {
        if live == baseline || live.len() < 4 {
            return None;
        }

        // 1. Detect unconditional 4-byte branch: `B #imm` (top 6 bits = 0b000101)
        let first = u32::from_le_bytes([live[0], live[1], live[2], live[3]]);
        if (first >> 26) == 0b000101 {
            return Some("arm64_unconditional_b_trampoline".to_string());
        }

        // 2. Detect 16-byte absolute indirect jump hook:
        // `LDR X16, #8` (0x58000050) + `BR X16` (0xD61F0200) + 8-byte target
        if live.len() >= 8 {
            let second = u32::from_le_bytes([live[4], live[5], live[6], live[7]]);
            if first == 0x5800_0050 && second == 0xD61F_0200 {
                return Some("arm64_ldr_x16_br_x16_absolute_trampoline".to_string());
            }

            // Also check `LDR X17, #8` (0x58000051) + `BR X17` (0xD61F0220)
            if first == 0x5800_0051 && second == 0xD61F_0220 {
                return Some("arm64_ldr_x17_br_x17_absolute_trampoline".to_string());
            }
        }

        // 3. Detect `BRK #0` or software breakpoint injection
        if (first & 0xFFE0_001F) == 0xD420_0000 {
            return Some("arm64_brk_software_breakpoint_hook".to_string());
        }

        // General divergence check
        if live.iter().zip(baseline.iter()).any(|(a, b)| a != b) {
            return Some("arm64_patched_opcode_divergence".to_string());
        }

        None
    }
}
