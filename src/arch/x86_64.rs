use super::{ArchDisassembler, NormalizedInstruction, TargetArch};
use crate::security::violations::SecurityViolation;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};

/// x86_64 instruction decoder and trampoline detector backed by `iced-x86`.
pub struct X86_64Disassembler;

impl ArchDisassembler for X86_64Disassembler {
    fn arch(&self) -> TargetArch {
        TargetArch::X86_64
    }

    fn page_size(&self) -> usize {
        4096 // Standard 4KB page
    }

    fn decode_stream(&self, bytes: &[u8], base_addr: u64) -> Result<Vec<NormalizedInstruction>, SecurityViolation> {
        let mut instructions = Vec::new();
        if bytes.is_empty() {
            return Ok(instructions);
        }

        let mut decoder = Decoder::with_ip(64, bytes, base_addr, DecoderOptions::NONE);
        let mut instr = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);

            let addr = instr.ip();
            let len = instr.len();
            let start_offset = (addr.saturating_sub(base_addr)) as usize;
            let end_offset = (start_offset + len).min(bytes.len());
            let raw_bytes = if start_offset < bytes.len() {
                bytes[start_offset..end_offset].to_vec()
            } else {
                Vec::new()
            };

            let mnem = instr.mnemonic();
            let is_syscall = matches!(mnem, Mnemonic::Syscall | Mnemonic::Sysenter)
                || (matches!(mnem, Mnemonic::Int) && instr.op0_kind() == OpKind::Immediate8 && instr.immediate8() == 0x80);

            let is_vm_or_timer_probe = matches!(mnem, Mnemonic::Cpuid | Mnemonic::Rdtsc | Mnemonic::Rdtscp);
            let is_cfi_landing_pad = matches!(mnem, Mnemonic::Endbr64 | Mnemonic::Endbr32);

            let fc = instr.flow_control();
            let is_branch = matches!(
                fc,
                FlowControl::Call
                    | FlowControl::IndirectCall
                    | FlowControl::UnconditionalBranch
                    | FlowControl::IndirectBranch
                    | FlowControl::ConditionalBranch
                    | FlowControl::Return
            );

            let branch_target = match instr.op0_kind() {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => Some(instr.near_branch_target()),
                _ => None,
            };

            instructions.push(NormalizedInstruction {
                address: addr,
                mnemonic: format!("{:?}", mnem).to_lowercase(),
                raw_bytes,
                is_syscall,
                is_vm_or_timer_probe,
                is_cache_flush: false,
                is_cfi_landing_pad,
                is_branch,
                branch_target,
            });
        }

        Ok(instructions)
    }

    fn is_inline_trampoline(&self, live: &[u8], baseline: &[u8]) -> Option<String> {
        if live == baseline || live.is_empty() {
            return None;
        }

        // 1. Detect 5-byte `JMP rel32` (0xE9 xx xx xx xx)
        if live[0] == 0xE9 && live.len() >= 5 {
            return Some("x86_5byte_jmp_rel32_trampoline".to_string());
        }

        // 2. Detect 6-byte indirect `JMP [RIP+disp32]` (0xFF 0x25 xx xx xx xx)
        if live.len() >= 6 && live[0] == 0xFF && live[1] == 0x25 {
            return Some("x86_6byte_rip_indirect_jmp_trampoline".to_string());
        }

        // 3. Detect 12-byte `mov rax, imm64; push rax; ret` (0x48 0xB8 ... 0x50 0xC3)
        if live.len() >= 12
            && live[0] == 0x48
            && live[1] == 0xB8
            && live[10] == 0x50
            && live[11] == 0xC3
        {
            return Some("x86_12byte_push_ret_trampoline".to_string());
        }

        // 4. Detect 2-byte short jump (0xEB xx) hooking the function prologue
        if live[0] == 0xEB && live.len() >= 2 {
            return Some("x86_2byte_short_jmp_hook".to_string());
        }

        // General byte divergence detected
        if live.iter().zip(baseline.iter()).any(|(a, b)| a != b) {
            return Some("x86_patched_code_divergence".to_string());
        }

        None
    }
}
