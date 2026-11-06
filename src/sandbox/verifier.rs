use std::sync::Arc;

use crate::arch::types::StaticBaseline;
use crate::arch::ArchDisassembler;
use crate::sandbox::memory::GuestMemory;
use crate::sandbox::policy::SandboxPolicy;
use crate::security::violations::SecurityViolation;

/// Dynamic RAM Opcode Verifier: Diffs live guest memory against disk baseline and audits unbacked code.
pub struct RamOpcodeVerifier {
    pub disassembler: Arc<dyn ArchDisassembler>,
}

impl RamOpcodeVerifier {
    pub fn new(disassembler: Arc<dyn ArchDisassembler>) -> Self {
        Self { disassembler }
    }

    /// Audit a live guest physical RAM page triggered by an EPT / Stage-2 MMU execute fault or cache flush.
    ///
    /// Returns `Ok(true)` if the page was newly verified unbacked RAM,
    /// or `Ok(false)` if it was an existing clean baseline page.
    pub fn audit_live_page(
        &self,
        gpa_or_ipa: u64,
        live_page_bytes: &[u8],
        baseline: &StaticBaseline,
        memory: &mut GuestMemory,
        policy: &SandboxPolicy,
    ) -> Result<bool, SecurityViolation> {
        let page_addr = memory.page_align(gpa_or_ipa);

        // Branch 1: Is this page backed by original disk `.text`?
        if let Some(expected_bytes) = baseline.code_page_baselines.get(&page_addr) {
            // Check for inline trampoline hooks (x86 JMP / indirect JMP, ARM64 B / LDR+BR)
            if let Some(hook_type) = self.disassembler.is_inline_trampoline(live_page_bytes, expected_bytes) {
                return Err(SecurityViolation::InlineHookDetected {
                    gpa_or_ipa: page_addr,
                    expected: expected_bytes.iter().take(16).copied().collect(),
                    actual: live_page_bytes.iter().take(16).copied().collect(),
                    hook_type,
                });
            }

            // Lock page to Read+Execute
            memory.lock_page_rx(page_addr);
            Ok(false)
        } else {
            // Branch 2: Unbacked / Newly Unpacked RAM Page (Anonymous memory, JIT, Shellcode)
            let decoded = self.disassembler.decode_stream(live_page_bytes, page_addr)?;

            for insn in decoded {
                if insn.is_syscall && !policy.allow_raw_syscalls_in_unbacked_ram {
                    return Err(SecurityViolation::UnbackedExecutableShellcode {
                        gpa_or_ipa: insn.address,
                        opcode_summary: format!(
                            "Raw syscall '{}' at 0x{:016X} within unbacked anonymous RAM",
                            insn.mnemonic, insn.address
                        ),
                    });
                }
            }

            // Lock page to Read+Execute (clear write permission)
            memory.lock_page_rx(page_addr);
            Ok(true)
        }
    }
}
