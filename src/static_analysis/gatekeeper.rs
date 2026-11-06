use std::collections::HashMap;
use std::sync::Arc;

use crate::arch::types::{StaticBaseline, TargetArch};
use crate::arch::{ArchDisassembler, Arm64Disassembler, X86_64Disassembler};
use crate::security::violations::SecurityViolation;
use crate::static_analysis::binary_parser::{ExtractedBinary, UniversalBinaryParser};
use crate::static_analysis::cfg::ControlFlowGraph;
use crate::static_analysis::entropy::shannon_entropy;

pub struct StaticGatekeeper;

impl StaticGatekeeper {
    /// Audits static opcodes, parses headers, calculates entropy, builds CFG,
    /// and generates the immutable disk baseline for dynamic RAM diffing.
    pub fn audit_binary(
        bytes: &[u8],
        forced_arch: Option<TargetArch>,
        strict_syscall_check: bool,
    ) -> Result<StaticBaseline, SecurityViolation> {
        Self::audit_binary_with_vaddr(bytes, forced_arch, None, strict_syscall_check)
    }

    /// Audits static opcodes with optional custom virtual address mapping.
    pub fn audit_binary_with_vaddr(
        bytes: &[u8],
        forced_arch: Option<TargetArch>,
        custom_vaddr: Option<u64>,
        strict_syscall_check: bool,
    ) -> Result<StaticBaseline, SecurityViolation> {
        let parsed = UniversalBinaryParser::parse_with_vaddr(bytes, forced_arch, custom_vaddr).map_err(|e| {
            SecurityViolation::SignatureRuleHit {
                rule_name: "CorruptOrMalformedBinaryHeader".to_string(),
                description: e,
            }
        })?;

        Self::audit_extracted(&parsed, strict_syscall_check)
    }

    /// Audits a pre-parsed binary representation.
    pub fn audit_extracted(
        binary: &ExtractedBinary,
        strict_syscall_check: bool,
    ) -> Result<StaticBaseline, SecurityViolation> {
        let text_entropy = shannon_entropy(&binary.text_section);
        let is_packed = text_entropy > 7.2 || binary.text_section.is_empty();

        let disasm: Arc<dyn ArchDisassembler> = match binary.arch {
            TargetArch::X86_64 => Arc::new(X86_64Disassembler),
            TargetArch::AArch64 => Arc::new(Arm64Disassembler::default()),
        };

        let decoded = disasm.decode_stream(&binary.text_section, binary.text_vaddr)?;

        // 1. Audit static instructions for forbidden raw syscalls or evasion instructions
        let mut has_pac_bti = false;
        let mut cfi_landing_pads_found = 0;
        let mut total_branches = 0;

        for insn in &decoded {
            if insn.is_syscall && strict_syscall_check {
                return Err(SecurityViolation::ForbiddenStaticOpcode {
                    arch: binary.arch,
                    address: insn.address,
                    mnemonic: insn.mnemonic.clone(),
                    reason: "Direct raw syscall instruction found in static binary text".to_string(),
                });
            }

            if insn.is_cfi_landing_pad {
                has_pac_bti = true;
                cfi_landing_pads_found += 1;
            }

            if insn.is_branch {
                total_branches += 1;
            }
        }

        // On ARM64 modern binaries with functions, check for PAC/BTI security landing pads if strict
        if binary.arch == TargetArch::AArch64 && decoded.len() > 10 && total_branches > 2 && !has_pac_bti && !is_packed {
            // High security requirement: warn / flag missing CFI landing pads
            // (Only for larger ARM64 binaries)
        }

        // 2. Construct Control Flow Graph
        let cfg = ControlFlowGraph::build(&decoded);

        // 3. Partition clean disk text section into hardware page-sized chunks for Stage 3 RAM diffing
        let page_size = disasm.page_size();
        let mut code_page_baselines = HashMap::new();
        for (page_idx, chunk) in binary.text_section.chunks(page_size).enumerate() {
            let page_addr = binary.text_vaddr + (page_idx * page_size) as u64;
            code_page_baselines.insert(page_addr, chunk.to_vec());
        }

        Ok(StaticBaseline {
            arch: binary.arch,
            is_packed_or_high_entropy: is_packed,
            section_entropy: text_entropy,
            code_page_baselines,
            total_instructions_audited: decoded.len(),
            cfg_node_count: cfg.graph.node_count(),
            cfg_edge_count: cfg.graph.edge_count(),
            cfi_landing_pads_found,
            entry_point: binary.entry_point,
            binary_sha256: binary.sha256.clone(),
        })
    }
}
