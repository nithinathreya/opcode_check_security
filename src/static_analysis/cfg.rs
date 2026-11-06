use crate::arch::types::NormalizedInstruction;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

/// Control Flow Graph (CFG) constructed over decoded instruction streams.
pub struct ControlFlowGraph {
    pub graph: DiGraph<u64, ()>,
    pub node_map: HashMap<u64, NodeIndex>,
}

impl ControlFlowGraph {
    /// Construct a CFG from decoded normalized instructions.
    pub fn build(instructions: &[NormalizedInstruction]) -> Self {
        let mut graph = DiGraph::<u64, ()>::new();
        let mut node_map = HashMap::new();

        // Pass 1: Insert all instruction addresses as nodes
        for insn in instructions {
            let idx = graph.add_node(insn.address);
            node_map.insert(insn.address, idx);
        }

        // Pass 2: Connect control-flow edges
        for (i, insn) in instructions.iter().enumerate() {
            let curr_idx = *node_map.get(&insn.address).unwrap();

            // Branch edge (if static target exists and is known)
            if let Some(target_addr) = insn.branch_target {
                if let Some(&target_idx) = node_map.get(&target_addr) {
                    graph.add_edge(curr_idx, target_idx, ());
                }
            }

            // Fallthrough edge (unless unconditional terminator like `ret` or unconditional direct jump)
            let is_unconditional_term = insn.mnemonic == "ret"
                || insn.mnemonic == "jmp"
                || insn.mnemonic == "b"
                || insn.mnemonic == "svc"
                || insn.mnemonic == "syscall";

            if !is_unconditional_term && i + 1 < instructions.len() {
                let next_addr = instructions[i + 1].address;
                if let Some(&next_idx) = node_map.get(&next_addr) {
                    graph.add_edge(curr_idx, next_idx, ());
                }
            }
        }

        Self { graph, node_map }
    }

    /// Calculate cyclomatic complexity: M = E - N + 2
    pub fn cyclomatic_complexity(&self) -> usize {
        let n = self.graph.node_count();
        let e = self.graph.edge_count();
        if e >= n {
            e - n + 2
        } else {
            1
        }
    }
}
