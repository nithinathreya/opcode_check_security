use serde::{Deserialize, Serialize};

/// Cumulative risk assessment engine for AegisVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScorer {
    pub cumulative_score: u32,
    pub max_allowed_score: u32,
    pub risk_factors: Vec<String>,
}

impl RiskScorer {
    pub fn new(max_allowed_score: u32) -> Self {
        Self {
            cumulative_score: 0,
            max_allowed_score,
            risk_factors: Vec::new(),
        }
    }

    /// Add risk points with an accompanying explanatory reason.
    pub fn add_risk(&mut self, points: u32, reason: &str) {
        self.cumulative_score = self.cumulative_score.saturating_add(points);
        self.risk_factors.push(format!("+{} pts: {}", points, reason));
    }

    /// Check if the risk score has breached the allowable threshold.
    pub fn is_breached(&self) -> bool {
        self.cumulative_score >= self.max_allowed_score
    }
}
