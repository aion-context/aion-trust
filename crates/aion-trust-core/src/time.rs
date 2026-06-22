//! A minimal timestamp (unix seconds). Verification takes an explicit `now` so tests
//! are deterministic; the CLI supplies the wall clock.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// The current wall-clock time in unix seconds (saturates to 0 before the epoch).
    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Timestamp(secs)
    }

    /// This timestamp plus `seconds`.
    pub fn plus_seconds(self, seconds: i64) -> Self {
        Timestamp(self.0.saturating_add(seconds))
    }
}
