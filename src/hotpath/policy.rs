use crate::Result;
use crate::clob::types::TickSize;
use crate::error::Error;

/// Policy wrapper for values that can either be fixed or fetched/cached.
///
/// `FetchAndCache` is intentionally modeled now for future expansion,
/// but only `Fixed` is currently implemented in `hotpath`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum FixedOrFetch<T> {
    Fixed(T),
    FetchAndCache,
}

impl<T: Copy> FixedOrFetch<T> {
    pub(crate) fn resolve_fixed(self, field: &str) -> Result<T> {
        match self {
            FixedOrFetch::Fixed(value) => Ok(value),
            FixedOrFetch::FetchAndCache => Err(Error::validation(format!(
                "{field} policy FetchAndCache is not implemented in hotpath yet"
            ))),
        }
    }
}

/// Time policy used for L1/L2 header timestamps.
///
/// `Fixed` means "no `/time` call" and uses local unix timestamp.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum TimePolicy {
    Fixed,
    FetchAndCache,
}

impl TimePolicy {
    pub(crate) fn ensure_supported(self) -> Result<()> {
        match self {
            TimePolicy::Fixed => Ok(()),
            TimePolicy::FetchAndCache => Err(Error::validation(
                "time policy FetchAndCache is not implemented in hotpath yet",
            )),
        }
    }
}

/// Defaults used by the hot-path order flow.
#[derive(Clone, Copy, Debug)]
pub struct HotPathPolicies {
    pub tick_size: FixedOrFetch<TickSize>,
    pub neg_risk: FixedOrFetch<bool>,
    pub fee_rate_bps: FixedOrFetch<u32>,
    pub time: TimePolicy,
}

impl HotPathPolicies {
    pub(crate) fn default_tick_size(self) -> Result<TickSize> {
        self.tick_size.resolve_fixed("tick_size")
    }

    pub(crate) fn default_neg_risk(self) -> Result<bool> {
        self.neg_risk.resolve_fixed("neg_risk")
    }

    pub(crate) fn default_fee_rate_bps(self) -> Result<u32> {
        self.fee_rate_bps.resolve_fixed("fee_rate_bps")
    }

    pub(crate) fn validate(self) -> Result<()> {
        self.time.ensure_supported()?;
        let _ = self.default_tick_size()?;
        let _ = self.default_neg_risk()?;
        let _ = self.default_fee_rate_bps()?;
        Ok(())
    }
}
