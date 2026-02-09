//! Lean hot-path client focused on fast limit order placement.
//!
//! This module intentionally implements only the critical `/order` flow:
//! - bootstrap credentials via L1 auth
//! - build + sign limit orders
//! - submit signed orders with L2 headers
//!
//! Additional REST-backed policy modes are modeled but not yet implemented.

mod client;
mod config;
mod policy;
mod types;

pub use client::HotPathClient;
pub use config::{HotPathConfig, RawHotPathSigningConfig};
pub use policy::{FixedOrFetch, HotPathPolicies, TimePolicy};
pub use types::{LimitOrderOverrides, LimitOrderRequest, SignatureTypeInput};
