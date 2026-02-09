use std::str::FromStr;

use chrono::{DateTime, Utc};

use crate::Result;
use crate::clob::types::{OrderType, Side, SignatureType, TickSize};
use crate::error::Error;
use crate::types::{Address, Decimal, U256};

/// Signature type parser for config-style string inputs.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureTypeInput {
    Eoa,
    Proxy,
    GnosisSafe,
}

impl SignatureTypeInput {
    pub fn parse(value: &str) -> Result<SignatureTypeInput> {
        match value.trim().to_ascii_lowercase().as_str() {
            "0" | "eoa" => Ok(SignatureTypeInput::Eoa),
            "1" | "proxy" => Ok(SignatureTypeInput::Proxy),
            "2" | "gnosis" | "gnosis_safe" | "gnosissafe" | "safe" => {
                Ok(SignatureTypeInput::GnosisSafe)
            }
            other => Err(Error::validation(format!(
                "invalid signature_type `{other}`; expected one of: eoa|proxy|gnosis"
            ))),
        }
    }

    #[must_use]
    pub const fn into_signature_type(self) -> SignatureType {
        match self {
            SignatureTypeInput::Eoa => SignatureType::Eoa,
            SignatureTypeInput::Proxy => SignatureType::Proxy,
            SignatureTypeInput::GnosisSafe => SignatureType::GnosisSafe,
        }
    }
}

/// Input values for a single limit order.
#[derive(Clone, Debug)]
pub struct LimitOrderRequest {
    pub token_id: U256,
    pub side: Side,
    pub price: Decimal,
    pub size: Decimal,
    pub nonce: Option<u64>,
    pub expiration: Option<DateTime<Utc>>,
    pub taker: Option<Address>,
    pub order_type: Option<OrderType>,
    pub post_only: Option<bool>,
}

impl LimitOrderRequest {
    #[must_use]
    pub fn new(token_id: U256, side: Side, price: Decimal, size: Decimal) -> Self {
        Self {
            token_id,
            side,
            price,
            size,
            nonce: None,
            expiration: None,
            taker: None,
            order_type: None,
            post_only: None,
        }
    }
}

/// Per-order overrides on top of fixed hot-path defaults.
#[derive(Clone, Copy, Debug, Default)]
pub struct LimitOrderOverrides {
    pub tick_size: Option<TickSize>,
    pub neg_risk: Option<bool>,
    pub fee_rate_bps: Option<u32>,
    pub timestamp: Option<i64>,
}

impl LimitOrderOverrides {
    #[must_use]
    pub const fn with_tick_size(mut self, tick_size: TickSize) -> Self {
        self.tick_size = Some(tick_size);
        self
    }

    #[must_use]
    pub const fn with_neg_risk(mut self, neg_risk: bool) -> Self {
        self.neg_risk = Some(neg_risk);
        self
    }

    #[must_use]
    pub const fn with_fee_rate_bps(mut self, fee_rate_bps: u32) -> Self {
        self.fee_rate_bps = Some(fee_rate_bps);
        self
    }

    #[must_use]
    pub const fn with_timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}

impl FromStr for SignatureTypeInput {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        SignatureTypeInput::parse(s)
    }
}
