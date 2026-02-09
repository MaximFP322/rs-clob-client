use std::str::FromStr as _;

use secrecy::SecretString;
use url::Url;

use crate::POLYGON;
use crate::Result;
use crate::clob::types::SignatureType;
use crate::error::Error;
use crate::hotpath::policy::HotPathPolicies;
use crate::hotpath::types::SignatureTypeInput;
use crate::types::{Address, ChainId};

/// Raw signing values typically passed from app-level bot config.
#[derive(Clone, Debug)]
pub struct RawHotPathSigningConfig {
    pub private_key: SecretString,
    pub signature_type: String,
    pub funder: String,
}

/// Hot-path bootstrap configuration.
#[derive(Clone, Debug)]
pub struct HotPathConfig {
    pub host: Url,
    pub chain_id: ChainId,
    pub private_key: SecretString,
    pub signature_type: SignatureType,
    pub funder: Address,
    pub nonce: Option<u32>,
    pub policies: HotPathPolicies,
}

impl HotPathConfig {
    pub fn from_raw(
        host: &str,
        chain_id: ChainId,
        raw: RawHotPathSigningConfig,
        policies: HotPathPolicies,
    ) -> Result<Self> {
        let host = Url::parse(host)?;
        let signature_type =
            SignatureTypeInput::from_str(&raw.signature_type)?.into_signature_type();
        let funder = Address::from_str(&raw.funder)
            .map_err(|e| Error::validation(format!("invalid funder address: {e}")))?;

        Self::new(
            host,
            chain_id,
            raw.private_key,
            signature_type,
            funder,
            None,
            policies,
        )
    }

    pub fn new(
        host: Url,
        chain_id: ChainId,
        private_key: SecretString,
        signature_type: SignatureType,
        funder: Address,
        nonce: Option<u32>,
        policies: HotPathPolicies,
    ) -> Result<Self> {
        if chain_id != POLYGON {
            return Err(Error::validation(format!(
                "hotpath currently supports Polygon only, got chain_id={chain_id}"
            )));
        }
        if signature_type == SignatureType::Eoa {
            return Err(Error::validation(
                "hotpath config expects proxy signatures (Proxy/GnosisSafe), got Eoa",
            ));
        }
        if funder == Address::ZERO {
            return Err(Error::validation(
                "hotpath config requires non-zero funder for proxy signatures",
            ));
        }

        policies.validate()?;

        Ok(Self {
            host,
            chain_id,
            private_key,
            signature_type,
            funder,
            nonce,
            policies,
        })
    }
}
