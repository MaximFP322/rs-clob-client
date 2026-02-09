use std::borrow::Cow;
use std::str::FromStr as _;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::dyn_abi::Eip712Domain;
use alloy::primitives::U256;
use alloy::signers::Signer as _;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolStruct as _;
use chrono::{DateTime, Utc};
use rand::Rng as _;
use reqwest::Client as ReqwestClient;
use reqwest::Method;
use rust_decimal::prelude::ToPrimitive as _;
use secrecy::ExposeSecret as _;
use url::Url;

use crate::auth;
use crate::auth::state::Authenticated;
use crate::auth::{Credentials, Normal};
use crate::clob::types::response::PostOrderResponse;
use crate::clob::types::{Order, OrderType, Side, SignatureType, SignedOrder};
use crate::contract_config;
use crate::error::{Error, Kind as ErrorKind};
use crate::hotpath::{
    HotPathConfig, HotPathPolicies, LimitOrderOverrides, LimitOrderRequest, TimePolicy,
};
use crate::types::{Address, ChainId, Decimal};
use crate::{Result, Timestamp};

const ORDER_NAME: Option<Cow<'static, str>> = Some(Cow::Borrowed("Polymarket CTF Exchange"));
const VERSION: Option<Cow<'static, str>> = Some(Cow::Borrowed("1"));

const USDC_DECIMALS: u32 = 6;
const LOT_SIZE_SCALE: u32 = 2;

/// High-throughput client optimized for limit `POST /order`.
#[derive(Clone, Debug)]
pub struct HotPathClient {
    host: Url,
    chain_id: ChainId,
    nonce: Option<u32>,
    signer: PrivateKeySigner,
    signature_type: SignatureType,
    funder: Address,
    policies: HotPathPolicies,
    credentials: Credentials,
    state: Authenticated<Normal>,
    client: ReqwestClient,
}

impl HotPathClient {
    /// Creates a new hot-path client and bootstraps credentials with L1 auth.
    pub async fn bootstrap(config: HotPathConfig) -> Result<Self> {
        Self::bootstrap_with_client(config, ReqwestClient::new()).await
    }

    /// Creates a new hot-path client and bootstraps credentials with a custom HTTP client.
    pub async fn bootstrap_with_client(
        config: HotPathConfig,
        client: ReqwestClient,
    ) -> Result<Self> {
        let signer = Self::signer_from_config(&config)?;
        let credentials = Self::create_or_derive_api_key(
            &client,
            &config.host,
            &signer,
            config.chain_id,
            config.nonce,
            config.policies.time,
        )
        .await?;

        Self::with_credentials_inner(config, signer, credentials, client)
    }

    /// Creates a hot-path client from already known credentials.
    pub fn with_credentials(config: HotPathConfig, credentials: Credentials) -> Result<Self> {
        Self::with_credentials_and_client(config, credentials, ReqwestClient::new())
    }

    /// Creates a hot-path client from already known credentials and a custom HTTP client.
    pub fn with_credentials_and_client(
        config: HotPathConfig,
        credentials: Credentials,
        client: ReqwestClient,
    ) -> Result<Self> {
        let signer = Self::signer_from_config(&config)?;
        Self::with_credentials_inner(config, signer, credentials, client)
    }

    fn with_credentials_inner(
        config: HotPathConfig,
        signer: PrivateKeySigner,
        credentials: Credentials,
        client: ReqwestClient,
    ) -> Result<Self> {
        Self::validate_funder_signature(config.signature_type, config.funder)?;

        let state = Authenticated {
            address: signer.address(),
            credentials: credentials.clone(),
            kind: Normal,
        };

        Ok(Self {
            host: config.host,
            chain_id: config.chain_id,
            nonce: config.nonce,
            signer,
            signature_type: config.signature_type,
            funder: config.funder,
            policies: config.policies,
            credentials,
            state,
            client,
        })
    }

    fn signer_from_config(config: &HotPathConfig) -> Result<PrivateKeySigner> {
        PrivateKeySigner::from_str(config.private_key.expose_secret())
            .map_err(|e| Error::validation(format!("invalid private key: {e}")))
            .map(|signer| signer.with_chain_id(Some(config.chain_id)))
    }

    #[must_use]
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    #[must_use]
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Recreates or derives API credentials and updates internal L2 auth state.
    ///
    /// Intended for recovery flow after `401/403` responses.
    pub async fn refresh_credentials(&mut self) -> Result<&Credentials> {
        let credentials = Self::create_or_derive_api_key(
            &self.client,
            &self.host,
            &self.signer,
            self.chain_id,
            self.nonce,
            self.policies.time,
        )
        .await?;

        self.state.credentials = credentials.clone();
        self.credentials = credentials;
        Ok(&self.credentials)
    }

    /// Signs and submits a limit order with default fixed policies.
    pub async fn post_limit_order(&self, request: &LimitOrderRequest) -> Result<PostOrderResponse> {
        self.post_limit_order_with_overrides(request, LimitOrderOverrides::default())
            .await
    }

    /// Signs and submits a limit order with per-order overrides.
    ///
    /// If an override is not provided, default fixed policy values are used.
    pub async fn post_limit_order_with_overrides(
        &self,
        request: &LimitOrderRequest,
        overrides: LimitOrderOverrides,
    ) -> Result<PostOrderResponse> {
        let signed = self.sign_limit_order(request, overrides).await?;
        self.post_signed_order(signed, overrides.timestamp).await
    }

    /// Builds and signs a limit order.
    pub async fn sign_limit_order(
        &self,
        request: &LimitOrderRequest,
        overrides: LimitOrderOverrides,
    ) -> Result<SignedOrder> {
        let tick_size = overrides
            .tick_size
            .map_or_else(|| self.policies.default_tick_size(), Ok)?;
        let neg_risk = overrides
            .neg_risk
            .map_or_else(|| self.policies.default_neg_risk(), Ok)?;
        let fee_rate_bps = overrides
            .fee_rate_bps
            .map_or_else(|| self.policies.default_fee_rate_bps(), Ok)?;

        let order_type = request.order_type.clone().unwrap_or(OrderType::GTC);
        let expiration = request.expiration.unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
        let nonce = request.nonce.unwrap_or(0);
        let taker = request.taker.unwrap_or(Address::ZERO);
        let post_only = request.post_only.unwrap_or(false);

        if !matches!(order_type, OrderType::GTD) && expiration > DateTime::<Utc>::UNIX_EPOCH {
            return Err(Error::validation(
                "Only GTD orders may have a non-zero expiration",
            ));
        }
        if post_only && !matches!(order_type, OrderType::GTC | OrderType::GTD) {
            return Err(Error::validation(
                "postOnly is only supported for GTC and GTD orders",
            ));
        }

        let price = request.price;
        let size = request.size;
        let side = request.side;

        if price.is_sign_negative() {
            return Err(Error::validation(format!(
                "Unable to build Order due to negative price {price}"
            )));
        }
        if size.is_zero() || size.is_sign_negative() {
            return Err(Error::validation(format!(
                "Unable to build Order due to negative size {size}"
            )));
        }
        if size.scale() > LOT_SIZE_SCALE {
            return Err(Error::validation(format!(
                "Unable to build Order: Size {size} has {} decimal places. Maximum lot size is {LOT_SIZE_SCALE}",
                size.scale()
            )));
        }

        let minimum_tick_size = tick_size.as_decimal();
        let decimals = minimum_tick_size.scale();

        if price.scale() > minimum_tick_size.scale() {
            return Err(Error::validation(format!(
                "Unable to build Order: Price {price} has {} decimal places. Minimum tick size \
                {minimum_tick_size} has {} decimal places. Price decimal places <= minimum tick size decimal places",
                price.scale(),
                minimum_tick_size.scale()
            )));
        }
        if price < minimum_tick_size || price > Decimal::ONE - minimum_tick_size {
            return Err(Error::validation(format!(
                "Price {price} is too small or too large for the minimum tick size {minimum_tick_size}"
            )));
        }

        let (taker_amount, maker_amount) = match side {
            Side::Buy => (
                size,
                (size * price).trunc_with_scale(decimals + LOT_SIZE_SCALE),
            ),
            Side::Sell => (
                (size * price).trunc_with_scale(decimals + LOT_SIZE_SCALE),
                size,
            ),
            other => return Err(Error::validation(format!("Invalid side: {other}"))),
        };

        let expiration_u64 = expiration
            .timestamp()
            .to_u64()
            .ok_or(Error::validation(format!(
                "Unable to represent expiration {expiration} as a u64"
            )))?;

        let order = Order {
            salt: U256::from(to_ieee_754_int(generate_seed())),
            maker: self.funder,
            signer: self.address(),
            taker,
            tokenId: request.token_id,
            makerAmount: U256::from(to_fixed_u128(maker_amount)?),
            takerAmount: U256::from(to_fixed_u128(taker_amount)?),
            expiration: U256::from(expiration_u64),
            nonce: U256::from(nonce),
            feeRateBps: U256::from(fee_rate_bps),
            side: side as u8,
            signatureType: self.signature_type as u8,
        };

        let exchange_contract = contract_config(self.chain_id, neg_risk)
            .ok_or(Error::missing_contract_config(self.chain_id, neg_risk))?
            .exchange;
        let domain = Eip712Domain {
            name: ORDER_NAME,
            version: VERSION,
            chain_id: Some(U256::from(self.chain_id)),
            verifying_contract: Some(exchange_contract),
            ..Eip712Domain::default()
        };
        let signature = self
            .signer
            .sign_hash(&order.eip712_signing_hash(&domain))
            .await?;

        Ok(SignedOrder {
            order,
            signature,
            order_type,
            owner: self.credentials.key(),
            post_only: Some(post_only),
        })
    }

    /// Posts an already-signed order to `/order`.
    pub async fn post_signed_order(
        &self,
        signed_order: SignedOrder,
        timestamp_override: Option<Timestamp>,
    ) -> Result<PostOrderResponse> {
        let request = self
            .client
            .request(Method::POST, self.endpoint("order")?)
            .json(&signed_order)
            .build()?;
        let headers = self.create_l2_headers(&request, timestamp_override).await?;

        crate::request::<PostOrderResponse>(&self.client, request, Some(headers)).await
    }

    async fn create_or_derive_api_key(
        client: &ReqwestClient,
        host: &Url,
        signer: &PrivateKeySigner,
        chain_id: ChainId,
        nonce: Option<u32>,
        time_policy: TimePolicy,
    ) -> Result<Credentials> {
        match Self::create_api_key(client, host, signer, chain_id, nonce, time_policy).await {
            Ok(creds) => Ok(creds),
            Err(err) if err.kind() == ErrorKind::Status => {
                Self::derive_api_key(client, host, signer, chain_id, nonce, time_policy).await
            }
            Err(err) => Err(err),
        }
    }

    async fn create_api_key(
        client: &ReqwestClient,
        host: &Url,
        signer: &PrivateKeySigner,
        chain_id: ChainId,
        nonce: Option<u32>,
        time_policy: TimePolicy,
    ) -> Result<Credentials> {
        let request = client
            .request(Method::POST, host.join("auth/api-key")?)
            .build()?;
        let headers =
            Self::create_l1_headers(signer, chain_id, nonce, time_policy, host, client).await?;

        crate::request::<Credentials>(client, request, Some(headers)).await
    }

    async fn derive_api_key(
        client: &ReqwestClient,
        host: &Url,
        signer: &PrivateKeySigner,
        chain_id: ChainId,
        nonce: Option<u32>,
        time_policy: TimePolicy,
    ) -> Result<Credentials> {
        let request = client
            .request(Method::GET, host.join("auth/derive-api-key")?)
            .build()?;
        let headers =
            Self::create_l1_headers(signer, chain_id, nonce, time_policy, host, client).await?;

        crate::request::<Credentials>(client, request, Some(headers)).await
    }

    async fn create_l1_headers(
        signer: &PrivateKeySigner,
        chain_id: ChainId,
        nonce: Option<u32>,
        time_policy: TimePolicy,
        _host: &Url,
        _client: &ReqwestClient,
    ) -> Result<reqwest::header::HeaderMap> {
        let timestamp = resolve_timestamp(time_policy, None)?;
        auth::l1::create_headers(signer, chain_id, timestamp, nonce).await
    }

    async fn create_l2_headers(
        &self,
        request: &reqwest::Request,
        timestamp_override: Option<Timestamp>,
    ) -> Result<reqwest::header::HeaderMap> {
        let timestamp = resolve_timestamp(self.policies.time, timestamp_override)?;
        auth::l2::create_headers(&self.state, request, timestamp).await
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        Ok(self.host.join(path)?)
    }

    fn validate_funder_signature(signature_type: SignatureType, funder: Address) -> Result<()> {
        if matches!(signature_type, SignatureType::Eoa) {
            return Err(Error::validation(
                "Cannot have a funder address with an Eoa signature type",
            ));
        }
        if funder == Address::ZERO {
            return Err(Error::validation(
                "Cannot have a zero funder address with a proxy signature type",
            ));
        }
        Ok(())
    }
}

fn resolve_timestamp(
    policy: TimePolicy,
    override_timestamp: Option<Timestamp>,
) -> Result<Timestamp> {
    if let Some(ts) = override_timestamp {
        return Ok(ts);
    }

    match policy {
        TimePolicy::Fixed => Ok(Utc::now().timestamp()),
        TimePolicy::FetchAndCache => Err(Error::validation(
            "time policy FetchAndCache is not implemented in hotpath yet",
        )),
    }
}

/// Removes trailing zeros, truncates to 6 decimals, and quantizes as integer.
fn to_fixed_u128(d: Decimal) -> Result<u128> {
    if d.is_sign_negative() {
        return Err(Error::validation(format!("amount cannot be negative: {d}")));
    }

    d.normalize()
        .trunc_with_scale(USDC_DECIMALS)
        .mantissa()
        .to_u128()
        .ok_or(Error::validation(format!(
            "unable to represent amount as u128: {d}"
        )))
}

/// Mask salt to <= 2^53 - 1 because backend parses as IEEE 754.
fn to_ieee_754_int(salt: u64) -> u64 {
    salt & ((1 << 53) - 1)
}

fn generate_seed() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards");
    let seconds = now.as_secs_f64();
    let random = rand::rng().random::<f64>();
    (seconds * random).round() as u64
}
