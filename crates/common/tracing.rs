use std::collections::HashMap;

use bytes::Bytes;
use ethereum_types::H256;
use ethereum_types::{Address, U256};
use serde::{Deserialize, Serialize};

/// Collection of traces of each call frame as defined in geth's `callTracer` output
/// https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers#call-tracer
pub type CallTrace = Vec<CallTraceFrame>;

/// Trace of each call frame as defined in geth's `callTracer` output
/// https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers#call-tracer
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CallTraceFrame {
    /// Type of the Call
    #[serde(rename = "type")]
    pub call_type: CallType,
    /// Address that initiated the call
    pub from: Address,
    /// Address that received the call
    #[serde(skip_serializing_if = "Address::is_zero")]
    pub to: Address,
    /// Amount transfered
    pub value: U256,
    /// Gas provided for the call
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub gas: u64,
    /// Gas used by the call
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub gas_used: u64,
    /// Call data
    #[serde(with = "crate::serde_utils::bytes")]
    pub input: Bytes,
    /// Return data
    #[serde(
        with = "crate::serde_utils::bytes",
        skip_serializing_if = "Bytes::is_empty"
    )]
    pub output: Bytes,
    /// Error returned if the call failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Revert reason if the call reverted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    /// List of nested sub-calls
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<CallTraceFrame>,
    /// Logs (if enabled)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<CallLog>,
}

#[derive(Serialize, Debug, Default)]
pub enum CallType {
    #[default]
    CALL,
    CALLCODE,
    STATICCALL,
    DELEGATECALL,
    CREATE,
    CREATE2,
    SELFDESTRUCT,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CallLog {
    pub address: Address,
    pub topics: Vec<H256>,
    #[serde(with = "crate::serde_utils::bytes")]
    pub data: Bytes,
    #[serde(with = "crate::serde_utils::u64::hex_str")]
    pub position: u64,
}

/// Account state captured by the prestate tracer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrestateAccount {
    /// Account balance (omitted if zero and account doesn't exist)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "u256_hex_option")]
    pub balance: Option<U256>,

    /// Account nonce (omitted if zero)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,

    /// Account bytecode (omitted if empty or if disabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "bytes_hex_option")]
    pub code: Option<Bytes>,

    /// Account bytecode hash (omitted if empty or if disabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<H256>,

    /// Storage slots that were accessed (omitted if empty or if disabled)
    #[serde(
        skip_serializing_if = "storage_is_none_or_empty",
        with = "crate::serde_utils::hashmap_h256_u256::hex_str_opt"
    )]
    pub storage: Option<HashMap<H256, U256>>,
}

/// Helper function for serde to skip serializing storage when None or empty.
fn storage_is_none_or_empty(storage: &Option<HashMap<H256, U256>>) -> bool {
    match storage {
        None => true,
        Some(map) => map.is_empty(),
    }
}

impl PrestateAccount {
    /// Returns true if the account exists (has non-zero balance, nonce, or code).
    pub fn exists(&self) -> bool {
        let has_balance = self.balance.map(|b| b != U256::zero()).unwrap_or(false);
        let has_nonce = self.nonce.map(|n| n > 0).unwrap_or(false);
        let has_code = self.code.as_ref().map(|c| !c.is_empty()).unwrap_or(false);
        let has_storage = self
            .storage
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        has_balance || has_nonce || has_code || has_storage
    }

    /// Returns true if the account is considered empty (for cleanup purposes).
    pub fn is_empty(&self) -> bool {
        !self.exists()
    }
}

/// Configuration for the prestate tracer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrestateTracerConfig {
    /// If true, return both pre-state and post-state (showing modifications).
    #[serde(default)]
    pub diff_mode: bool,

    /// If true, do not return contract code.
    #[serde(default)]
    pub disable_code: bool,

    /// If true, do not return storage.
    #[serde(default)]
    pub disable_storage: bool,

    /// If true, include empty accounts in the result.
    #[serde(default)]
    pub include_empty: bool,
}

/// The result of prestate tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrestateTracerResult {
    /// Default mode: only pre-state.
    Default(HashMap<Address, PrestateAccount>),
    /// Diff mode: both pre-state and post-state.
    Diff {
        pre: HashMap<Address, PrestateAccount>,
        post: HashMap<Address, PrestateAccount>,
    },
}

/// Helper module for serializing Option<U256> as hex.
mod u256_hex_option {
    use crate::U256;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<U256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => {
                let hex = format!("{v:#x}");
                hex.serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.trim_start_matches("0x");
                U256::from_str_radix(s, 16)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
            None => Ok(None),
        }
    }
}

/// Helper module for serializing Option<Bytes> as hex.
mod bytes_hex_option {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Convert bytes to hex string
    fn bytes_to_hex(bytes: &[u8]) -> String {
        #[allow(clippy::arithmetic_side_effects)]
        let capacity = 2usize.saturating_add(bytes.len().saturating_mul(2));
        let mut hex_string = String::with_capacity(capacity);
        hex_string.push_str("0x");
        for byte in bytes {
            hex_string.push_str(&format!("{byte:02x}"));
        }
        hex_string
    }

    /// Parse hex string to bytes
    fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
        let s = s.trim_start_matches("0x");
        if !s.len().is_multiple_of(2) {
            return Err("Invalid hex string length".to_string());
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        let mut chars = s.chars();
        while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
            let high = h
                .to_digit(16)
                .ok_or_else(|| format!("Invalid hex char: {h}"))?;
            let low = l
                .to_digit(16)
                .ok_or_else(|| format!("Invalid hex char: {l}"))?;
            #[allow(clippy::as_conversions, clippy::arithmetic_side_effects)]
            bytes.push((high * 16 + low) as u8);
        }
        Ok(bytes)
    }

    pub fn serialize<S>(value: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => {
                let hex = bytes_to_hex(v);
                hex.serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => hex_to_bytes(&s)
                .map(|v| Some(Bytes::from(v)))
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
