//! Prestate Tracer implementation for ethrex.
//!
//! This tracer captures the pre-execution state of all accounts that were accessed during
//! transaction execution. Similar to geth's `prestateTracer`, it records account balances,
//! nonces, code, and storage slots that were read or written during execution.
//!
//! The tracer supports two modes:
//! - Default mode: Returns only the pre-state (state before transaction execution)
//! - Diff mode: Returns both pre-state and post-state (showing what changed)

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use ::tracing::error;

use bytes::Bytes;
use ethrex_common::evm::calculate_create_address;
use ethrex_common::tracing::{PrestateAccount, PrestateTracerConfig, PrestateTracerResult};
use ethrex_common::types::{Log, TxKind};
use ethrex_common::{Address, H256, U256, tracing::CallType};

use crate::Environment;
use crate::db::gen_db::GeneralizedDatabase;
use crate::errors::InternalError;
use crate::opcodes::Opcode;

use super::Tracer;

/// State map type alias.
pub type StateMap = HashMap<Address, PrestateAccount>;

/// Prestate tracer that captures account state before and after transaction execution.
///
/// Unlike geth's tracer which has direct state access during execution, this tracer
/// tracks which addresses/slots are accessed and then populates the state afterward
/// using closures provided at finalization time.
pub struct PrestateTracer {
    /// Configuration for the tracer.
    config: PrestateTracerConfig,

    /// Pre-execution state of accessed accounts.
    pre: StateMap,

    /// Post-execution state of modified accounts (only populated in diff mode).
    post: StateMap,

    /// Addresses of contracts created during execution.
    created: HashSet<Address>,

    /// Addresses of contracts that called SELFDESTRUCT.
    deleted: HashSet<Address>,

    /// Atomic flag to signal execution interruption.
    interrupt: AtomicBool,

    /// Tracks which addresses were accessed during execution.
    tracked_addresses: HashSet<Address>,

    /// Tracks which storage slots were accessed per address.
    tracked_storage: HashMap<Address, HashSet<H256>>,

    /// Marks accounts that were empty at lookup time (for filtering).
    empty_accounts: HashSet<Address>,
}

impl Default for PrestateTracer {
    fn default() -> Self {
        Self::new(PrestateTracerConfig::default())
    }
}

impl PrestateTracer {
    /// Creates a new prestate tracer with the given configuration.
    pub fn new(config: PrestateTracerConfig) -> Self {
        Self {
            config,
            pre: HashMap::new(),
            post: HashMap::new(),
            created: HashSet::new(),
            deleted: HashSet::new(),
            interrupt: AtomicBool::new(false),
            tracked_addresses: HashSet::new(),
            tracked_storage: HashMap::new(),
            empty_accounts: HashSet::new(),
        }
    }

    /// Fetches details of an account and stores it in prestate if it doesn't exists already
    pub fn lookup_account(&mut self, address: Address, db: &mut GeneralizedDatabase) {
        match self.pre.entry(address) {
            Entry::Occupied(occupied_entry) => (),
            Entry::Vacant(vacant_entry) => {
                let Ok(account) = db
                    .get_account(address)
                    .inspect_err(|e| error!("Failed to get account: {}\n", e))
                    .cloned()
                else {
                    return;
                };
                let balance = account.info.balance;
                let nonce = account.info.nonce;
                let code = if self.config.disable_code {
                    None
                } else {
                    db.get_code(account.info.code_hash)
                        .inspect_err(|e| error!("Failed to get code: {}\n", e))
                        .ok()
                        .and_then(|c| {
                            if c.bytecode.is_empty() {
                                None
                            } else {
                                Some(c.clone())
                            }
                        })
                };
                let storage = if self.config.disable_storage {
                    None
                } else {
                    Some(HashMap::new())
                };

                let prestate_account = PrestateAccount {
                    balance: if balance.is_zero() {
                        None
                    } else {
                        Some(balance)
                    },
                    nonce: if nonce == 0 { None } else { Some(nonce) },
                    code_hash: code.as_ref().map(|c| c.hash),
                    code: code.map(|c| c.bytecode),
                    storage,
                };
                // Track if account was empty at lookup time (before storage was added)
                if !prestate_account.exists() {
                    self.empty_accounts.insert(address);
                }

                self.pre.insert(address, prestate_account);
            }
        }
    }

    /// Processes the diff state after transaction execution.
    fn process_diff_state(&mut self, db: &mut GeneralizedDatabase) {
        let addresses: Vec<Address> = self.pre.keys().cloned().collect();
        let mut slots_to_remove: HashMap<Address, Vec<H256>> = HashMap::new();
        let mut addrs_to_remove: Vec<Address> = Vec::new();

        for addr in &addresses {
            // Deleted accounts stay in pre but not post (like geth)
            if self.deleted.contains(addr) {
                continue;
            }

            let mut modified = false;
            let mut post_account = PrestateAccount::default();
            let acc = db.get_account(*addr).cloned().unwrap_or_default();

            let new_balance = acc.info.balance;
            let new_nonce = acc.info.nonce;

            let (old_balance, old_nonce, old_code, old_code_hash, pre_storage) =
                if let Some(pre_account) = self.pre.get(addr) {
                    (
                        pre_account.balance,
                        pre_account.nonce.unwrap_or(0),
                        pre_account.code.as_ref().cloned().unwrap_or_default(),
                        pre_account.code_hash.as_ref().cloned().unwrap_or_default(),
                        pre_account.storage.clone(),
                    )
                } else {
                    continue;
                };

            // Check balance change
            if old_balance != Some(new_balance) {
                modified = true;
                post_account.balance = if new_balance.is_zero() {
                    None
                } else {
                    Some(new_balance)
                };
            }

            // Check nonce change
            if old_nonce != new_nonce {
                modified = true;
                post_account.nonce = if new_nonce > 0 { Some(new_nonce) } else { None };
            }

            // Check code change
            if !self.config.disable_code {
                let new_code = db.get_code(acc.info.code_hash).cloned().unwrap_or_default();
                if old_code_hash != new_code.hash {
                    modified = true;
                    post_account.code_hash = if new_code.bytecode.is_empty() {
                        None
                    } else {
                        Some(new_code.hash)
                    };
                    post_account.code = if new_code.bytecode.is_empty() {
                        None
                    } else {
                        Some(new_code.bytecode)
                    };
                }
            }

            // Check storage changes
            if !self.config.disable_storage
                && let Some(ref pre_storage) = pre_storage
            {
                let mut post_storage = HashMap::new();
                let mut remove_slots = Vec::new();

                for (slot, old_value) in pre_storage {
                    let new_value = db.get_storage_value(*addr, *slot).unwrap_or_default();

                    // Remove empty slots from pre
                    if *old_value == U256::zero() {
                        remove_slots.push(*slot);
                    }

                    if *old_value != new_value {
                        modified = true;
                        // Only include non-zero values in post
                        if new_value != U256::zero() {
                            post_storage.insert(*slot, new_value);
                        }
                    } else {
                        // Remove unchanged slots from pre
                        remove_slots.push(*slot);
                    }
                }

                if !remove_slots.is_empty() {
                    slots_to_remove.insert(*addr, remove_slots);
                }

                if !post_storage.is_empty() {
                    post_account.storage = Some(post_storage);
                }
            }

            if modified {
                self.post.insert(*addr, post_account);
            } else {
                // If state is not modified, no need to include in pre
                addrs_to_remove.push(*addr);
            }
        }

        // Apply slot removals from pre
        for (addr, slots) in slots_to_remove {
            if let Some(pre_acc) = self.pre.get_mut(&addr)
                && let Some(ref mut s) = pre_acc.storage
            {
                for slot in slots {
                    s.remove(&slot);
                }
            }
        }

        // Apply address removals from pre
        for addr in addrs_to_remove {
            self.pre.remove(&addr);
        }
    }

    /// Finalizes the tracer and returns the result.
    pub fn get_result(&self) -> Result<PrestateTracerResult, String> {
        if self.config.diff_mode {
            Ok(PrestateTracerResult::Diff {
                pre: self.pre.clone(),
                post: self.post.clone(),
            })
        } else {
            Ok(PrestateTracerResult::Default(self.pre.clone()))
        }
    }

    /// Clears the tracer state for reuse.
    pub fn clear(&mut self) {
        self.pre.clear();
        self.post.clear();
        self.created.clear();
        self.deleted.clear();
        self.interrupt.store(false, Ordering::SeqCst);
        self.tracked_addresses.clear();
        self.tracked_storage.clear();
        self.empty_accounts.clear();
    }
}

impl Tracer for PrestateTracer {
    fn enter(
        &mut self,
        _call_type: CallType,
        from: Address,
        to: Address,
        _value: U256,
        _gas: u64,
        _input: &Bytes,
    ) {
    }

    fn log(&mut self, _log: &Log) -> Result<(), InternalError> {
        Ok(())
    }

    fn on_opcode(
        &mut self,
        _opcode: Opcode,
        _current_address: Address,
        _stack: &[U256],
        _db: &mut GeneralizedDatabase,
    ) -> bool {
        true
    }

    fn on_storage_access(&mut self, address: Address, slot: H256, db: &mut GeneralizedDatabase) {
        if self.config.disable_storage {
            return;
        }
        if let Some(storage) = self.pre.get_mut(&address).and_then(|a| a.storage.as_mut()) {
            storage.entry(slot).or_insert(
                db.get_storage_value(address, slot)
                    .inspect_err(|e| error!("Failed to get storage value: {}", e))
                    .unwrap_or_default(),
            );
        }
    }

    fn on_account_access(&mut self, address: Address, db: &mut GeneralizedDatabase) {
        self.lookup_account(address, db);
    }

    fn on_create(&mut self, address: Address, _db: &mut GeneralizedDatabase) {
        self.created.insert(address);
    }

    fn on_selfdestruct(&mut self, address: Address, _db: &mut GeneralizedDatabase) {
        self.deleted.insert(address);
    }

    fn txn_start(
        &mut self,
        env: &Environment,
        tx: &ethrex_common::types::Transaction,
        from: Address,
        db: &mut GeneralizedDatabase,
    ) {
        self.lookup_account(from, db);

        let to = match tx.to() {
            TxKind::Call(address_to) => Some(address_to),
            TxKind::Create => db
                .get_account(from)
                .inspect_err(|e| error!("Failed to get account: {}\n", e))
                .ok()
                .map(|a| {
                    let addr = calculate_create_address(from, a.info.nonce);
                    self.created.insert(addr);
                    addr
                }),
        };
        if let Some(to) = to {
            self.lookup_account(to, db);
        }

        self.lookup_account(env.coinbase, db);

        if let Some(authorization_list) = tx.authorization_list() {
            for authorization in authorization_list {
                if let Ok(auth_addr) = authorization.authority() {
                    self.lookup_account(auth_addr, db)
                }
            }
        }
    }

    fn txn_end(&mut self, gas_used: u64, err: Option<String>, db: &mut GeneralizedDatabase) {
        if err.is_some() {
            return;
        }
        if self.config.diff_mode {
            // Populate prestate from the database's initial account state
            // The initial_accounts_state contains the state before transaction execution
            self.process_diff_state(db);
        }
        // Remove empty accounts unless include_empty is set
        if !self.config.include_empty {
            let empty: Vec<Address> = self
                .pre
                .iter()
                .filter(|(addr, acc)| self.empty_accounts.contains(addr) || acc.is_empty())
                .map(|(addr, _)| *addr)
                .collect();
            for addr in empty {
                self.pre.remove(&addr);
            }
        }
    }
}
