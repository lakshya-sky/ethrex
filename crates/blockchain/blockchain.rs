pub mod constants;
pub mod error;
pub mod fork_choice;
pub mod mempool;
pub mod payload;
mod smoke_test;

use error::{ChainError, InvalidBlockError, MempoolError};
use ethrex_common::constants::GAS_PER_BLOB;
use ethrex_common::types::requests::{compute_requests_hash, EncodedRequests, Requests};
use ethrex_common::types::{
    compute_receipts_root, validate_block_header, validate_cancun_header_fields,
    validate_prague_header_fields, validate_pre_cancun_header_fields, BlobsBundle, Block,
    BlockHash, BlockHeader, BlockNumber, ChainConfig, EIP4844Transaction, MempoolTransaction,
    Receipt, Transaction, TxType,
};
use ethrex_common::{Address, H256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::{ops::Div, time::Instant};

use ethrex_storage::error::StoreError;
use ethrex_storage::Store;
use ethrex_vm::backends::BlockExecutionResult;
use ethrex_vm::backends::EVM;
use ethrex_vm::db::evm_state;
use fork_choice::apply_fork_choice;
use tracing::{error, info, warn};

//TODO: Implement a struct Chain or BlockChain to encapsulate
//functionality and canonical chain state and config

#[derive(Debug, Clone)]
pub struct Blockchain {
    pub vm: EVM,
    pub storage: Store,
    pub mempool: Arc<Mutex<HashMap<H256, MempoolTransaction>>>,
    pub blobs_bundle_pool: Arc<Mutex<HashMap<H256, BlobsBundle>>>,
}

impl Blockchain {
    pub fn new(evm: EVM, store: Store) -> Self {
        Self {
            vm: evm,
            storage: store,
            mempool: Arc::new(Mutex::new(HashMap::new())),
            blobs_bundle_pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn default_with_store(store: Store) -> Self {
        Self {
            vm: Default::default(),
            storage: store,
            mempool: Default::default(),
            blobs_bundle_pool: Default::default(),
        }
    }

    pub fn add_block(&self, block: &Block) -> Result<(), ChainError> {
        let since = Instant::now();

        let block_hash = block.header.compute_block_hash();

        // Validate if it can be the new head and find the parent
        let Ok(parent_header) = find_parent_header(&block.header, &self.storage) else {
            // If the parent is not present, we store it as pending.
            self.storage.add_pending_block(block.clone())?;
            return Err(ChainError::ParentNotFound);
        };
        let mut state = evm_state(self.storage.clone(), block.header.parent_hash);
        let chain_config = state.chain_config().map_err(ChainError::from)?;

        // Validate the block pre-execution
        validate_block(block, &parent_header, &chain_config)?;
        let BlockExecutionResult {
            receipts,
            requests,
            account_updates,
        } = self.vm.execute_block(block, &mut state)?;

        validate_gas_used(&receipts, &block.header)?;

        // Apply the account updates over the last block's state and compute the new state root
        let new_state_root = state
            .database()
            .ok_or(ChainError::StoreError(StoreError::MissingStore))?
            .apply_account_updates(block.header.parent_hash, &account_updates)?
            .ok_or(ChainError::ParentStateNotFound)?;

        // Check state root matches the one in block header after execution
        validate_state_root(&block.header, new_state_root)?;

        // Check receipts root matches the one in block header after execution
        validate_receipts_root(&block.header, &receipts)?;

        // Processes requests from receipts, computes the requests_hash and compares it against the header
        validate_requests_hash(&block.header, &chain_config, &requests)?;

        store_block(&self.storage, block.clone())?;
        store_receipts(&self.storage, receipts, block_hash)?;

        let interval = Instant::now().duration_since(since).as_millis();
        if interval != 0 {
            let as_gigas = (block.header.gas_used as f64).div(10_f64.powf(9_f64));
            let throughput = (as_gigas) / (interval as f64) * 1000_f64;
            info!("[METRIC] BLOCK EXECUTION THROUGHPUT: {throughput} Gigagas/s TIME SPENT: {interval} msecs");
        }

        Ok(())
    }

    //TODO: Forkchoice Update shouldn't be part of this function
    pub fn import_blocks(&self, blocks: &Vec<Block>) {
        let size = blocks.len();
        for block in blocks {
            let hash = block.hash();
            info!(
                "Adding block {} with hash {:#x}.",
                block.header.number, hash
            );
            if let Err(error) = self.add_block(block) {
                warn!(
                    "Failed to add block {} with hash {:#x}: {}.",
                    block.header.number, hash, error
                );
            }
            if self
                .storage
                .update_latest_block_number(block.header.number)
                .is_err()
            {
                error!("Fatal: added block {} but could not update the block number -- aborting block import", block.header.number);
                break;
            };
            if self
                .storage
                .set_canonical_block(block.header.number, hash)
                .is_err()
            {
                error!(
                    "Fatal: added block {} but could not set it as canonical -- aborting block import",
                    block.header.number
                );
                break;
            };
        }
        if let Some(last_block) = blocks.last() {
            let hash = last_block.hash();
            match self.vm {
                EVM::LEVM => {
                    // We are allowing this not to unwrap so that tests can run even if block execution results in the wrong root hash with LEVM.
                    let _ = apply_fork_choice(&self.storage, hash, hash, hash);
                }
                EVM::REVM => {
                    apply_fork_choice(&self.storage, hash, hash, hash).unwrap();
                }
            }
        }
        info!("Added {size} blocks to blockchain");
    }

    /// Add transaction to the pool
    pub fn add_transaction_to_pool(
        &self,
        hash: H256,
        transaction: MempoolTransaction,
    ) -> Result<(), MempoolError> {
        let mut mempool = self
            .mempool
            .lock()
            .map_err(|error| MempoolError::Custom(error.to_string()))?;
        mempool.insert(hash, transaction);

        Ok(())
    }

    /// Add a blobs bundle to the pool by its blob transaction hash
    pub fn add_blobs_bundle_to_pool(
        &self,
        tx_hash: H256,
        blobs_bundle: BlobsBundle,
    ) -> Result<(), MempoolError> {
        self.blobs_bundle_pool
            .lock()
            .map_err(|error| MempoolError::Custom(error.to_string()))?
            .insert(tx_hash, blobs_bundle);
        Ok(())
    }

    /// Get a blobs bundle to the pool given its blob transaction hash
    pub fn get_blobs_bundle_from_pool(
        &self,
        tx_hash: H256,
    ) -> Result<Option<BlobsBundle>, MempoolError> {
        Ok(self
            .blobs_bundle_pool
            .lock()
            .map_err(|error| MempoolError::Custom(error.to_string()))?
            .get(&tx_hash)
            .cloned())
    }

    /// Remove a transaction from the pool
    pub fn remove_transaction_from_pool(&self, hash: &H256) -> Result<(), MempoolError> {
        let mut mempool = self
            .mempool
            .lock()
            .map_err(|error| MempoolError::Custom(error.to_string()))?;
        if let Some(tx) = mempool.get(hash) {
            if matches!(tx.tx_type(), TxType::EIP4844) {
                self.blobs_bundle_pool
                    .lock()
                    .map_err(|error| MempoolError::Custom(error.to_string()))?
                    .remove(&tx.compute_hash());
            }

            mempool.remove(hash);
        };

        Ok(())
    }

    /// Applies the filter and returns a set of suitable transactions from the mempool.
    /// These transactions will be grouped by sender and sorted by nonce
    pub fn filter_pool_transactions(
        &self,
        filter: &dyn Fn(&Transaction) -> bool,
    ) -> Result<HashMap<Address, Vec<MempoolTransaction>>, MempoolError> {
        let mut txs_by_sender: HashMap<Address, Vec<MempoolTransaction>> = HashMap::new();
        let mempool = self
            .mempool
            .lock()
            .map_err(|error| MempoolError::Custom(error.to_string()))?;

        for (_, tx) in mempool.iter() {
            if filter(tx) {
                txs_by_sender
                    .entry(tx.sender())
                    .or_default()
                    .push(tx.clone())
            }
        }

        txs_by_sender.iter_mut().for_each(|(_, txs)| txs.sort());
        Ok(txs_by_sender)
    }

    /// Gets hashes from possible_hashes that are not already known in the mempool.
    pub fn filter_unknown_transactions(
        &self,
        possible_hashes: &[H256],
    ) -> Result<Vec<H256>, MempoolError> {
        let mempool = self
            .mempool
            .lock()
            .map_err(|error| MempoolError::Custom(error.to_string()))?;

        let tx_set: HashSet<_> = mempool.iter().map(|(hash, _)| hash).collect();
        Ok(possible_hashes
            .iter()
            .filter(|hash| !tx_set.contains(hash))
            .copied()
            .collect())
    }
}

pub fn validate_requests_hash(
    header: &BlockHeader,
    chain_config: &ChainConfig,
    requests: &[Requests],
) -> Result<(), ChainError> {
    if !chain_config.is_prague_activated(header.timestamp) {
        return Ok(());
    }

    let encoded_requests: Vec<EncodedRequests> = requests.iter().map(|r| r.encode()).collect();
    let computed_requests_hash = compute_requests_hash(&encoded_requests);
    let valid = header
        .requests_hash
        .map(|requests_hash| requests_hash == computed_requests_hash)
        .unwrap_or(false);

    if !valid {
        return Err(ChainError::InvalidBlock(
            InvalidBlockError::RequestsHashMismatch,
        ));
    }

    Ok(())
}

/// Stores block and header in the database
pub fn store_block(storage: &Store, block: Block) -> Result<(), ChainError> {
    storage.add_block(block)?;
    Ok(())
}

pub fn store_receipts(
    storage: &Store,
    receipts: Vec<Receipt>,
    block_hash: BlockHash,
) -> Result<(), ChainError> {
    storage.add_receipts(block_hash, receipts)?;
    Ok(())
}

/// Performs post-execution checks
pub fn validate_state_root(
    block_header: &BlockHeader,
    new_state_root: H256,
) -> Result<(), ChainError> {
    // Compare state root
    if new_state_root == block_header.state_root {
        Ok(())
    } else {
        Err(ChainError::InvalidBlock(
            InvalidBlockError::StateRootMismatch,
        ))
    }
}

pub fn validate_receipts_root(
    block_header: &BlockHeader,
    receipts: &[Receipt],
) -> Result<(), ChainError> {
    let receipts_root = compute_receipts_root(receipts);

    if receipts_root == block_header.receipts_root {
        Ok(())
    } else {
        Err(ChainError::InvalidBlock(
            InvalidBlockError::ReceiptsRootMismatch,
        ))
    }
}

// Returns the hash of the head of the canonical chain (the latest valid hash).
pub fn latest_canonical_block_hash(storage: &Store) -> Result<H256, ChainError> {
    let latest_block_number = storage.get_latest_block_number()?;
    if let Some(latest_valid_header) = storage.get_block_header(latest_block_number)? {
        let latest_valid_hash = latest_valid_header.compute_block_hash();
        return Ok(latest_valid_hash);
    }
    Err(ChainError::StoreError(StoreError::Custom(
        "Could not find latest valid hash".to_string(),
    )))
}

/// Validates if the provided block could be the new head of the chain, and returns the
/// parent_header in that case. If not found, the new block is saved as pending.
pub fn find_parent_header(
    block_header: &BlockHeader,
    storage: &Store,
) -> Result<BlockHeader, ChainError> {
    match storage.get_block_header_by_hash(block_header.parent_hash)? {
        Some(parent_header) => Ok(parent_header),
        None => Err(ChainError::ParentNotFound),
    }
}

/// Performs pre-execution validation of the block's header values in reference to the parent_header
/// Verifies that blob gas fields in the header are correct in reference to the block's body.
/// If a block passes this check, execution will still fail with execute_block when a transaction runs out of gas
pub fn validate_block(
    block: &Block,
    parent_header: &BlockHeader,
    chain_config: &ChainConfig,
) -> Result<(), ChainError> {
    // Verify initial header validity against parent
    validate_block_header(&block.header, parent_header).map_err(InvalidBlockError::from)?;

    if chain_config.is_prague_activated(block.header.timestamp) {
        validate_prague_header_fields(&block.header, parent_header)
            .map_err(InvalidBlockError::from)?;
        verify_blob_gas_usage(block, chain_config)?;
    } else if chain_config.is_cancun_activated(block.header.timestamp) {
        validate_cancun_header_fields(&block.header, parent_header)
            .map_err(InvalidBlockError::from)?;
        verify_blob_gas_usage(block, chain_config)?;
    } else {
        validate_pre_cancun_header_fields(&block.header).map_err(InvalidBlockError::from)?
    }

    Ok(())
}

pub fn is_canonical(
    store: &Store,
    block_number: BlockNumber,
    block_hash: BlockHash,
) -> Result<bool, StoreError> {
    match store.get_canonical_block_hash(block_number)? {
        Some(hash) if hash == block_hash => Ok(true),
        _ => Ok(false),
    }
}

pub fn validate_gas_used(
    receipts: &[Receipt],
    block_header: &BlockHeader,
) -> Result<(), ChainError> {
    if let Some(last) = receipts.last() {
        // Note: This is commented because it is still being used in development.
        // dbg!(last.cumulative_gas_used);
        // dbg!(block_header.gas_used);
        if last.cumulative_gas_used != block_header.gas_used {
            return Err(ChainError::InvalidBlock(InvalidBlockError::GasUsedMismatch));
        }
    }
    Ok(())
}

// Perform validations over the block's blob gas usage.
// Must be called only if the block has cancun activated
fn verify_blob_gas_usage(block: &Block, config: &ChainConfig) -> Result<(), ChainError> {
    let mut blob_gas_used = 0_u64;
    let mut blobs_in_block = 0_u64;
    let max_blob_number_per_block = config
        .get_fork_blob_schedule(block.header.timestamp)
        .map(|schedule| schedule.max)
        .ok_or(ChainError::Custom("Provided block fork is invalid".into()))?;
    let max_blob_gas_per_block = max_blob_number_per_block * GAS_PER_BLOB;

    for transaction in block.body.transactions.iter() {
        if let Transaction::EIP4844Transaction(tx) = transaction {
            blob_gas_used += get_total_blob_gas(tx);
            blobs_in_block += tx.blob_versioned_hashes.len() as u64;
        }
    }
    if blob_gas_used > max_blob_gas_per_block {
        return Err(ChainError::InvalidBlock(
            InvalidBlockError::ExceededMaxBlobGasPerBlock,
        ));
    }
    if blobs_in_block > max_blob_number_per_block {
        return Err(ChainError::InvalidBlock(
            InvalidBlockError::ExceededMaxBlobNumberPerBlock,
        ));
    }
    if block
        .header
        .blob_gas_used
        .is_some_and(|header_blob_gas_used| header_blob_gas_used != blob_gas_used)
    {
        return Err(ChainError::InvalidBlock(
            InvalidBlockError::BlobGasUsedMismatch,
        ));
    }
    Ok(())
}

/// Calculates the blob gas required by a transaction
fn get_total_blob_gas(tx: &EIP4844Transaction) -> u64 {
    GAS_PER_BLOB * tx.blob_versioned_hashes.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::types::BYTES_PER_BLOB;
    use ethrex_storage::EngineType;

    use hex_literal::hex;

    // Creates an empty store, runs the test and then removes the store (if needed)
    fn run_test(test_func: &dyn Fn(Blockchain)) {
        // Build a new store
        let store =
            Store::new("store-test-db", EngineType::InMemory).expect("Failed to create test db");
        let blockchain = Blockchain::default_with_store(store);
        // Run the test
        test_func(blockchain);
    }

    fn test_filter_mempool_transactions(blockchain: Blockchain) {
        let plain_tx_decoded = Transaction::decode_canonical(&hex!("f86d80843baa0c4082f618946177843db3138ae69679a54b95cf345ed759450d870aa87bee538000808360306ba0151ccc02146b9b11adf516e6787b59acae3e76544fdcd75e77e67c6b598ce65da064c5dd5aae2fbb535830ebbdad0234975cd7ece3562013b63ea18cc0df6c97d4")).unwrap();
        let plain_tx_sender = plain_tx_decoded.sender();
        let plain_tx = MempoolTransaction::new(plain_tx_decoded, plain_tx_sender);
        let blob_tx_decoded = Transaction::decode_canonical(&hex!("03f88f0780843b9aca008506fc23ac00830186a09400000000000000000000000000000000000001008080c001e1a0010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c44401401a0840650aa8f74d2b07f40067dc33b715078d73422f01da17abdbd11e02bbdfda9a04b2260f6022bf53eadb337b3e59514936f7317d872defb891a708ee279bdca90")).unwrap();
        let blob_tx_sender = blob_tx_decoded.sender();
        let blob_tx = MempoolTransaction::new(blob_tx_decoded, blob_tx_sender);
        let plain_tx_hash = plain_tx.compute_hash();
        let blob_tx_hash = blob_tx.compute_hash();
        let filter =
            |tx: &Transaction| -> bool { matches!(tx, Transaction::EIP4844Transaction(_)) };
        blockchain
            .add_transaction_to_pool(blob_tx_hash, blob_tx.clone())
            .unwrap();
        blockchain
            .add_transaction_to_pool(plain_tx_hash, plain_tx)
            .unwrap();
        let txs = blockchain.filter_pool_transactions(&filter).unwrap();
        assert_eq!(txs, HashMap::from([(blob_tx.sender(), vec![blob_tx])]));
    }

    fn blobs_bundle_loadtest(blockchain: Blockchain) {
        // Write a bundle of 6 blobs 10 times
        // If this test fails please adjust the max_size in the DB config
        for i in 0..300 {
            let blobs = [[i as u8; BYTES_PER_BLOB]; 6];
            let commitments = [[i as u8; 48]; 6];
            let proofs = [[i as u8; 48]; 6];
            let bundle = BlobsBundle {
                blobs: blobs.to_vec(),
                commitments: commitments.to_vec(),
                proofs: proofs.to_vec(),
            };
            blockchain
                .add_blobs_bundle_to_pool(H256::random(), bundle)
                .unwrap();
        }
    }
}
