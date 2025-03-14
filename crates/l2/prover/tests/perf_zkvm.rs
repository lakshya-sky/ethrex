#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
use ethrex_blockchain::Blockchain;
use ethrex_common::types::Block;
use std::path::Path;
use tracing::info;

use ethrex_prover_lib::prover::{Prover, Risc0Prover, Sp1Prover};
use ethrex_storage::{EngineType, Store};
use ethrex_vm::{backends::revm::execution_db::ToExecDB, db::StoreWrapper};
use zkvm_interface::io::ProgramInput;

#[tokio::test]
async fn test_performance_zkvm() {
    tracing_subscriber::fmt::init();

    let (input, block_to_prove) = setup().await;

    let mut prover = Risc0Prover::new();

    let start = std::time::Instant::now();

    let receipt = prover.prove(input).unwrap();

    let duration = start.elapsed();
    info!(
        "Number of EIP1559 transactions in the proven block: {}",
        block_to_prove.body.transactions.len()
    );
    info!("[SECONDS] Proving Took: {:?}", duration);
    info!("[MINUTES] Proving Took: {}[m]", duration.as_secs() / 60);

    prover.verify(&receipt).unwrap();

    let _program_output = prover.get_commitment(&receipt).unwrap();
}

#[tokio::test]
async fn test_performance_sp1_zkvm() {
    tracing_subscriber::fmt::init();

    let (input, block_to_prove) = setup().await;

    let mut prover = Sp1Prover::new();

    let start = std::time::Instant::now();

    let output = prover.prove(input).unwrap();

    let duration = start.elapsed();
    info!(
        "Number of EIP1559 transactions in the proven block: {}",
        block_to_prove.body.transactions.len()
    );
    info!("[SECONDS] Proving Took: {:?}", duration);
    info!("[MINUTES] Proving Took: {}[m]", duration.as_secs() / 60);

    prover.verify(&output).unwrap();
}

async fn setup() -> (ProgramInput, Block) {
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test_data"));

    let genesis_file_path = path.join("genesis-l2-ci.json");
    // l2-loadtest.rlp has blocks with many txs.
    let chain_file_path = path.join("l2-loadtest.rlp");

    let store = Store::new("memory", EngineType::InMemory).expect("Failed to create Store");

    let genesis =
        ethrex_l2::utils::test_data_io::read_genesis_file(genesis_file_path.to_str().unwrap());
    store.add_initial_state(genesis.clone()).unwrap();

    let blocks = ethrex_l2::utils::test_data_io::read_chain_file(chain_file_path.to_str().unwrap());
    info!("Number of blocks to insert: {}", blocks.len());

    let blockchain = Blockchain::default_with_store(store.clone());
    for block in &blocks {
        info!(
            "txs {} in block{}",
            block.body.transactions.len(),
            block.header.number
        );
        blockchain.add_block(block).unwrap();
    }
    let block_to_prove = blocks.get(3).unwrap();

    let parent_block_header = store
        .get_block_header_by_hash(block_to_prove.header.parent_hash)
        .unwrap()
        .unwrap();

    let store = StoreWrapper {
        store: store.clone(),
        block_hash: block_to_prove.header.parent_hash,
    };
    let db = store.to_exec_db(block_to_prove).unwrap();

    let input = ProgramInput {
        block: block_to_prove.clone(),
        parent_block_header,
        db,
    };
    (input, block_to_prove.clone())
}
