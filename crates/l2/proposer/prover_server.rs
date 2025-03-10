use crate::proposer::errors::{ProverServerError, SigIntError};
use crate::utils::{
    config::{
        committer::CommitterConfig, errors::ConfigError, eth::EthConfig,
        prover_server::ProverServerConfig,
    },
    prover::{
        errors::SaveStateError,
        proving_systems::{ProverType, ProvingOutput},
        save_state::{StateFileType, StateType, *},
    },
};
use ethrex_common::{
    types::{Block, BlockHeader},
    Address, H256, U256,
};
use ethrex_l2_sdk::calldata::{encode_calldata, Value};
use ethrex_rpc::clients::eth::{eth_sender::Overrides, EthClient, WrappedTransaction};
use ethrex_storage::Store;
use ethrex_vm::{
    backends::revm::execution_db::{ExecutionDB, ToExecDB},
    db::StoreWrapper,
    EvmError,
};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    io::{BufReader, BufWriter, Write},
    net::{IpAddr, Shutdown, TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};
use tokio::{
    signal::unix::{signal, SignalKind},
    time::sleep,
};
use tracing::{debug, error, info, warn};

const VERIFY_FUNCTION_SIGNATURE: &str = "verify(uint256,bytes,bytes32,bytes32,bytes32,bytes,bytes)";

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProverInputData {
    pub block: Block,
    pub parent_block_header: BlockHeader,
    pub db: ExecutionDB,
}

#[derive(Clone)]
struct ProverServer {
    ip: IpAddr,
    port: u16,
    store: Store,
    eth_client: EthClient,
    on_chain_proposer_address: Address,
    verifier_address: Address,
    verifier_private_key: SecretKey,
}

/// Enum for the ProverServer <--> ProverClient Communication Protocol.
#[derive(Serialize, Deserialize)]
pub enum ProofData {
    /// 1.
    /// The Client initiates the connection with a Request.
    /// Asking for the ProverInputData the prover_server considers/needs.
    Request,

    /// 2.
    /// The Server responds with a Response containing the ProverInputData.
    /// If the Response will is ProofData::Response{None, None}, the Client knows that the Request couldn't be performed.
    Response {
        block_number: Option<u64>,
        input: Option<ProverInputData>,
    },

    /// 3.
    /// The Client submits the zk Proof generated by the prover
    /// for the specified block.
    /// The [ProvingOutput] has the [ProverType] implicitly.
    Submit {
        block_number: u64,
        proving_output: ProvingOutput,
    },

    /// 4.
    /// The Server acknowledges the receipt of the proof and updates its state,
    SubmitAck { block_number: u64 },
}

impl ProofData {
    /// Builder function for creating a Request
    pub fn request() -> Self {
        ProofData::Request
    }

    /// Builder function for creating a Response
    pub fn response(block_number: Option<u64>, input: Option<ProverInputData>) -> Self {
        ProofData::Response {
            block_number,
            input,
        }
    }

    /// Builder function for creating a Submit
    pub fn submit(block_number: u64, proving_output: ProvingOutput) -> Self {
        ProofData::Submit {
            block_number,
            proving_output,
        }
    }

    /// Builder function for creating a SubmitAck
    pub fn submit_ack(block_number: u64) -> Self {
        ProofData::SubmitAck { block_number }
    }
}

pub async fn start_prover_server(store: Store) -> Result<(), ConfigError> {
    let server_config = ProverServerConfig::from_env()?;
    let eth_config = EthConfig::from_env()?;
    let proposer_config = CommitterConfig::from_env()?;
    let mut prover_server =
        ProverServer::new_from_config(server_config.clone(), &proposer_config, eth_config, store)
            .await?;
    prover_server.run(&server_config).await;
    Ok(())
}

impl ProverServer {
    pub async fn new_from_config(
        config: ProverServerConfig,
        committer_config: &CommitterConfig,
        eth_config: EthConfig,
        store: Store,
    ) -> Result<Self, ConfigError> {
        let eth_client = EthClient::new(&eth_config.rpc_url);
        let on_chain_proposer_address = committer_config.on_chain_proposer_address;

        Ok(Self {
            ip: config.listen_ip,
            port: config.listen_port,
            store,
            eth_client,
            on_chain_proposer_address,
            verifier_address: config.verifier_address,
            verifier_private_key: config.verifier_private_key,
        })
    }

    pub async fn run(&mut self, server_config: &ProverServerConfig) {
        loop {
            let result = if server_config.dev_mode {
                self.main_logic_dev().await
            } else {
                self.clone().main_logic(server_config).await
            };

            match result {
                Ok(_) => {
                    if !server_config.dev_mode {
                        warn!("Prover Server shutting down");
                        break;
                    }
                }
                Err(e) => {
                    let error_message = if !server_config.dev_mode {
                        format!("Prover Server, severe Error, trying to restart the main_logic function: {e}")
                    } else {
                        format!("Prover Server Dev Error: {e}")
                    };
                    error!(error_message);
                }
            }

            sleep(Duration::from_millis(200)).await;
        }
    }

    async fn main_logic(
        mut self,
        server_config: &ProverServerConfig,
    ) -> Result<(), ProverServerError> {
        let (tx, rx) = mpsc::channel();

        // It should never exit the start() fn, handling errors inside the for loop of the function.
        let server_handle = tokio::spawn(async move { self.start(rx).await });

        ProverServer::handle_sigint(tx, server_config).await?;

        match server_handle.await {
            Ok(result) => match result {
                Ok(_) => (),
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e.into()),
        };

        Ok(())
    }

    async fn handle_sigint(
        tx: mpsc::Sender<()>,
        config: &ProverServerConfig,
    ) -> Result<(), ProverServerError> {
        let mut sigint = signal(SignalKind::interrupt())?;
        sigint.recv().await.ok_or(SigIntError::Recv)?;
        tx.send(()).map_err(SigIntError::Send)?;
        TcpStream::connect(format!("{}:{}", config.listen_ip, config.listen_port))?
            .shutdown(Shutdown::Both)
            .map_err(SigIntError::Shutdown)?;

        Ok(())
    }

    pub async fn start(&mut self, rx: Receiver<()>) -> Result<(), ProverServerError> {
        let listener = TcpListener::bind(format!("{}:{}", self.ip, self.port))?;

        info!("Starting TCP server at {}:{}", self.ip, self.port);

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    debug!("Connection established!");

                    if let Ok(()) = rx.try_recv() {
                        info!("Shutting down Prover Server");
                        break;
                    }

                    if let Err(e) = self.handle_connection(stream).await {
                        error!("Error handling connection: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
        Ok(())
    }

    async fn handle_connection(&mut self, mut stream: TcpStream) -> Result<(), ProverServerError> {
        let buf_reader = BufReader::new(&stream);

        let last_verified_block =
            EthClient::get_last_verified_block(&self.eth_client, self.on_chain_proposer_address)
                .await?;

        let last_verified_block = if last_verified_block == u64::MAX {
            0
        } else {
            last_verified_block
        };

        let block_to_verify = last_verified_block + 1;

        let mut tx_submitted = false;

        // If we have all the proofs send a transaction to verify them on chain

        let send_tx = match block_number_has_all_proofs(block_to_verify) {
            Ok(has_all_proofs) => has_all_proofs,
            Err(e) => {
                if let SaveStateError::IOError(ref error) = e {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        return Err(e.into());
                    }
                } else {
                    return Err(e.into());
                }
                false
            }
        };
        if send_tx {
            self.handle_proof_submission(block_to_verify).await?;
            // Remove the Proofs for that block_number
            prune_state(block_to_verify)?;
            tx_submitted = true;
        }

        let data: Result<ProofData, _> = serde_json::de::from_reader(buf_reader);
        match data {
            Ok(ProofData::Request) => {
                if let Err(e) = self
                    .handle_request(&stream, block_to_verify, tx_submitted)
                    .await
                {
                    warn!("Failed to handle request: {e}");
                }
            }
            Ok(ProofData::Submit {
                block_number,
                proving_output,
            }) => {
                self.handle_submit(&mut stream, block_number)?;

                // Avoid storing a proof of a future block_number
                // CHECK: maybe we would like to store all the proofs given the case in which
                // the provers generate them fast enough. In this way, we will avoid unneeded reexecution.
                if block_number != block_to_verify {
                    return Err(ProverServerError::Custom(format!("Prover Client submitted an invalid block_number: {block_number}. The last_proved_block is: {last_verified_block}")));
                }

                // If the transaction was submitted for the block_to_verify
                // avoid storing already used proofs.
                if tx_submitted {
                    return Ok(());
                }

                // Check if we have an entry for the proof in that block_number
                // Get the ProverType, implicitly set by the ProvingOutput
                let prover_type = match proving_output {
                    ProvingOutput::RISC0(_) => ProverType::RISC0,
                    ProvingOutput::SP1(_) => ProverType::SP1,
                };

                // Check if we have the proof for that ProverType
                // If we don't have it, insert it.
                let has_proof = match block_number_has_state_file(
                    StateFileType::Proof(prover_type),
                    block_number,
                ) {
                    Ok(has_proof) => has_proof,
                    Err(e) => {
                        let error = format!("{e}");
                        if !error.contains("No such file or directory") {
                            return Err(e.into());
                        }
                        false
                    }
                };
                if !has_proof {
                    write_state(block_number, &StateType::Proof(proving_output))?;
                }

                // Then if we have all the proofs, we send the transaction in the next `handle_connection` call.
            }
            Err(e) => {
                warn!("Failed to parse request: {e}");
            }
            _ => {
                warn!("Invalid request");
            }
        }

        debug!("Connection closed");
        Ok(())
    }

    async fn handle_request(
        &self,
        stream: &TcpStream,
        block_number: u64,
        tx_submitted: bool,
    ) -> Result<(), ProverServerError> {
        debug!("Request received");

        let latest_block_number = self.store.get_latest_block_number()?;

        let response = if block_number > latest_block_number {
            let response = ProofData::response(None, None);
            debug!("Didn't send response");
            response
        } else if tx_submitted {
            let response = ProofData::response(None, None);
            debug!("Block: {block_number} has been submitted.");
            response
        } else {
            let input = self.create_prover_input(block_number)?;
            let response = ProofData::response(Some(block_number), Some(input));
            info!("Sent Response for block_number: {block_number}");
            response
        };

        let writer = BufWriter::new(stream);
        serde_json::to_writer(writer, &response)
            .map_err(|e| ProverServerError::ConnectionError(e.into()))
    }

    fn handle_submit(
        &self,
        stream: &mut TcpStream,
        block_number: u64,
    ) -> Result<(), ProverServerError> {
        debug!("Submit received for BlockNumber: {block_number}");

        let response = ProofData::submit_ack(block_number);
        let json_string = serde_json::to_string(&response)
            .map_err(|e| ProverServerError::Custom(format!("serde_json::to_string(): {e}")))?;
        stream
            .write_all(json_string.as_bytes())
            .map_err(ProverServerError::ConnectionError)?;

        Ok(())
    }

    fn create_prover_input(&self, block_number: u64) -> Result<ProverInputData, ProverServerError> {
        let header = self
            .store
            .get_block_header(block_number)?
            .ok_or(ProverServerError::StorageDataIsNone)?;
        let body = self
            .store
            .get_block_body(block_number)?
            .ok_or(ProverServerError::StorageDataIsNone)?;

        let block = Block::new(header, body);

        let parent_hash = block.header.parent_hash;
        let store = StoreWrapper {
            store: self.store.clone(),
            block_hash: parent_hash,
        };
        let db = store.to_exec_db(&block).map_err(EvmError::ExecutionDB)?;

        let parent_block_header = self
            .store
            .get_block_header_by_hash(parent_hash)?
            .ok_or(ProverServerError::StorageDataIsNone)?;

        debug!("Created prover input for block {block_number}");

        Ok(ProverInputData {
            db,
            block,
            parent_block_header,
        })
    }

    pub async fn handle_proof_submission(
        &self,
        block_number: u64,
    ) -> Result<H256, ProverServerError> {
        // TODO change error
        let risc0_proving_output =
            read_proof(block_number, StateFileType::Proof(ProverType::RISC0))?;
        let risc0_contract_data = match risc0_proving_output {
            ProvingOutput::RISC0(risc0_proof) => risc0_proof.contract_data()?,
            _ => {
                return Err(ProverServerError::Custom(
                    "RISC0 Proof isn't present".to_string(),
                ))
            }
        };

        let sp1_proving_output = read_proof(block_number, StateFileType::Proof(ProverType::SP1))?;
        let sp1_contract_data = match sp1_proving_output {
            ProvingOutput::SP1(sp1_proof) => sp1_proof.contract_data()?,
            _ => {
                return Err(ProverServerError::Custom(
                    "SP1 Proof isn't present".to_string(),
                ))
            }
        };

        debug!("Sending proof for {block_number}");

        let calldata_values = vec![
            Value::Uint(U256::from(block_number)),
            Value::Bytes(risc0_contract_data.block_proof.into()),
            Value::FixedBytes(risc0_contract_data.image_id.into()),
            Value::FixedBytes(risc0_contract_data.journal_digest.into()),
            Value::FixedBytes(sp1_contract_data.vk.into()),
            Value::Bytes(sp1_contract_data.public_values.into()),
            Value::Bytes(sp1_contract_data.proof_bytes.into()),
        ];

        let calldata = encode_calldata(VERIFY_FUNCTION_SIGNATURE, &calldata_values)?;

        let verify_tx = self
            .eth_client
            .build_eip1559_transaction(
                self.on_chain_proposer_address,
                self.verifier_address,
                calldata.into(),
                Overrides::default(),
                10,
            )
            .await?;

        let verify_tx_hash = self
            .eth_client
            .send_wrapped_transaction_with_retry(
                &WrappedTransaction::EIP1559(verify_tx),
                &self.verifier_private_key,
                3 * 60,
                10,
            )
            .await?;

        info!("Sent proof for block {block_number}, with transaction hash {verify_tx_hash:#x}");

        Ok(verify_tx_hash)
    }

    pub async fn main_logic_dev(&self) -> Result<(), ProverServerError> {
        loop {
            thread::sleep(Duration::from_millis(200));

            let last_committed_block = EthClient::get_last_committed_block(
                &self.eth_client,
                self.on_chain_proposer_address,
            )
            .await?;

            let last_verified_block = EthClient::get_last_verified_block(
                &self.eth_client,
                self.on_chain_proposer_address,
            )
            .await?;

            if last_committed_block == last_verified_block {
                debug!("No new blocks to prove");
                continue;
            }

            info!("Last committed: {last_committed_block} - Last verified: {last_verified_block}");

            let calldata_values = vec![
                // blockNumber
                Value::Uint(U256::from(last_verified_block + 1)),
                // blockProof
                Value::Bytes(vec![].into()),
                // imageId
                Value::FixedBytes(H256::zero().as_bytes().to_vec().into()),
                // journalDigest
                Value::FixedBytes(H256::zero().as_bytes().to_vec().into()),
                // programVKey
                Value::FixedBytes(H256::zero().as_bytes().to_vec().into()),
                // publicValues
                Value::Bytes(vec![].into()),
                // proofBytes
                Value::Bytes(vec![].into()),
            ];

            let calldata = encode_calldata(VERIFY_FUNCTION_SIGNATURE, &calldata_values)?;

            let verify_tx = self
                .eth_client
                .build_eip1559_transaction(
                    self.on_chain_proposer_address,
                    self.verifier_address,
                    calldata.into(),
                    Overrides {
                        ..Default::default()
                    },
                    10,
                )
                .await?;

            info!("Sending verify transaction.");

            let verify_tx_hash = self
                .eth_client
                .send_wrapped_transaction_with_retry(
                    &WrappedTransaction::EIP1559(verify_tx),
                    &self.verifier_private_key,
                    3 * 60,
                    10,
                )
                .await?;

            info!("Sent proof for block {last_verified_block}, with transaction hash {verify_tx_hash:#x}");

            info!(
                "Mocked verify transaction sent for block {}",
                last_verified_block + 1
            );
        }
    }
}
