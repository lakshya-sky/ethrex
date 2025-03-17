pub mod backends;
pub mod errors;
pub mod prover_client;

use ethrex_l2::utils::config::prover_client::ProverClientConfig;
use tracing::warn;

pub async fn init_client(config: ProverClientConfig) {
    prover_client::start_proof_data_client(config).await;
    warn!("Prover finished!");
}

#[cfg(not(any(feature = "exec", feature = "pico", feature = "risc0", feature = "sp1")))]
compile_error!(
    "A prover backend must be chosen by enabling one of the next features: exec, pico, risc0, sp1."
);

#[cfg(feature = "exec")]
pub use backends::exec::*;

#[cfg(feature = "pico")]
pub use backends::pico::*;

#[cfg(feature = "risc0")]
pub use backends::risc0::*;

#[cfg(feature = "sp1")]
pub use backends::sp1::*;
