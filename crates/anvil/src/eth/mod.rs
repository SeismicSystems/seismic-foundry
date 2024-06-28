pub mod api;
pub mod otterscan;
pub mod sign;
pub use api::EthApi;

pub mod backend;

pub mod error;

pub mod fees;
pub(crate) mod macros;
pub mod miner;
pub mod pool;
pub mod util;

lazy_static::lazy_static! {
    pub static ref SEISMIC_DB: std::sync::RwLock<seismic_db::CommitmentInMemoryDb> = std::sync::RwLock::new(seismic_db::CommitmentInMemoryDb::new(seismic_db::CommitmentEmptyDb::default()));
}
