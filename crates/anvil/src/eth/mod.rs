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
    pub static ref SEISMIC_DB: seismic_db::SyncInMemoryDB = seismic_db::SyncInMemoryDB::new();
    // pub static ref SEISMIC_DB_BACKEND_COMPATIBLE: seismic_db::SyncInMemoryDBAnvil = seismic_db::SyncInMemoryDBAnvil::new();
}
