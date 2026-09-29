use alloy_provider::{RootProvider, fillers::FillProvider};
use foundry_common::provider::{
    ProviderBuilder, RetryProvider, RetryProviderWithSigner, SignedFillerChain, get_http_provider,
    signed_filler_chain,
};

use seismic_prelude::foundry::{AnyNetwork, EthereumWallet};

pub fn http_provider(http_endpoint: &str) -> RetryProvider {
    get_http_provider(http_endpoint)
}

pub fn http_provider_with_signer(
    http_endpoint: &str,
    signer: EthereumWallet,
) -> RetryProviderWithSigner {
    ProviderBuilder::new(http_endpoint)
        .build_with_wallet(signer)
        .expect("failed to build Alloy HTTP provider with signer")
}

pub fn ws_provider_with_signer(
    ws_endpoint: &str,
    signer: EthereumWallet,
) -> RetryProviderWithSigner {
    ProviderBuilder::new(ws_endpoint)
        .build_with_wallet(signer)
        .expect("failed to build Alloy WS provider with signer")
}

/// Currently required to get around <https://github.com/alloy-rs/alloy/issues/296>
pub async fn connect_pubsub(conn_str: &str) -> RootProvider {
    alloy_provider::ProviderBuilder::default().connect(conn_str).await.unwrap()
}

type PubsubSigner = FillProvider<SignedFillerChain, RootProvider<AnyNetwork>, AnyNetwork>;

pub async fn connect_pubsub_with_wallet(conn_str: &str, wallet: EthereumWallet) -> PubsubSigner {
    let mut rpc_url: reqwest::Url = conn_str.parse().unwrap();
    match rpc_url.scheme() {
        "ws" => rpc_url.set_scheme("http").unwrap(),
        "wss" => rpc_url.set_scheme("https").unwrap(),
        _ => {}
    }

    alloy_provider::ProviderBuilder::<_, _, AnyNetwork>::default()
        .layer(signed_filler_chain(wallet, rpc_url))
        .connect(conn_str)
        .await
        .unwrap()
}

pub async fn ipc_provider_with_wallet(
    ipc_endpoint: &str,
    wallet: EthereumWallet,
) -> RetryProviderWithSigner {
    ProviderBuilder::new(ipc_endpoint)
        .build_with_wallet(wallet)
        .expect("failed to build Alloy IPC provider with signer")
}
