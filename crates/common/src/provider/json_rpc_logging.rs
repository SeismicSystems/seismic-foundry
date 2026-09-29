//! A transport layer that prints full JSON-RPC requests and responses to stderr.
//!
//! The layer is always installed in the provider stack but is a no-op unless
//! enabled via [`set_verbose_json_rpc`] (wired to the global `--verbose-json-rpc`
//! CLI flag). It sits below the retry layer, so retried requests are printed as
//! they appear on the wire.

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{TransportError, TransportFut};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use tower::{Layer, Service};

static VERBOSE_JSON_RPC: AtomicBool = AtomicBool::new(false);

/// Enables or disables printing of JSON-RPC requests and responses.
pub fn set_verbose_json_rpc(enabled: bool) {
    VERBOSE_JSON_RPC.store(enabled, Ordering::Relaxed);
}

/// Whether printing of JSON-RPC requests and responses is enabled.
pub fn verbose_json_rpc() -> bool {
    VERBOSE_JSON_RPC.load(Ordering::Relaxed)
}

/// A transport layer that prints every JSON-RPC request and response to stderr
/// when enabled via [`set_verbose_json_rpc`].
#[derive(Clone, Copy, Debug, Default)]
pub struct JsonRpcLoggingLayer;

impl<S> Layer<S> for JsonRpcLoggingLayer {
    type Service = JsonRpcLoggingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JsonRpcLoggingService { inner }
    }
}

/// Tower service for [`JsonRpcLoggingLayer`].
#[derive(Clone, Debug)]
pub struct JsonRpcLoggingService<S> {
    inner: S,
}

impl<S> Service<RequestPacket> for JsonRpcLoggingService<S>
where
    S: Service<
            RequestPacket,
            Response = ResponsePacket,
            Error = TransportError,
            Future = TransportFut<'static>,
        >
        + Send
        + 'static
        + Clone,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        if !verbose_json_rpc() {
            return self.inner.call(req);
        }

        print_request(&req);
        let fut = self.inner.call(req);
        Box::pin(async move {
            let resp = fut.await;
            match &resp {
                Ok(resp) => print_response(resp),
                Err(err) => {
                    let _ = sh_eprintln!("JSON-RPC error:\n{err}");
                }
            }
            resp
        })
    }
}

fn print_request(req: &RequestPacket) {
    match req {
        RequestPacket::Single(req) => {
            let _ = sh_eprintln!("JSON-RPC request:\n{}", req.serialized().get());
        }
        RequestPacket::Batch(reqs) => {
            for req in reqs {
                let _ = sh_eprintln!("JSON-RPC batch request:\n{}", req.serialized().get());
            }
        }
    }
}

fn print_response(resp: &ResponsePacket) {
    let json = match resp {
        ResponsePacket::Single(resp) => serde_json::to_string_pretty(resp),
        ResponsePacket::Batch(resps) => serde_json::to_string_pretty(resps),
    };
    match json {
        Ok(json) => {
            let _ = sh_eprintln!("JSON-RPC response:\n{json}");
        }
        Err(e) => {
            let _ = sh_eprintln!("JSON-RPC response: <failed to serialize: {e}>");
        }
    }
}
