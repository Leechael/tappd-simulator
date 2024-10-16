// use std::sync::Arc;

use anyhow::Result;
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    // Container,
    DeriveKeyArgs,
    DeriveKeyResponse,
    TdxQuoteArgs,
    TdxQuoteResponse,
};

use crate::{config::Config, rpc_call::RpcCall};

#[derive(Clone)]
pub struct AppState {
    // inner: Arc<AppStateInner>,
}

// struct AppStateInner {
// ca: CaCert,
// }

impl AppState {
    pub fn new(_config: Config) -> Result<Self> {
        // let ca = CaCert::load(&config.cert_file, &config.key_file)
        //     .context("Failed to load CA certificate")?;
        Ok(Self {
            // inner: Arc::new(AppStateInner { ca }),
            // inner: Arc::new(AppStateInner { }),
        })
    }
}

pub struct InternalRpcHandler {
    #[allow(dead_code)]
    state: AppState,
}

impl TappdRpc for InternalRpcHandler {
    async fn derive_key(self, _request: DeriveKeyArgs) -> Result<DeriveKeyResponse> {
        // let derived_key = [0u8; 32];
        // let cert = vec![0u8; 64];
        Ok(DeriveKeyResponse {
            key: String::from("mock_derived_key_pem"),
            certificate_chain: vec![
                String::from("mock_cert_pem"),
                String::from("mock_ca_cert_pem"),
            ],
        })
    }

    async fn tdx_quote(self, _request: TdxQuoteArgs) -> Result<TdxQuoteResponse> {
        // let report_data = sha2_512(&request.report_data);
        Ok(TdxQuoteResponse {
            quote: vec![0u8; 64],
            event_log: String::from("mock_event_log"),
        })
    }
}

impl RpcCall<AppState> for InternalRpcHandler {
    type PrpcService = TappdServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TappdServer::new(self)
    }

    // fn construct(state: &AppState, _attestation: Option<Attestation>) -> Result<Self>
    fn construct(state: &AppState) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(InternalRpcHandler {
            state: state.clone(),
        })
    }
}

// fn sha2_512(data: &[u8]) -> [u8; 64] {
//     use sha2::{Digest, Sha512};
//     let mut hasher = Sha512::new();
//     hasher.update(data);
//     hasher.finalize().into()
// }
