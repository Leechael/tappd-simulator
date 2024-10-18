use std::sync::Arc;

use anyhow::{Context, Result};
use proptest::{
    arbitrary::Arbitrary,
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};
use scale::Encode;
use dcap_qvl::quote::{Header, TDReport10, AuthDataV4};
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    // Container,
    DeriveKeyArgs,
    DeriveKeyResponse,
    TdxQuoteArgs,
    TdxQuoteResponse,
};

use crate::{
    rpc_call::RpcCall,
    ra_tls::{
        cert::{CaCert, CertRequest},
        kdf::derive_ecdsa_key_pair
    }
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    ca: CaCert,
}

impl AppState {
    pub fn new(cert_file: String, key_file: String) -> Result<Self> {
        let ca = CaCert::load(&cert_file, &key_file)
            .unwrap_or_else(|err| panic!("Failed to load ca cert: {err}"));
        Ok(Self {
            inner: Arc::new(AppStateInner { ca }),
        })
    }
}

pub struct InternalRpcHandler {
    #[allow(dead_code)]
    state: AppState,
}

impl TappdRpc for InternalRpcHandler {
    async fn derive_key(self, request: DeriveKeyArgs) -> Result<DeriveKeyResponse> {
        let derived_key =
            derive_ecdsa_key_pair(&self.state.inner.ca.key, &[request.path.as_bytes()])
                .context("Failed to derive key")?;
        let req = CertRequest::builder()
            .subject(&request.subject)
            .key(&derived_key)
            .build();
        let cert = self
            .state
            .inner
            .ca
            .sign(req)
            .context("Failed to sign certificate")?;
        Ok(DeriveKeyResponse {
            key: derived_key.serialize_pem(),
            certificate_chain: vec![cert.pem(), self.state.inner.ca.cert.pem()],
        })
    }

    async fn tdx_quote(self, _request: TdxQuoteArgs) -> Result<TdxQuoteResponse> {
        let mut runner = TestRunner::default();

        let mut header = <Header as Arbitrary>::arbitrary().new_tree(&mut runner).expect("Failed to create value tree").current();
        // TODO: the python decoder not a full implementation.
        header.version = 4;
        header.tee_type = 0x00000081;
        header.attestation_key_type = 3u16;
        let body = <TDReport10 as Arbitrary>::arbitrary()
            .new_tree(&mut runner)
            .expect("Failed to create value tree")
            .current()
            .encode();

        let mut encoded = Vec::new();
        encoded.extend(header.encode());
        encoded.extend(body);

        let inner = <AuthDataV4 as Arbitrary>::arbitrary()
            .new_tree(&mut runner)
            .expect("Failed to create value tree")
            .current()
            .encode();
        encoded.extend((inner.len() as u32).encode());
        encoded.extend(inner);

        Ok(TdxQuoteResponse {
            quote: encoded,
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
