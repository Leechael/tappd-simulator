use std::sync::Arc;

use anyhow::{Context, Result};
use proptest::{
    arbitrary::Arbitrary,
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};
use scale::Encode;
use dcap_qvl::quote::{AuthDataV4, Header, TDReport10, TdxEventLogs};
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    // Container,
    DeriveKeyArgs,
    DeriveKeyResponse,
    TdxQuoteArgs,
    TdxQuoteResponse,
};
use sha2::Digest;

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
            .alt_names(&request.alt_names)
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

    async fn tdx_quote(self, request: TdxQuoteArgs) -> Result<TdxQuoteResponse> {
        let mut runner = TestRunner::default();

        let params = Default::default();
        let event_logs = <TdxEventLogs as Arbitrary>::arbitrary_with(params)
            .new_tree(&mut runner)
            .expect("Failed to create event_logs")
            .current();
        let rtmrs = event_logs.get_rtmr();

        let mut header = <Header as Arbitrary>::arbitrary().new_tree(&mut runner).expect("Failed to create value tree").current();
        // TODO: the python decoder not a full implementation.
        header.version = 4;
        header.tee_type = 0x00000081;
        header.attestation_key_type = 3u16;

        let mut body = <TDReport10 as Arbitrary>::arbitrary()
            .new_tree(&mut runner)
            .expect("Failed to create value tree")
            .current();
        body.rt_mr0 = rtmrs[0];
        body.rt_mr1 = rtmrs[1];
        body.rt_mr2 = rtmrs[2];
        body.rt_mr3 = rtmrs[3];
        body.report_data = to_report_data_with_hash(&request.report_data, &request.hash_algorithm)?;

        let mut encoded = Vec::new();
        encoded.extend(header.encode());
        encoded.extend(body.encode());

        let inner = <AuthDataV4 as Arbitrary>::arbitrary()
            .new_tree(&mut runner)
            .expect("Failed to create value tree")
            .current()
            .encode();
        encoded.extend((inner.len() as u32).encode());
        encoded.extend(inner);

        Ok(TdxQuoteResponse {
            quote: encoded,
            event_log: event_logs.to_json().unwrap_or_default(),
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

fn to_report_data_with_hash(content: &[u8], hash: &str) -> Result<[u8; 64]> {
    macro_rules! do_hash {
        ($hash: ty) => {{
            // The format is:
            // hash(<tag>:<content>)
            let mut hasher = <$hash>::new();
            hasher.update("app-data".as_bytes());
            hasher.update(b":");
            hasher.update(content);
            let output = hasher.finalize();

            let mut padded = [0u8; 64];
            padded[..output.len()].copy_from_slice(&output);
            padded
        }};
    }
    let output = match hash {
        "sha256" => do_hash!(sha2::Sha256),
        "sha384" => do_hash!(sha2::Sha384),
        // Default to sha512
        "" | "sha512" => do_hash!(sha2::Sha512),
        "sha3-256" => do_hash!(sha3::Sha3_256),
        "sha3-384" => do_hash!(sha3::Sha3_384),
        "sha3-512" => do_hash!(sha3::Sha3_512),
        "keccak256" => do_hash!(sha3::Keccak256),
        "keccak384" => do_hash!(sha3::Keccak384),
        "keccak512" => do_hash!(sha3::Keccak512),
        "raw" => content.try_into().ok().context("invalid content length")?,
        _ => anyhow::bail!("invalid hash algorithm"),
    };
    Ok(output)
}