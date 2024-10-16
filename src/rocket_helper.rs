use anyhow::{Context, Result};
use rocket::{
    data::{ByteUnit, Limits, ToByteUnit},
    http::{ContentType, Status},
    mtls::Certificate,
    response::status::Custom,
    Data,
};

use crate::rpc_call::RpcCall;

async fn read_data(data: Data<'_>, limit: ByteUnit) -> Result<Vec<u8>> {
    let stream = data.open(limit);
    let data = stream.into_bytes().await.context("failed to read data")?;
    if !data.is_complete() {
        anyhow::bail!("payload too large");
    }
    Ok(data.into_inner())
}

fn limit_for_method(method: &str, limits: &Limits) -> ByteUnit {
    if let Some(v) = limits.get(method) {
        return v;
    }
    10.mebibytes()
}

pub async fn handle_prpc<State, Call: RpcCall<State>>(
    state: &State,
    _certificate: Option<Certificate<'_>>,
    method: &str,
    data: Option<Data<'_>>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Result<Custom<Vec<u8>>> {
    let data = match data {
        Some(data) => {
            let limit = limit_for_method(method, limits);
            let _todo = "confirm this would not truncate the data";
            read_data(data, limit)
                .await
                .context("failed to read data")?
        }
        None => vec![],
    };
    let json = json || content_type.map(|t| t.is_json()).unwrap_or(false);
    let call = Call::construct(state).context("failed to construct call")?;
    let data = data.to_vec();
    let (status_code, output) = call.call(method.to_string(), data, json).await;
    Ok(Custom(Status::new(status_code), output))
}
