#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rocket::{
    figment::Figment,
    listener::{Bind, DefaultListener},
};
use rpc_service::AppState;

mod config;
mod http_routes;
mod rocket_helper;
mod rpc_call;
mod rpc_service;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,

    // The listen address for the server, defaults to unix:/var/run/tappd.sock under Linux,
    // and tcp:0.0.0.0:8090 under Windows & Mac
    #[arg(short, long)]
    listen: Option<String>,

    // The port to listen on, defaults to 8090. It only applies to listening on IP addresses,
    // or once it specifies, it will auto switch to the listen mode.
    #[arg(short, long, default_value_t = 8090)]
    port: u16,
}

async fn run_internal(state: AppState, figment: Figment) -> Result<()> {
    let rocket = rocket::custom(figment)
        .mount("/", http_routes::internal_routes())
        .manage(state);
    let ignite = rocket
        .ignite()
        .await
        .map_err(|err| anyhow!("Failed to ignite rocket: {err}"))?;
    let endpoint = DefaultListener::bind_endpoint(&ignite)
        .map_err(|err| anyhow!("Failed to get endpoint: {err}"))?;
    let listener = DefaultListener::bind(&ignite)
        .await
        .map_err(|err| anyhow!("Failed to bind on {endpoint}: {err}"))?;
    #[cfg(unix)]
    if let Some(path) = endpoint.unix() {
        // Allow any user to connect to the socket
        fs_err::set_permissions(path, Permissions::from_mode(0o777))?;
    }
    ignite
        .launch_on(listener)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(())
}

#[rocket::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config = rocket::Config::figment()
        .merge(("address", args.listen.unwrap_or_else(|| {
            #[cfg(all(unix, not(target_os = "macos")))]
            {
                String::from("unix:/var/run/tappd.sock")
            }
            #[cfg(any(windows, target_os = "macos"))]
            {
                String::from("0.0.0.0")
            }
        })))
        .merge(("port", args.port));

    let figment = config::load_config_figment(args.config.as_deref());
    let state =
        AppState::new(figment.focus("core").extract()?).context("Failed to create app state")?;

    tokio::select!(
        res = run_internal(state.clone(), config) => res?,
    );
    Ok(())
}
