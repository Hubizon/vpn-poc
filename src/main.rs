mod gui;
mod node;
mod protocol;
mod vpn;

use std::{net::SocketAddr, path::PathBuf, process::Command as Process};

use clap::Parser;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

/// Peer-to-peer VPN prototype: peers find each other over the public Amino DHT
/// and connect through relays, hole punching to direct connections.
#[derive(Parser)]
struct Args {
    /// Where the identity key and saved network code are stored.
    #[arg(long, default_value = "vpn-poc-data")]
    data_dir: PathBuf,
    /// Port of the local web GUI.
    #[arg(long, default_value_t = 8080)]
    gui_port: u16,
    /// Network code to join on startup (otherwise use the GUI).
    #[arg(long)]
    network: Option<String>,
    /// Don't open the GUI in the default browser.
    #[arg(long)]
    no_browser: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "vpn_poc=info".into()))
        .init();
    let args = Args::parse();

    let shared = node::Shared::default();
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();

    let mut node = node::Node::new(&args.data_dir, shared.clone(), commands_rx)?;
    match args.network {
        Some(code) => node.join(&code),
        None => node.restore_network(),
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], args.gui_port));
    let url = format!("http://{addr}");
    tracing::info!("GUI available at {url}");
    if !args.no_browser {
        open_browser(&url);
    }

    tokio::select! {
        _ = node.run() => {}
        result = gui::serve(addr, shared, commands_tx) => result?,
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

fn open_browser(url: &str) {
    let result = if cfg!(windows) {
        Process::new("cmd").args(["/C", "start", "", url]).spawn()
    } else if cfg!(target_os = "macos") {
        Process::new("open").arg(url).spawn()
    } else {
        Process::new("xdg-open").arg(url).spawn()
    };
    if result.is_err() {
        tracing::warn!("could not open a browser, visit {url} manually");
    }
}
