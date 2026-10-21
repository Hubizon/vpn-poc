//! Local web GUI: a tiny HTTP server bound to localhost, polled by `web/index.html`.

use std::net::SocketAddr;

use axum::{
    extract::State,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use libp2p::PeerId;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::node::{Command, Shared, Snapshot};
use crate::protocol::new_network_code;

const MIN_CODE_LEN: usize = 16;

#[derive(Clone)]
struct App {
    shared: Shared,
    commands: mpsc::UnboundedSender<Command>,
}

#[derive(Deserialize)]
struct JoinRequest {
    /// Empty or missing: create a new network.
    code: Option<String>,
}

#[derive(Deserialize)]
struct SendRequest {
    peer: String,
    text: String,
}

pub async fn serve(addr: SocketAddr, shared: Shared, commands: mpsc::UnboundedSender<Command>) -> anyhow::Result<()> {
    // Only `application/json` bodies are accepted by the POST routes, so other
    // websites can't drive this API from a browser without a CORS preflight.
    let router = Router::new()
        .route("/", get(|| async { Html(include_str!("../web/index.html")) }))
        .route("/api/state", get(state))
        .route("/api/join", post(join))
        .route("/api/send", post(send))
        .with_state(App { shared, commands });
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn state(State(app): State<App>) -> Json<Snapshot> {
    Json(app.shared.lock().unwrap().clone())
}

async fn join(State(app): State<App>, Json(request): Json<JoinRequest>) -> Result<(), (StatusCode, &'static str)> {
    if app.shared.lock().unwrap().network_code.is_some() {
        return Err((StatusCode::CONFLICT, "already joined a network"));
    }
    let code = request.code.map(|c| c.trim().to_owned()).filter(|c| !c.is_empty());
    let code = match code {
        Some(code) if code.len() < MIN_CODE_LEN => return Err((StatusCode::BAD_REQUEST, "network code is too short")),
        Some(code) => code,
        None => new_network_code(),
    };
    app.commands.send(Command::Join(code)).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "node stopped"))
}

async fn send(State(app): State<App>, Json(request): Json<SendRequest>) -> Result<(), (StatusCode, &'static str)> {
    let peer: PeerId = request.peer.parse().map_err(|_| (StatusCode::BAD_REQUEST, "invalid peer id"))?;
    app.commands
        .send(Command::Send { peer, text: request.text })
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "node stopped"))
}
