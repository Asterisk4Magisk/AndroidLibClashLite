// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use axum::{
    body::to_bytes,
    extract::{ConnectInfo, Request},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use meow_common::{AdapterType, ConnType, Metadata, Network, Proxy};
use meow_transport::{
    tls::{TlsConfig, TlsLayer},
    Transport,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncReadExt, sync::watch};
use url::{Position, Url};

const MAX_BODY: usize = 16 * 1024;
const MAX_REDIRECTS: usize = 10;
const WORK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct UnixControllerPeer;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum RuntimeState {
    Running,
    Reloading,
    Stopped,
}

pub(crate) struct ReloadGuard<'a>(&'a watch::Sender<RuntimeState>);

impl<'a> ReloadGuard<'a> {
    pub(crate) fn new(runtime: &'a watch::Sender<RuntimeState>) -> Self {
        runtime.send_if_modified(|state| {
            if *state != RuntimeState::Running {
                return false;
            }
            *state = RuntimeState::Reloading;
            true
        });
        Self(runtime)
    }
}

impl Drop for ReloadGuard<'_> {
    fn drop(&mut self) {
        self.0.send_if_modified(|state| {
            if *state != RuntimeState::Reloading {
                return false;
            }
            *state = RuntimeState::Running;
            true
        });
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeRequest {
    outbound_tag: String,
    url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Sample {
    outbound_tag: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<String>,
}

pub(crate) async fn handle(
    request: Request,
    app: &meow_api::routes::AppState,
    home: &Path,
    mut runtime: watch::Receiver<RuntimeState>,
) -> Response {
    if request.method() != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !valid_token(home, local_token(&request)).await {
        return error(StatusCode::FORBIDDEN, "PERMISSION_DENIED");
    }
    let Ok(body) = to_bytes(request.into_body(), 4096).await else {
        return error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT");
    };
    let Ok(probe) = serde_json::from_slice::<ProbeRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT");
    };
    let Ok(endpoint) = Url::parse(&probe.url) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT");
    };
    if probe.outbound_tag.is_empty() || !valid_endpoint(&endpoint) {
        return error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT");
    }
    if *runtime.borrow_and_update() != RuntimeState::Running {
        return error(StatusCode::CONFLICT, "NOT_RUNNING");
    }
    let Some(outbound) = app.tunnel.proxy(&probe.outbound_tag).filter(|outbound| {
        matches!(
            outbound.adapter_type(),
            AdapterType::Selector
                | AdapterType::Fallback
                | AdapterType::UrlTest
                | AdapterType::LoadBalance
                | AdapterType::Relay
        )
    }) else {
        return error(StatusCode::NOT_FOUND, "OUTBOUND_NOT_FOUND");
    };
    let measure = tokio::time::timeout(
        WORK_TIMEOUT,
        meow_proxy::group::with_read_only_probe(measure(outbound.as_ref(), endpoint)),
    );
    let result = tokio::select! {
        biased;
        _ = runtime.changed() => return error(StatusCode::CONFLICT, "RUNTIME_CHANGED"),
        result = measure => result,
    };
    let (status, response) = match result {
        Ok(Ok(response)) => ("ok", Some(response)),
        Ok(Err(status)) => (status, None),
        Err(_) => ("timeout", None),
    };
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(Sample {
            outbound_tag: probe.outbound_tag,
            status,
            response,
        }),
    )
        .into_response()
}

pub(crate) fn local_token(request: &Request) -> &str {
    let local = request.extensions().get::<UnixControllerPeer>().is_some()
        || request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|peer| peer.0.ip().is_loopback());
    if !local {
        return "";
    }
    request
        .headers()
        .get("x-asterisk-probe-token")
        .and_then(|token| token.to_str().ok())
        .unwrap_or_default()
}

pub(crate) async fn valid_token(home: &Path, provided: &str) -> bool {
    if provided.len() != 64 || !provided.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let Ok(file) = tokio::fs::File::open(home.join("proxy-ip-probe.token")).await else {
        return false;
    };
    let mut expected = String::new();
    if file.take(67).read_to_string(&mut expected).await.is_err() {
        return false;
    }
    let expected = expected.trim();
    expected.len() == 64
        && expected.bytes().all(|b| b.is_ascii_hexdigit())
        && bool::from(
            expected
                .to_ascii_lowercase()
                .as_bytes()
                .ct_eq(provided.to_ascii_lowercase().as_bytes()),
        )
}

fn valid_endpoint(endpoint: &Url) -> bool {
    endpoint.scheme() == "https"
        && endpoint.has_host()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
}

enum ProbeResponse {
    Body(String),
    Redirect(Url),
}

async fn measure(outbound: &dyn Proxy, mut endpoint: Url) -> Result<String, &'static str> {
    for _ in 0..=MAX_REDIRECTS {
        match probe_once(outbound, &endpoint).await? {
            ProbeResponse::Body(body) => return Ok(body),
            ProbeResponse::Redirect(next) => endpoint = next,
        }
    }
    Err("invalid_response")
}

async fn probe_once(outbound: &dyn Proxy, endpoint: &Url) -> Result<ProbeResponse, &'static str> {
    let host = endpoint
        .host_str()
        .ok_or("unreachable")?
        .trim_matches(['[', ']']);
    let dst_ip = host.parse::<IpAddr>().ok();
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Tunnel,
        host: if dst_ip.is_none() {
            host.into()
        } else {
            Default::default()
        },
        dst_ip,
        dst_port: endpoint.port().unwrap_or(443),
        ..Default::default()
    };
    let conn = outbound.dial_tcp(&metadata).await.map_err(|err| {
        if meow_proxy::group::probe_blocked(&err) {
            "blocked"
        } else {
            "unreachable"
        }
    })?;
    let tls = TlsLayer::new(&TlsConfig::new(host.to_owned())).map_err(|_| "unreachable")?;
    let tls = tls
        .connect(Box::new(conn))
        .await
        .map_err(|_| "unreachable")?;
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(MAX_BODY)
        .handshake(TokioIo::new(tls))
        .await
        .map_err(|_| "unreachable")?;
    let exchange = async {
        let request = axum::http::Request::builder()
            .uri(&endpoint[Position::BeforePath..Position::AfterQuery])
            .header(
                header::HOST,
                &endpoint[Position::BeforeHost..Position::AfterPort],
            )
            .header(header::CONNECTION, "close")
            .body(Empty::<Bytes>::new())
            .map_err(|_| "unreachable")?;
        let mut response = sender
            .send_request(request)
            .await
            .map_err(|_| "invalid_response")?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT => {
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| !value.is_empty())
                    .ok_or("invalid_response")?;
                let next = endpoint.join(location).map_err(|_| "invalid_response")?;
                if !valid_endpoint(&next) {
                    return Err("invalid_response");
                }
                return Ok(ProbeResponse::Redirect(next));
            }
            _ => return Err("invalid_response"),
        }
        let mut bytes = Vec::new();
        while let Some(frame) = response.body_mut().frame().await {
            let frame = frame.map_err(|_| "invalid_response")?;
            if let Some(data) = frame.data_ref() {
                if data.len() > MAX_BODY - bytes.len() {
                    return Err("invalid_response");
                }
                bytes.extend_from_slice(data);
            }
        }
        String::from_utf8(bytes)
            .map(ProbeResponse::Body)
            .map_err(|_| "invalid_response")
    };
    // Drive HTTP and consume its response within the cancellable probe task.
    tokio::pin!(exchange);
    tokio::select! {
        result = &mut exchange => result,
        result = connection => {
            result.map_err(|_| "invalid_response")?;
            exchange.await
        }
    }
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({"code": code}))).into_response()
}
