// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use crate::proxy_ip_probe::{local_token, valid_token};
use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::{convert::Infallible, path::Path};

pub(crate) const PATH: &str = "/asterisk/dns-events";

pub(crate) async fn handle(request: Request, home: &Path) -> Response {
    if request.method() != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !valid_token(home, local_token(&request)).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"code":"PERMISSION_DENIED"})),
        )
            .into_response();
    }
    #[cfg(target_os = "android")]
    let observation = crate::dns_uid::observe();
    #[cfg(not(target_os = "android"))]
    let observation = ();
    let stream = futures::stream::unfold(
        (meow_dns::events::subscribe(), observation),
        |(mut subscription, observation)| async move {
            loop {
                let event = subscription.recv().await?;
                if let Ok(mut line) = serde_json::to_vec(event.as_ref()) {
                    line.push(b'\n');
                    return Some((Ok::<_, Infallible>(line), (subscription, observation)));
                }
            }
        },
    );
    Response::builder()
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-store")
        .body(Body::from_stream(stream))
        .expect("valid DNS event stream response")
}
