// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

//! Binding-owned configuration and routes around the unchanged meow router.
use crate::autoswitch::{Service, Settings};
use anyhow::{Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use meow_api::routes::AppState;
use std::{io::Write, path::Path, sync::Arc};
use subtle::ConstantTimeEq;

#[derive(Clone)]
struct Extension {
    app: Arc<AppState>,
    autoswitch: Arc<Service>,
    startup: Arc<meow_config::raw::RawConfig>,
}

pub fn router(app: Arc<AppState>, autoswitch: Arc<Service>) -> Router {
    let startup = Arc::new(app.raw_config.read().clone());
    meow_api::routes::create_router(app.clone())
        .layer(middleware::from_fn_with_state(
            Extension {
                app,
                autoswitch,
                startup,
            },
            extend,
        ))
        .layer(tower_http::cors::CorsLayer::permissive())
}

fn error(status: StatusCode, message: impl ToString) -> Response {
    (
        status,
        Json(serde_json::json!({"message": message.to_string()})),
    )
        .into_response()
}
fn authorized(request: &Request, app: &AppState) -> bool {
    let Some(secret) = app.secret.as_deref().filter(|s| !s.is_empty()) else {
        return true;
    };
    request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| bool::from(token.as_bytes().ct_eq(secret.as_bytes())))
}

fn restart_fields(
    startup: &meow_config::raw::RawConfig,
    candidate: &meow_config::raw::RawConfig,
) -> Result<Vec<&'static str>> {
    // Compare configured ports, not assigned ephemeral ports in AppState.listeners.
    let listeners = |raw| -> Result<serde_json::Value> {
        let mut named = meow_config::resolve_named_listeners(raw)?;
        named.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(serde_json::to_value(named)?)
    };
    let mut fields = Vec::new();
    if listeners(startup)? != listeners(candidate)? {
        fields.push("listeners");
    }
    let old = serde_json::to_value(startup)?;
    let new = serde_json::to_value(candidate)?;
    for field in [
        "external-controller",
        "secret",
        "external-ui",
        "external-ui-name",
        "authentication",
        "skip-auth-prefixes",
        "sniffer",
    ] {
        if old[field] != new[field] {
            fields.push(field);
        }
    }
    Ok(fields)
}

fn restart_required(fields: Vec<&str>) -> Response {
    (StatusCode::CONFLICT, Json(serde_json::json!({
        "code":"RESTART_REQUIRED", "message":"Restart the core to apply startup-only configuration changes", "fields":fields
    }))).into_response()
}

async fn extend(State(extension): State<Extension>, mut request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let custom = path == "/asterisk/auto-switch";
    let capabilities = path == "/asterisk/capabilities";
    let reload = path == "/configs" && method == Method::PUT;
    let save = path == "/api/config/save" && method == Method::POST;
    if (custom || capabilities || reload || save) && !authorized(&request, &extension.app) {
        return error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }
    // All mutable API operations share the automatic selection lane. Reads,
    // probes and streaming endpoints remain independent of a slow reload.
    let _mutation = if method != Method::GET && method != Method::HEAD && method != Method::OPTIONS
    {
        Some(extension.autoswitch.mutations.lock().await)
    } else {
        None
    };
    if capabilities {
        return if method == Method::GET {
            (
                [("content-type", "application/json")],
                crate::engine::capabilities(),
            )
                .into_response()
        } else {
            error(StatusCode::METHOD_NOT_ALLOWED, "Use GET")
        };
    }
    if custom {
        return match method {
            Method::GET => Json(extension.autoswitch.snapshot()).into_response(),
            Method::PATCH => {
                let result = async {
                    let bytes = to_bytes(request.into_body(), 32 * 1024 * 1024).await?;
                    let settings: Settings = serde_json::from_slice(&bytes)?;
                    extension.autoswitch.patch(settings).await
                }
                .await;
                match result {
                    Ok(()) => StatusCode::NO_CONTENT.into_response(),
                    Err(e) => error(StatusCode::BAD_REQUEST, e),
                }
            }
            _ => error(StatusCode::METHOD_NOT_ALLOWED, "Use GET or PATCH"),
        };
    }
    if save {
        return match save_config(&extension).await {
            Ok(()) => Json(serde_json::json!({"message":"config saved"})).into_response(),
            Err(e) => error(
                if extension.app.config_path.is_none() {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                e,
            ),
        };
    }
    let mut configured = None;
    if reload {
        let (parts, body) = request.into_parts();
        let result = async {
            let bytes = to_bytes(body, 32 * 1024 * 1024).await?;
            let body: serde_json::Value = serde_json::from_slice(&bytes)?;
            let bytes = if let Some(path) = body.get("path").and_then(|p| p.as_str()) {
                tokio::fs::read(path).await?
            } else {
                STANDARD.decode(
                    body.get("payload")
                        .and_then(|p| p.as_str())
                        .context("path or payload required")?,
                )?
            };
            let (raw, settings) = crate::engine::parse(&bytes)?;
            let restart = restart_fields(&extension.startup, &raw)?;
            // Pass the exact bytes checked here; a file can change during reload.
            let normalized = serde_yaml::to_string(&crate::profile::decode(&bytes)?)?;
            let payload = serde_json::json!({"payload": STANDARD.encode(normalized)}).to_string();
            Ok::<_, anyhow::Error>((payload, settings, restart))
        }
        .await;
        match result {
            Ok((payload, settings, restart)) => {
                if !restart.is_empty() {
                    return restart_required(restart);
                }
                configured = Some(settings);
                request = Request::from_parts(parts, Body::from(payload));
                request.headers_mut().remove("content-length");
                request
                    .headers_mut()
                    .insert("content-type", "application/json".parse().unwrap());
            }
            Err(e) => return error(StatusCode::BAD_REQUEST, e),
        }
    }
    let response = next.run(request).await;
    if response.status().is_success() {
        if path == "/connections" && method == Method::DELETE {
            extension.app.tunnel.close_all_udp_sessions();
        }
        if let Some(settings) = configured {
            extension.autoswitch.apply(settings).await;
        }
    }
    response
}

async fn save_config(extension: &Extension) -> Result<()> {
    let path = extension
        .app
        .config_path
        .clone()
        .context("no backing config file")?;
    let _mutation = meow_api::routes::CONFIG_MUTATION.lock().await;
    let configured = extension.autoswitch.configured().await;
    let mut value = serde_yaml::to_value(&*extension.app.raw_config.read())?;
    value.as_mapping_mut().context("config mapping")?.insert(
        "asterisk-auto-switch".into(),
        serde_yaml::to_value(configured)?,
    );
    let yaml = serde_yaml::to_string(&value)?;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let path = Path::new(&path);
        let mut temporary =
            tempfile::NamedTempFile::new_in(path.parent().context("config directory")?)?;
        temporary.write_all(yaml.as_bytes())?;
        if path.exists() {
            std::fs::copy(path, format!("{}.bak", path.display()))?;
        }
        temporary.persist(path)?;
        Ok(())
    })
    .await?
}
