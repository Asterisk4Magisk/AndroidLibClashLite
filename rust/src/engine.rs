// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::{bail, Context, Result};
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use meow_api::routes::{AppState, DnsServerHandle};
use meow_config::{raw::RawConfig, Config};
use meow_listener::SnifferRuntime;
use meow_tunnel::Tunnel;
use parking_lot::{Mutex, RwLock};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tower::ServiceExt;

pub static OPERATION: Mutex<()> = Mutex::new(());
static SESSION: Mutex<Option<Session>> = Mutex::new(None);

struct Session {
    app: Arc<AppState>,
    router: Router,
    autoswitch: Arc<crate::autoswitch::Service>,
    home: String,
    base: String,
    unix_controller: Option<UnixController>,
    flow_tokens: std::collections::HashMap<String, String>,
}

struct UnixController {
    path: String,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for UnixController {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
impl UnixController {
    fn bind(path: String, router: Router) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove stale Unix controller"),
        }
        let socket = tokio::net::UnixListener::bind(&path).context("bind Unix controller")?;
        let mut controller = Self { path, task: None };
        std::fs::set_permissions(&controller.path, std::fs::Permissions::from_mode(0o600))?;
        controller.task = Some(tokio::spawn(async move {
            if let Err(error) = axum::serve(socket, router).await {
                tracing::error!("Unix Clash API stopped: {error}");
            }
        }));
        Ok(controller)
    }
}

pub fn tunnel() -> Option<Tunnel> {
    SESSION.lock().as_ref().map(|s| s.app.tunnel.clone())
}
pub fn is_running() -> bool {
    SESSION.lock().is_some()
}

pub fn capabilities() -> String {
    serde_json::json!({
        "schemaVersion":1, "core":"meow", "version":crate::CORE_VERSION,
        "jni":true, "cli":true, "tunFd":cfg!(unix),
        "clashApi":true, "mixed":true, "socks5":true, "http":true,
        "rootTproxy":cfg!(target_os = "android"), "rootTun":false,
        "age":true, "subscriptionHwid":true, "autoSwitch":true,
        "systemDns":true, "libclashFacade":true, "isolatedValidation":true,
        "dnsOutbound":true, "tunDnsTcp":true, "tunDnsUdp":true,
        "ageIdentities":["X25519"], "tunStacks":["lwip"], "selectableCongestionController":false,
        "congestionControllers":[], "congestionControllerStacks":[],
        "listenerHotReload":false, "connectionTracking":["tcp"], "memoryMetric":"rss",
        "configDiagnostics":true, "uiSubtitlePattern":true,
        "dnsOptions":{"direct-nameserver":true,"direct-nameserver-follow-policy":true,"respect-rules":false,"prefer-h3":false}
    })
    .to_string()
}

fn check_config(raw: &RawConfig) -> Result<()> {
    if raw.tun.as_ref().is_some_and(|tun| tun.enable) {
        bail!("ROOT TUN is not supported by this binding; Android VPN must pass its TUN fd to startTun");
    }
    Ok(())
}

pub(crate) fn parse(
    bytes: &[u8],
) -> Result<(RawConfig, crate::autoswitch::Settings, Option<String>)> {
    meow_common::process_lookup::enable_inbound_process_info();
    let (value, controller_unix) = crate::profile::decode_core(bytes)?;
    let raw = meow_config::parse_raw_yaml(&serde_yaml::to_string(&value)?)
        .context("parse configuration")?;
    let settings = value
        .get("asterisk-auto-switch")
        .filter(|v| !v.is_null())
        .cloned()
        .map(serde_yaml::from_value)
        .transpose()?
        .unwrap_or_default();
    check_config(&raw)?;
    Ok((raw, settings, controller_unix))
}

pub fn start(home: &str, base: &str, bytes: &[u8], config_path: Option<String>) -> Result<()> {
    start_inner(home, base, bytes, config_path, None)
}

fn start_inner(
    home: &str,
    base: &str,
    bytes: &[u8],
    config_path: Option<String>,
    reload_state: Option<crate::autoswitch::ReloadState>,
) -> Result<()> {
    if is_running() {
        bail!("meow is already running; stop it before starting another session");
    }
    if !Path::new(home).is_absolute() || !Path::new(base).is_absolute() {
        bail!("home and baseDirectory must be absolute paths");
    }
    let (raw, settings, controller_unix) = parse(bytes)?;
    let (profile, _) = crate::profile::decode_core(bytes)?;
    let process_mode = profile
        .get("find-process-mode")
        .and_then(|value| value.as_str())
        .unwrap_or("strict")
        .to_owned();
    #[cfg(unix)]
    let flow_tokens = crate::flowmeta::tokens(bytes)?;
    #[cfg(not(unix))]
    let flow_tokens = std::collections::HashMap::new();
    std::fs::create_dir_all(home)?;
    meow_common::set_home_dir(PathBuf::from(home));
    meow_config::set_offline_validate(false);
    meow_api::set_listener_gate(crate::listeners::supported);
    crate::logging::capture();
    let result = crate::get_runtime().block_on(async {
        let config = meow_config::build_config(raw, Some(Path::new(base))).await?;
        meow_api::ensure_listeners_supported(&config.listeners.named, crate::listeners::supported)?;
        crate::platform::configure_process_mode(&process_mode);
        let mut session = start_config(
            config,
            config_path,
            settings,
            reload_state,
            controller_unix,
            flow_tokens,
        )
        .await?;
        session.home = home.into();
        session.base = base.into();
        *SESSION.lock() = Some(session);
        Ok(())
    });
    if result.is_err() {
        stop();
    }
    result
}

async fn start_config(
    config: Config,
    config_path: Option<String>,
    settings: crate::autoswitch::Settings,
    reload_state: Option<crate::autoswitch::ReloadState>,
    controller_unix: Option<String>,
    flow_tokens: std::collections::HashMap<String, String>,
) -> Result<Session> {
    meow_common::set_host_resolver(Arc::new(
        meow_dns::ResolverHostHook::new_with_proxy_resolver(
            Arc::clone(&config.dns.resolver),
            config.dns.proxy_resolver.clone(),
        ),
    ));
    meow_common::logbook::apply(config.general.logbook);
    let _ = meow_api::log_stream::reload_log_level(&config.general.log_level);
    let tunnel = Tunnel::new_with_slot(Arc::clone(&config.dns.resolver_slot));
    tunnel.set_dialer_registry(config.provider_dialer_registry.clone());
    tunnel.set_mode(config.general.mode);
    tunnel.set_connection_notes(config.general.connection_notes);
    tunnel.set_tcp_idle_timeout(config.general.tcp_idle_timeout);
    tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
    tunnel.spawn_background_tasks();
    tunnel.reconcile_health_checks(&meow_config::extract_health_check_specs(
        config.raw.proxy_groups.as_deref().unwrap_or(&[]),
    ));
    let providers = Arc::new(
        config
            .proxy_providers
            .into_iter()
            .collect::<dashmap::DashMap<_, _>>(),
    );
    let rules = Arc::new(RwLock::new(config.rule_providers));
    let rule_refresh = Arc::new(meow_config::rule_provider_refresh::RefreshSupervisor::default());
    rule_refresh.reconcile(&rules);
    let proxy_refresh =
        Arc::new(meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor::default());
    proxy_refresh.reconcile(&providers, config.raw.proxy_providers.as_ref());
    meow_config::proxy_provider::spawn_deferred_initial_fetches(&providers);
    config.dropped_providers.record();
    let dns_handle = Arc::new(RwLock::new(None));
    if let Some(address) = config.dns.listen_addr {
        let server = meow_dns::DnsServer::new(Arc::clone(&config.dns.resolver), address);
        let resolver_slot = server.resolver_slot();
        let bound = server
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!("DNS bind: {e}"))?;
        let task = tokio::spawn(async move {
            if let Err(e) = bound.run().await {
                tracing::error!("DNS server stopped: {e}");
            }
        });
        *dns_handle.write() = Some(DnsServerHandle {
            listen: address,
            task,
            resolver_slot,
        });
    }
    let sniffer = Arc::new(SnifferRuntime::new(config.sniffer));
    let mut named = config.listeners.named;
    for listener in &mut named {
        #[cfg(unix)]
        if let Some(token) = flow_tokens.get(&listener.name) {
            let address = std::net::SocketAddr::new(listener.listen.parse()?, listener.port);
            crate::flowmeta::start(tunnel.clone(), address, token.clone()).await?;
            continue;
        }
        crate::listeners::start(
            listener,
            &tunnel,
            &sniffer,
            &config.auth,
            config.listeners.tcp_keepalive,
        )
        .await?;
    }
    let address = config.api.external_controller;
    let app = Arc::new(AppState {
        tunnel,
        secret: config.api.secret,
        config_path,
        raw_config: Arc::new(RwLock::new(config.raw)),
        log_tx: crate::logging::channel(),
        proxy_providers: providers,
        provider_dialer_registry: config.provider_dialer_registry,
        rule_providers: rules,
        rule_provider_refresh: rule_refresh,
        proxy_provider_refresh: proxy_refresh,
        listeners: named,
        external_ui: config.api.external_ui,
        traffic_feed: Default::default(),
        dns_server: dns_handle,
    });
    let autoswitch = crate::autoswitch::Service::new(app.tunnel.clone());
    let router = crate::control::router(
        Arc::clone(&app),
        autoswitch.clone(),
        controller_unix.clone(),
    );
    let unix_controller = match controller_unix {
        Some(path) => {
            #[cfg(unix)]
            {
                Some(UnixController::bind(path, router.clone())?)
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                bail!("Unix controllers are unavailable on this platform");
            }
        }
        None => None,
    };
    if let Some(address) = address {
        let socket = tokio::net::TcpListener::bind(address).await?;
        let service = router.clone();
        tokio::spawn(async move {
            if let Err(e) = axum::serve(socket, service).await {
                tracing::error!("Clash API stopped: {e}");
            }
        });
    }
    meow_common::logbook::engine_started(app.config_path.as_deref().unwrap_or("embedded"));
    if let Some(saved) = reload_state {
        autoswitch.restore_reload_state(saved).await;
    }
    autoswitch.apply(settings).await;
    Ok(Session {
        app,
        router,
        autoswitch,
        home: String::new(),
        base: String::new(),
        unix_controller,
        flow_tokens,
    })
}

/// Recreate startup-only listeners while retaining the Android TUN descriptor.
/// The caller reinstalls protection before each candidate/rollback build.
pub fn reload(
    home: &str,
    base: &str,
    bytes: &[u8],
    mut protect: impl FnMut() -> Result<()>,
) -> Result<()> {
    parse(bytes)?;
    let prior = SESSION
        .lock()
        .as_ref()
        .map(|session| -> Result<_> {
            let mut raw = serde_yaml::to_value(&*session.app.raw_config.read())?;
            // Named-listener deserialization ignores the private account. Preserve it
            // when rebuilding the rollback configuration after a failed reload.
            if let Some(listeners) = raw.get_mut("listeners").and_then(|v| v.as_sequence_mut()) {
                for listener in listeners {
                    let token = listener
                        .get("name")
                        .and_then(|v| v.as_str())
                        .and_then(|name| session.flow_tokens.get(name));
                    if let Some(token) = token {
                        listener["users"] = serde_yaml::to_value(vec![serde_json::json!({
                            "username": "__asterisk_flow_v1", "password": token
                        })])?;
                    }
                }
            }
            if let Some(controller) = &session.unix_controller {
                raw["external-controller-unix"] = controller.path.clone().into();
            }
            raw["asterisk-auto-switch"] = serde_yaml::to_value(
                crate::get_runtime().block_on(session.autoswitch.configured()),
            )?;
            Ok((
                session.home.clone(),
                session.base.clone(),
                serde_yaml::to_string(&raw)?,
                session.app.config_path.clone(),
            ))
        })
        .transpose()?;
    #[cfg(unix)]
    let tun = crate::tun2socks::retain_for_reload()?;
    let servers = meow_dns::system_dns::servers();
    let service = SESSION.lock().as_ref().map(|s| s.autoswitch.clone());
    let reload_state = service.map(|s| crate::get_runtime().block_on(s.suspend_for_reload()));
    let mut launch = |home: &str, base: &str, bytes: &[u8], path| -> Result<()> {
        if let Some(servers) = &servers {
            meow_dns::system_dns::update(servers.as_ref().clone());
        }
        protect()?;
        start_inner(home, base, bytes, path, reload_state.clone())?;
        #[cfg(unix)]
        if let Some((fd, dns)) = &tun {
            use std::os::fd::AsRawFd;
            crate::tun2socks::start(fd.as_raw_fd(), dns).map_err(anyhow::Error::msg)?;
        }
        Ok(())
    };
    stop();
    if let Err(error) = launch(home, base, bytes, None) {
        stop();
        if let Some((home, base, bytes, path)) = prior {
            if let Err(rollback) = launch(&home, &base, bytes.as_bytes(), path) {
                stop();
                bail!("{error:#}; restoring previous configuration failed: {rollback:#}");
            }
        }
        return Err(error);
    }
    Ok(())
}

pub fn stop() {
    #[cfg(unix)]
    crate::tun2socks::stop();
    let session = SESSION.lock().take();
    if let Some(session) = session {
        crate::get_runtime().block_on(session.autoswitch.stop());
        session.app.tunnel.statistics().close_all_connections();
        session.app.tunnel.close_all_udp_sessions();
        meow_common::logbook::engine_stopped(meow_common::logbook::Stop::Requested("stop"));
        drop(session);
    }
    // Dropping this session's runtime aborts/joins even upstream detached workers.
    crate::drop_runtime();
    meow_common::clear_host_resolver();
    crate::platform::clear();
    meow_dns::system_dns::update(Vec::new());
}

pub fn request(method: &str, path: &str, body: &str) -> Result<String> {
    let route = path.split('?').next().unwrap_or(path);
    if !path.starts_with('/')
        || path.starts_with("//")
        || matches!(route, "/logs" | "/traffic" | "/memory")
    {
        bail!("request requires a finite Clash API path; use traffic/readLogs for streams");
    }
    let (router, secret) = SESSION
        .lock()
        .as_ref()
        .map(|s| (s.router.clone(), s.app.secret.clone()))
        .context("meow is not running")?;
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(secret) = secret {
        request = request.header("authorization", format!("Bearer {secret}"));
    }
    let request = request.body(Body::from(body.to_owned()))?;
    crate::get_runtime().block_on(async {
        let response = router.oneshot(request).await?;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), 32 * 1024 * 1024).await?;
        Ok(
            serde_json::json!({"status":status, "body":String::from_utf8(body.to_vec())?})
                .to_string(),
        )
    })
}

pub fn traffic() -> Result<String> {
    let tunnel = tunnel().context("meow is not running")?;
    let (upload, download) = tunnel.statistics().snapshot();
    Ok(serde_json::json!({"uploadTotal": upload, "downloadTotal": download}).to_string())
}

pub fn query_auto_switch() -> Result<String> {
    let service = SESSION
        .lock()
        .as_ref()
        .map(|s| s.autoswitch.clone())
        .context("meow is not running")?;
    Ok(service.snapshot().to_string())
}

pub fn patch_auto_switch(json: &str) -> Result<()> {
    let settings = serde_json::from_str(json)?;
    let service = SESSION
        .lock()
        .as_ref()
        .map(|s| s.autoswitch.clone())
        .context("meow is not running")?;
    crate::get_runtime().block_on(async {
        let _mutation = service.mutations.lock().await;
        service.patch(settings).await
    })
}

pub fn validate(home: &str, base: &str, bytes: &[u8]) -> Result<()> {
    if is_running() {
        bail!("offline validation requires a stopped session");
    }
    if !Path::new(home).is_absolute() || !Path::new(base).is_absolute() {
        bail!("home and baseDirectory must be absolute paths");
    }
    let (raw, _, _) = parse(bytes)?;
    meow_common::set_home_dir(PathBuf::from(home));
    meow_config::set_offline_validate(true);
    let result = crate::get_runtime().block_on(async {
        let config = meow_config::build_config(raw, Some(Path::new(base))).await?;
        meow_api::ensure_listeners_supported(&config.listeners.named, crate::listeners::supported)?;
        Ok(())
    });
    crate::drop_runtime();
    meow_config::set_offline_validate(false);
    result
}
