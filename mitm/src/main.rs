mod config;
mod ad_inject;
mod forward;

use std::sync::Arc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;
use std::time::{Duration, SystemTime};
use tokio::net::{TcpListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::body::{Body, Incoming};
use hyper::{Request, Response, StatusCode, Method, Uri};
use hyper_rustls::TlsAcceptor;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, Certificate as RcgenCert};
use tracing::{info, warn, error, debug};
use tracing_subscriber;

use config::Config;
use ad_inject::inject_ad_blocker;

// ---------- Certificate Cache ----------
struct CertCache {
    ca: Arc<Ca>,
    cache: Arc<RwLock<HashMap<String, (CertificateDer<'static>, PrivateKeyDer<'static>, SystemTime)>>>,
    ttl: Duration,
}

impl CertCache {
    fn new(ca: Arc<Ca>, ttl_secs: u64) -> Self {
        CertCache {
            ca,
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    async fn get_or_create(&self, hostname: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), anyhow::Error> {
        {
            let cache = self.cache.read().await;
            if let Some((cert, key, expiry)) = cache.get(hostname) {
                if SystemTime::now() < *expiry {
                    return Ok((cert.clone(), key.clone()));
                }
            }
        }

        // Generate new leaf cert signed by CA
        let mut params = CertificateParams::new(vec![hostname.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
        let key_pair = KeyPair::generate()?;
        let ca_cert = RcgenCert::from_der(self.ca.cert.as_ref())?;
        let ca_key = rcgen::PrivateKey::from_der(self.ca.key.secret_der())?;
        let cert = params.signed_by(&key_pair, &ca_cert, &ca_key)?;
        let cert_der = CertificateDer::from(cert.serialize_der()?);
        let key_der = PrivateKeyDer::from(key_pair.serialize_der());
        let expiry = SystemTime::now() + self.ttl;

        {
            let mut cache = self.cache.write().await;
            cache.insert(hostname.to_string(), (cert_der.clone(), key_der.clone(), expiry));
        }
        Ok((cert_der, key_der))
    }
}

// ---------- CA Struct ----------
struct Ca {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl Ca {
    fn load_or_create(ca_dir: &PathBuf) -> Result<Self, anyhow::Error> {
        fs::create_dir_all(ca_dir)?;
        let cert_path = ca_dir.join("ca.cert");
        let key_path = ca_dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read(&cert_path)?;
            let key_pem = fs::read(&key_path)?;
            let cert = rustls_pemfile::certs(&mut cert_pem.as_slice())
                .next()
                .ok_or_else(|| anyhow::anyhow!("No cert found"))?;
            let key = rustls_pemfile::private_keys(&mut key_pem.as_slice())
                .next()
                .ok_or_else(|| anyhow::anyhow!("No key found"))?;
            Ok(Ca { cert, key })
        } else {
            // Generate new CA
            let mut params = CertificateParams::default();
            params.distinguished_name = DistinguishedName::new();
            params.distinguished_name.push(rcgen::DnType::CommonName, "PhantomD MITM CA");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::DigitalSignature];
            let key_pair = KeyPair::generate()?;
            let cert = params.self_signed(&key_pair)?;
            let cert_der = CertificateDer::from(cert.serialize_der()?);
            let key_der = PrivateKeyDer::from(key_pair.serialize_der());
            fs::write(&cert_path, cert_der.as_ref())?;
            fs::write(&key_path, key_der.secret_der())?;
            Ok(Ca { cert: cert_der, key: key_der })
        }
    }
}

// ---------- Resolver that uses CertCache ----------
struct DynamicCertResolver {
    cache: Arc<CertCache>,
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let sni = server_name.unwrap_or("default").to_string();
        let cache = self.cache.clone();
        // This method is synchronous, but we need async to generate certs.
        // Must use a blocking runtime or pre-generate. We'll pre-generate.
        // For simplicity, use tokio::runtime::Handle::current().block_on
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let (cert, key) = handle.block_on(async { cache.get_or_create(&sni).await.ok()? });
        let key_any = rustls::sign::any_supported_type(&key).ok()?;
        Some(Arc::new(CertifiedKey::new(vec![cert], Arc::new(key_any))))
    }
}

// ---------- Forward DoH to phantomd via Unix socket ----------
async fn forward_doh_to_phantomd(socket_path: &PathBuf, dns_wire: bytes::Bytes) -> Result<Vec<u8>, anyhow::Error> {
    let mut stream = UnixStream::connect(socket_path).await?;
    let len = (dns_wire.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&dns_wire).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

// ---------- Request handler ----------
async fn handle_request(
    req: Request<Incoming>,
    config: Arc<Config>,
    cert_cache: Arc<CertCache>,
    sni: Option<String>,
) -> Result<Response<Body>, hyper::Error> {
    let is_doh = req.method() == Method::POST
        && req.headers().get("content-type")
            .map(|v| v.as_bytes()) == Some(b"application/dns-message")
        && req.uri().path().contains("/dns-query");

    if is_doh {
        let body = req.collect().await?.to_bytes();
        match forward_doh_to_phantomd(&config.socket_path, body).await {
            Ok(dns_response) => {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/dns-message")
                    .body(Body::from(dns_response))
                    .unwrap();
                Ok(response)
            }
            Err(e) => {
                error!("DoH forward error: {}", e);
                let response = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Upstream DNS error"))
                    .unwrap();
                Ok(response)
            }
        }
    } else if config.ad_block_enabled {
        // This is a normal web request. Fetch from origin, inject ad-block script, return.
        let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
        let scheme = if sni.is_some() { "https" } else { "http" };
        let uri_str = format!("{}://{}{}", scheme, host, req.uri().path());
        let uri = uri_str.parse::<Uri>().unwrap_or_else(|_| "/".parse().unwrap());
        let mut origin_resp = forward::forward_request(req, uri).await?;
        let is_html = origin_resp.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/html"))
            .unwrap_or(false);
        if is_html && origin_resp.status().is_success() {
            let body_bytes = hyper::body::to_bytes(origin_resp.body_mut()).await?;
            let modified = inject_ad_blocker(&body_bytes);
            let mut resp = Response::builder()
                .status(origin_resp.status())
                .body(Body::from(modified))
                .unwrap();
            for (k, v) in origin_resp.headers().iter() {
                if k.as_str() != "content-length" {
                    resp.headers_mut().insert(k.clone(), v.clone());
                }
            }
            resp.headers_mut().insert("content-length", modified.len().into());
            Ok(resp)
        } else {
            Ok(origin_resp)
        }
    } else {
        // Forward non-DoH without modification
        let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
        let scheme = if sni.is_some() { "https" } else { "http" };
        let uri_str = format!("{}://{}{}", scheme, host, req.uri().path());
        let uri = uri_str.parse::<Uri>().unwrap_or_else(|_| "/".parse().unwrap());
        forward::forward_request(req, uri).await
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let args: Vec<String> = std::env::args().collect();
    let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("mitm-config.toml");
    let config = Config::from_file(config_path)?;

    let ca = Arc::new(Ca::load_or_create(&config.ca_dir)?);
    let cert_cache = Arc::new(CertCache::new(ca, config.cert_cache_ttl_secs));
    let resolver = Arc::new(DynamicCertResolver { cache: cert_cache.clone() });

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(&config.listen_addr).await?;
    info!("MITM proxy listening on {}", config.listen_addr);

    let config = Arc::new(config);
    loop {
        let (stream, _) = listener.accept().await?;
        let config = config.clone();
        let tls_acceptor = tls_acceptor.clone();
        let cert_cache = cert_cache.clone();
        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let sni = tls_stream.get_ref().0.negotiated_server_name().map(|s| s.to_string());
                    let service = service_fn(move |req| {
                        let config = config.clone();
                        let cert_cache = cert_cache.clone();
                        let sni = sni.clone();
                        handle_request(req, config, cert_cache, sni)
                    });
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(tls_stream, service)
                        .await
                    {
                        debug!("Connection error: {}", e);
                    }
                }
                Err(e) => warn!("TLS handshake failed: {}", e),
            }
        });
    }
}