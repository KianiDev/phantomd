use hyper::{Request, Response, Body, Uri, StatusCode};
use hyper::body::Incoming;
use hyper::client::conn::http1::Builder as ClientBuilder;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use tokio::net::TcpStream;
use rustls::ClientConfig;
use std::sync::Arc;
use http_body_util::BodyExt;

pub async fn forward_request(req: Request<Incoming>, uri: Uri) -> Result<Response<Body>, hyper::Error> {
    let scheme = uri.scheme_str().unwrap_or("http");
    let host = uri.host().unwrap_or("");
    let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });

    if scheme == "https" {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = ClientBuilder::new().build(https);
        let response = client.request(req).await?;
        Ok(response)
    } else {
        let stream = TcpStream::connect((host, port)).await.map_err(|e| hyper::Error::new(hyper::error::ErrorKind::Connect, e))?;
        let (mut sender, conn) = ClientBuilder::new()
            .handshake(stream)
            .await?;
        tokio::spawn(async move { conn.await });
        let response = sender.send_request(req).await?;
        Ok(response)
    }
}