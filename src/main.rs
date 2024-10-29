use std::net::SocketAddr;
use bytes::Bytes;
use http_body_util::{Full, Empty};
use http::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use std::sync::Arc;
use std::io;
use std::fs::File;
use hyper_util::server::conn::auto::Builder;
use hyper::body::Incoming;
use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};
use std::time::Duration;
use h3_quinn::VarInt;
use hyper::service::Service;
use std::future::Future;
use std::pin::Pin;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::net::ToSocketAddrs;
use rustls::RootCertStore;
use futures::future;
use tokio::io::AsyncWriteExt;
use rustls_native_certs::load_native_certs;
use http_body_util::BodyExt;
use hyper_tls::HttpsConnector;

const UPSTREAM_HOST: &str = "127.0.0.1";
const UPSTREAM_PORT: u16 = 4433;

#[derive(Clone)]
struct Http3Client {
    endpoint: quinn::Endpoint,
    root_store: Arc<RootCertStore>,
    transport_config: Arc<quinn::TransportConfig>,
}

impl Http3Client {
    fn new() -> io::Result<Self> {
        let mut root_store = RootCertStore::empty();
        let native_certs = load_native_certs();
        if native_certs.certs.is_empty() {
            eprintln!("No certificates found!");
            return Err(io::Error::new(io::ErrorKind::Other, "No certificates found"));
        }
        if !native_certs.errors.is_empty() {
            eprintln!("Some errors occurred while loading certificates: {:?}", native_certs.errors);
        }

        for cert in native_certs.certs {
            root_store.add(cert).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }

        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_idle_timeout(Some(VarInt::from_u32(10_000).into()))
            .keep_alive_interval(Some(Duration::from_secs(2)))
            .max_concurrent_bidi_streams(VarInt::from_u32(100));

        let endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        Ok(Self {
            endpoint,
            root_store: Arc::new(root_store),
            transport_config: Arc::new(transport_config),
        })
    }

    async fn connect(&self, addr: SocketAddr, server_name: &str) -> io::Result<quinn::Connection> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(self.root_store.clone())
            .with_no_client_auth();

        tls_config.enable_early_data = true;
        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
        ));
        client_config.transport_config(self.transport_config.clone());

        self.endpoint.connect_with(client_config, addr, server_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    async fn send_request(&self, req: Request<Bytes>, connection: quinn::Connection) 
        -> io::Result<Response<Bytes>> 
    {
        let h3_conn = h3_quinn::Connection::new(connection);
        let (mut driver, mut send_request) = h3::client::new(h3_conn)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let _drive = async move {
            future::poll_fn(|cx| driver.poll_close(cx)).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        };

        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, ());
        
        let mut stream = send_request.send_request(req)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        stream.send_data(body)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        stream.finish()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = stream.recv_response()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let body_bytes = Vec::new();

        while let Some(mut chunk) = stream.recv_data().await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))? {
            let mut out = tokio::io::stdout();
            out.write_all_buf(&mut chunk).await?;
            out.flush().await?;
        }

        Ok(Response::from_parts(
            response.into_parts().0,
            Bytes::from(body_bytes)
        ))
    }
}

#[derive(Clone)]
struct HttpProxy {
    h3_client: Http3Client,
    https_client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    http_client: Client<HttpConnector, Empty<Bytes>>,
}

impl HttpProxy {
    fn new() -> io::Result<Self> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        
        let mut root_store = RootCertStore::empty();
        let certs = load_native_certs().expect("Failed to load system certificates");

        for cert in certs {
            root_store.add(cert).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
        
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        
        let https = HttpsConnector::new_with_connector(http);
        
        Ok(Self {
            h3_client: Http3Client::new()?,
            https_client: Client::builder(TokioExecutor::new()).build(https),
            http_client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
        })
    }

    async fn try_http3_request(
        &self,
        req: &Request<Incoming>,
    ) -> io::Result<Response<Full<Bytes>>> {
        if let Ok(mut addrs) = (UPSTREAM_HOST, UPSTREAM_PORT).to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                if let Ok(conn) = self.h3_client.connect(addr, UPSTREAM_HOST).await {
                    let upstream_req = Request::builder()
                        .method(req.method())
                        .uri(format!(
                            "https://{}:{}{}",
                            UPSTREAM_HOST,
                            UPSTREAM_PORT,
                            req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
                        ))
                        .body(Bytes::new())
                        .unwrap();

                    if let Ok(response) = self.h3_client.send_request(upstream_req, conn).await {
                        let (parts, body) = response.into_parts();
                        return Ok(Response::from_parts(parts, Full::new(body)));
                    }
                }
            }
        }
        
        Err(io::Error::new(io::ErrorKind::Other, "HTTP/3 request failed"))
    }

    async fn try_https_request(
        &self,
        req: &mut Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        let upstream_uri = format!(
            "https://{}:{}{}",
            UPSTREAM_HOST,
            UPSTREAM_PORT,
            req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
        );

        let mut new_req = Request::builder()
            .method(req.method().clone())
            .uri(upstream_uri)
            .body(Empty::<Bytes>::new())?;

        *new_req.headers_mut() = req.headers().clone();
        
        let response = self.https_client.request(new_req).await?;
        let (parts, body) = response.into_parts();
        
        let mut bytes = bytes::BytesMut::new();
        let mut body_stream = body;

        while let Some(next) = body_stream.frame().await {
            if let Ok(frame) = next {
                if let Some(chunk) = frame.data_ref() {
                    if let Err(e) = tokio::io::stdout().write_all(&chunk).await {
                        eprintln!("Error when writing to stdout: {}", e);
                    }
                    bytes.extend_from_slice(&chunk);
                }
            }
        }

        Ok(Response::from_parts(parts, Full::new(bytes.freeze())))
    }

    async fn try_http_request(
        &self,
        req: &mut Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        let upstream_uri = format!(
            "http://{}:{}{}",
            UPSTREAM_HOST,
            UPSTREAM_PORT,
            req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
        );

        let mut new_req = Request::builder()
            .method(req.method().clone())
            .uri(upstream_uri)
            .body(Empty::<Bytes>::new())?;

        *new_req.headers_mut() = req.headers().clone();

        let response = self.http_client.request(new_req).await?;
        let (parts, body) = response.into_parts();
        
        let mut bytes = bytes::BytesMut::new();
        let mut body_stream = body;

        while let Some(next) = body_stream.frame().await {
            if let Ok(frame) = next {
                if let Some(chunk) = frame.data_ref() {
                    if let Err(e) = tokio::io::stdout().write_all(&chunk).await {
                        eprintln!("Error when writing to stdout: {}", e);
                    }
                    bytes.extend_from_slice(chunk);
                }
            }
        }

        Ok(Response::from_parts(parts, Full::new(bytes.freeze())))
    }

}

impl Service<Request<Incoming>> for HttpProxy {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        
        Box::pin(async move {
            match this.try_http3_request(&req).await {
                Ok(response) => {
                    println!("Successfully proxied using HTTP/3");
                    Ok(response)
                }
                Err(_) => {
                    match this.try_https_request(&mut req).await {
                        Ok(response) => {
                            println!("Successfully proxied using HTTPS");
                            Ok(response)
                        }
                        Err(e) => {
                            eprintln!("HTTPS request failed: {}, falling back to HTTP", e);
                            match this.try_http_request(&mut req).await {
                                Ok(response) => {
                                    println!("Successfully proxied using HTTP");
                                    Ok(response)
                                }
                                Err(e) => {
                                    eprintln!("HTTP request failed: {}", e);
                                    Ok(Response::builder()
                                        .status(StatusCode::BAD_GATEWAY)
                                        .body(Full::from(Bytes::from("Bad Gateway")))
                                        .unwrap())
                                }
                            }
                        }
                    }
                }
            }
        })
    }
}

async fn handle_h3_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let h3_client = Http3Client::new()?;
    
    if let Ok(mut addrs) = (UPSTREAM_HOST, UPSTREAM_PORT).to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            if let Ok(conn) = h3_client.connect(addr, UPSTREAM_HOST).await {
                let upstream_req = Request::builder()
                    .method(req.method())
                    .uri(format!(
                        "http://{}:{}{}",
                        UPSTREAM_HOST,
                        UPSTREAM_PORT,
                        req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
                    ))
                    .body(Bytes::new())
                    .unwrap();
    
                match h3_client.send_request(upstream_req, conn).await {
                    Ok(upstream_response) => {
                        let response = Response::builder()
                            .status(upstream_response.status())
                            .body(())
                            .unwrap();
    
                        stream.send_response(response).await?;
                        stream.send_data(upstream_response.into_body()).await?;
                        stream.finish().await?;
                        return Ok(());
                    }
                    Err(e) => eprintln!("HTTP/3 upstream request failed: {}", e),
                }
            }
        }
    }
    

    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(())
        .unwrap();

    stream.send_response(response).await?;
    stream.send_data(Bytes::from("Bad Gateway")).await?;
    stream.finish().await?;

    Ok(())
}

async fn handle_h3_connection(connection: quinn::Connection) -> Result<(), Box<dyn std::error::Error>> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
    
    loop {
        match h3_conn.accept().await {
            Ok(Some((req, stream))) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(req, stream).await {
                        eprintln!("Failed to handle HTTP/3 request: {}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                match e.get_error_level() {
                    ErrorLevel::ConnectionError => break,
                    ErrorLevel::StreamError => continue,
                }
            }
        }
    }
    Ok(())
}

fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certfile = File::open(filename)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    let keyfile = File::open(filename)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no private key found"))
}

fn configure_transport() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config
        .max_idle_timeout(Some(VarInt::from_u32(10_000).into()))
        .keep_alive_interval(Some(Duration::from_secs(2)))
        .max_concurrent_bidi_streams(VarInt::from_u32(100));
    config
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pretty_env_logger::init();

    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certs = load_certs("cert.pem")?;
    let key = load_private_key("key.pem")?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    
    server_config.alpn_protocols = vec![
        b"h3".to_vec(),
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
    
    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_config.clone())));
    let addr: SocketAddr = ([0, 0, 0, 0], 443).into();

    let mut h3server_config = quinn::ServerConfig::with_crypto(
        Arc::new(QuicServerConfig::try_from(server_config)?));
    h3server_config.transport_config(Arc::new(configure_transport()));

    let tcp_listener = TcpListener::bind(addr).await?;
    let h3_endpoint = quinn::Endpoint::server(h3server_config, addr)?;
    
    println!("Reverse proxy listening on https://{} (HTTP/3, HTTP/2, HTTP/1.1)", addr);
    println!("Forwarding to http://{}:{}", UPSTREAM_HOST, UPSTREAM_PORT);



    loop {
        tokio::select! {
            accept_result = h3_endpoint.accept() => {
                if let Some(connecting) = accept_result {
                    tokio::spawn(async move {
                        if let Ok(connection) = connecting.await {
                            if let Err(e) = handle_h3_connection(connection).await {
                                eprintln!("HTTP/3 connection error: {}", e);
                            }
                        }
                    });
                }
            }

            tcp_accept_result = tcp_listener.accept() => {
                if let Ok((stream, _)) = tcp_accept_result {
                    let tls_acceptor = tls_acceptor.clone();
                    let http_proxy = HttpProxy::new().expect("Failed to create HTTP proxy");
                    
                    tokio::spawn(async move {
                        if let Ok(tls_stream) = tls_acceptor.accept(stream).await {
                            if let Ok(()) = Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(tls_stream), http_proxy)
                                .await
                            {
                                println!("Connection completed successfully");
                            }
                        }
                    });
                }
            }
        }
    }
}