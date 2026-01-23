use crate::forwarder::TcpConnector;
use crate::http_codec::HttpCodec;
use crate::net_utils::TcpDestination;
use crate::pipe::DuplexPipe;
use crate::tcp_forwarder::TcpForwarder;
use crate::tls_demultiplexer::Protocol;
use crate::{core, forwarder, http1_codec, http_codec, log_id, log_utils, pipe, tunnel};
use bytes::{BufMut, BytesMut};
use std::io;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static ORIGINAL_PROTOCOL_HEADER: http::HeaderName =
    http::HeaderName::from_static("x-original-protocol");

#[derive(Default)]
struct SessionManager {
    active_streams_num: AtomicUsize,
}

pub(crate) async fn listen(
    context: Arc<core::Context>,
    mut codec: Box<dyn HttpCodec>,
    sni: String,
    log_id: log_utils::IdChain<u64>,
) {
    let (mut shutdown_notification, _shutdown_completion) = {
        let shutdown = context.shutdown.lock().unwrap();
        (shutdown.notification_handler(), shutdown.completion_guard())
    };

    tokio::select! {
        x = shutdown_notification.wait() => {
            match x {
                Ok(_) => (),
                Err(e) => log_id!(debug, log_id, "Shutdown notification failure: {}", e),
            }
        },
        _ = listen_inner(context, codec.as_mut(), sni, &log_id) => (),
    }

    if let Err(e) = codec.graceful_shutdown().await {
        log_id!(debug, log_id, "Failed to shutdown HTTP session: {}", e);
    }
}

async fn listen_inner(
    context: Arc<core::Context>,
    codec: &mut dyn HttpCodec,
    sni: String,
    log_id: &log_utils::IdChain<u64>,
) {
    let manager = Arc::new(SessionManager::default());
    let timeout = context.settings.connection_establishment_timeout;
    loop {
        match tokio::time::timeout(timeout, codec.listen()).await {
            Ok(Ok(Some(x))) => {
                tokio::spawn({
                    let context = context.clone();
                    let manager = manager.clone();
                    let protocol = codec.protocol();
                    let sni = sni.clone();
                    let log_id = log_id.clone();
                    async move {
                        manager.active_streams_num.fetch_add(1, Ordering::AcqRel);
                        if let Err(e) = handle_stream(context, x, protocol, sni, &log_id).await {
                            log_id!(debug, log_id, "Request failed: {}", e);
                        }
                        manager.active_streams_num.fetch_sub(1, Ordering::AcqRel);
                    }
                });
            }
            Ok(Ok(None)) => {
                log_id!(trace, log_id, "Connection closed");
                break;
            }
            Ok(Err(ref e)) if e.kind() == ErrorKind::UnexpectedEof => {
                log_id!(trace, log_id, "Connection closed");
                break;
            }
            Ok(Err(e)) => {
                log_id!(debug, log_id, "Session error: {}", e);
                break;
            }
            Err(_elapsed) if manager.active_streams_num.load(Ordering::Acquire) > 0 => log_id!(
                trace,
                log_id,
                "Ignoring timeout due to there are some active streams"
            ),
            Err(_elapsed) => {
                log_id!(debug, log_id, "Closing due to timeout");
                if let Err(e) = codec.graceful_shutdown().await {
                    log_id!(debug, log_id, "Failed to shut down session: {}", e);
                }
                break;
            }
        }
    }
}

async fn handle_stream(
    context: Arc<core::Context>,
    stream: Box<dyn http_codec::Stream>,
    protocol: Protocol,
    sni: String,
    log_id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    let (request, respond) = stream.split();
    log_id!(trace, log_id, "Received request: {:?}", request.request());

    let forwarder = Box::new(TcpForwarder::new(context.clone()));
    let settings = context.settings.reverse_proxy.as_ref().unwrap();
    let (mut server_source, mut server_sink) = forwarder
        .connect(
            log_id.clone(),
            forwarder::TcpConnectionMeta {
                client_address: Ipv4Addr::UNSPECIFIED.into(),
                destination: TcpDestination::Address(settings.server_address),
                auth: None,
                tls_domain: sni,
                user_agent: None,
            },
        )
        .await
        .map_err(|e| match e {
            tunnel::ConnectionError::Io(e) => e,
            _ => io::Error::new(ErrorKind::Other, format!("{}", e)),
        })?;

    let mut request_headers = request.clone_request();
    let original_version = request_headers.version;
    match protocol {
        Protocol::Http1 => (),
        Protocol::Http2 => unreachable!(),
        Protocol::Http3 => {
            request_headers.version = http::Version::HTTP_11;
            if settings.h3_backward_compatibility
                && request_headers.method == http::Method::GET
                && request_headers.uri.path() == "/"
            {
                request_headers.method = http::Method::CONNECT;
            }
        }
    }
    request_headers.headers.insert(
        &ORIGINAL_PROTOCOL_HEADER,
        http::HeaderValue::from_static(protocol.as_str()),
    );

    let encoded = http1_codec::encode_request(&request_headers);
    log_id!(
        trace,
        log_id,
        "Sending translated request: {:?}",
        request_headers
    );
    server_sink.write_all(encoded).await?;

    let mut buffer = BytesMut::new();
    let (response, chunk) = loop {
        match server_source.read().await? {
            pipe::Data::Chunk(chunk) => {
                server_source.consume(chunk.len())?;
                buffer.put(chunk);
            }
            pipe::Data::Eof => return Err(ErrorKind::UnexpectedEof.into()),
        }

        match http1_codec::decode_response(
            buffer,
            http1_codec::MAX_HEADERS_NUM,
            http1_codec::MAX_RAW_HEADERS_SIZE,
        )? {
            http1_codec::DecodeStatus::Partial(b) => buffer = b,
            http1_codec::DecodeStatus::Complete(mut h, tail) => {
                h.version = original_version; // restore the version in case it was not the same
                break (h, tail.freeze());
            }
        }
    };

    let mut client_sink = respond.send_response(response, false)?.into_pipe_sink();
    let chunk_len = chunk.len();
    client_sink.write_all(chunk).await?;
    server_source.consume(chunk_len)?;

    let mut pipe = DuplexPipe::new(
        (
            pipe::SimplexDirection::Outgoing,
            request.finalize(),
            server_sink,
        ),
        (pipe::SimplexDirection::Incoming, server_source, client_sink),
        |_, _| (),
    );

    pipe.exchange(context.settings.tcp_connections_timeout).await
}
