use std::io;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::Arc;
use bytes::{BufMut, BytesMut};
use crate::{core, forwarder, http1_codec, log_id, log_utils, pipe, tunnel};
use crate::forwarder::TcpConnector;
use crate::http_codec::HttpCodec;
use crate::net_utils::TcpDestination;
use crate::pipe::DuplexPipe;
use crate::protocol_selector::Protocol;
use crate::tcp_forwarder::TcpForwarder;


const ORIGINAL_PROTOCOL_HEADER: &str = "X-Original-Protocol";


pub(crate) async fn listen(
    context: Arc<core::Context>,
    mut codec: Box<dyn HttpCodec>,
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
        x = listen_inner(context, codec.as_mut(), &log_id) => {
            match x {
                Ok(_) => (),
                Err(e) => log_id!(debug, log_id, "Request processing failure: {}", e),
            }
        },
    }

    if let Err(e) = codec.graceful_shutdown().await {
        log_id!(debug, log_id, "Failed to shutdown HTTP session: {}", e);
    }
}

async fn listen_inner(
    context: Arc<core::Context>,
    codec: &mut dyn HttpCodec,
    log_id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    let mut pipe = match tokio::time::timeout(
        context.settings.reverse_proxy.as_ref().unwrap().connection_timeout,
        establish_tunnel(&context, codec, log_id)
    ).await.map_err(|_| io::Error::from(ErrorKind::TimedOut))?? {
        Some(((client_source, client_sink), (server_source, server_sink))) =>
            DuplexPipe::new(
                (pipe::SimplexDirection::Outgoing, client_source, server_sink),
                (pipe::SimplexDirection::Incoming, server_source, client_sink),
                |_, _| (),
            ),
        None => return Ok(()),
    };

    let listen_io = async move {
        match codec.listen().await {
            Ok(Some(x)) => Err(io::Error::new(
                ErrorKind::Other,
                format!("Got unexpected request while processing previous: {:?}", x.request().request())
            )),
            Ok(None) => Ok(()),
            Err(e) => Err(e),
        }
    };

    tokio::try_join!(
        listen_io,
        pipe.exchange(context.settings.reverse_proxy.as_ref().unwrap().connection_timeout),
    ).map(|_| ())
}

async fn establish_tunnel(
    context: &core::Context,
    codec: &mut dyn HttpCodec,
    log_id: &log_utils::IdChain<u64>,
) -> io::Result<Option<(
    (Box<dyn pipe::Source>, Box<dyn pipe::Sink>),
    (Box<dyn pipe::Source>, Box<dyn pipe::Sink>),
)>> {
    let (request, respond) = match codec.listen().await? {
        Some(x) => x.split(),
        None => {
            log_id!(debug, log_id, "Connection closed before any request");
            return Ok(None);
        }
    };
    log_id!(trace, log_id, "Received request: {:?}", request.request());

    let forwarder = Box::new(TcpForwarder::new(context.settings.clone()));
    let (mut server_source, mut server_sink) = forwarder.connect(
        log_id.clone(),
        forwarder::TcpConnectionMeta {
            client_address: Ipv4Addr::UNSPECIFIED.into(),
            destination: TcpDestination::Address(context.settings.reverse_proxy.as_ref().unwrap().server_address),
            auth: None,
            tls_domain: context.settings.reverse_proxy.as_ref().unwrap().tls_info.hostname.clone(),
            user_agent: None,
        },
    ).await.map_err(|e| match e {
        tunnel::ConnectionError::Io(e) => e,
        _ => io::Error::new(ErrorKind::Other, format!("{}", e)),
    })?;

    let mut request_headers = request.clone_request();
    let original_version = request_headers.version;
    match codec.protocol() {
        Protocol::Http1 => (),
        Protocol::Http2 => unreachable!(),
        Protocol::Http3 => {
            request_headers.version = http::Version::HTTP_11;
            if context.settings.reverse_proxy.as_ref().unwrap().h3_backward_compatibility
                && request_headers.method == http::Method::GET
                && request_headers.uri.path() == "/"
            {
                request_headers.method = http::Method::CONNECT;
            }
        }
    }
    request_headers.headers.insert(
        ORIGINAL_PROTOCOL_HEADER,
        http::HeaderValue::from_static(codec.protocol().as_str())
    );

    let encoded = http1_codec::encode_request(&request_headers);
    log_id!(trace, log_id, "Sending translated request: {:?}", request_headers);
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
            buffer, http1_codec::MAX_HEADERS_NUM, http1_codec::MAX_RAW_HEADERS_SIZE,
        )? {
            http1_codec::DecodeStatus::Partial(b) => buffer = b,
            http1_codec::DecodeStatus::Complete(mut h, tail) => {
                h.version = original_version; // restore the version in case it was not the same
                break (h, tail.freeze())
            },
        }
    };

    let mut client_sink = respond.send_response(response, false)?
        .into_pipe_sink();
    client_sink.write_all(chunk).await?;

    Ok(Some((
        (request.finalize(), client_sink),
        (server_source, server_sink),
    )))
}
