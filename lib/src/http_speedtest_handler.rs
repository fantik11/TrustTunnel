use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;

use crate::{http_codec, log_id, log_utils, pipe};
use crate::http_codec::HttpCodec;

const MAX_DOWNLOAD_MB: u32 = 100;
const MAX_UPLOAD_MB: u32 = 120;
const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Default)]
struct SpeedtestManager {
    running_tests_num: usize,
}

enum Speedtest {
    Download(u32),
    Upload(u32),
}

pub(crate) async fn listen(mut codec: Box<dyn HttpCodec>, timeout: Duration, log_id: log_utils::IdChain<u64>) {
    let manager = Arc::new(Mutex::new(SpeedtestManager::default()));
    loop {
        match tokio::time::timeout(timeout, codec.listen()).await {
            Ok(Ok(Some(x))) => {
                let request_headers = x.request().request();
                log_id!(trace, x.id(), "Received request: {:?}", request_headers);
                match prepare_speedtest(request_headers) {
                    Ok(Speedtest::Download(n)) => {
                        manager.lock().unwrap().running_tests_num += 1;
                        tokio::spawn({
                            let manager = manager.clone();
                            async move {
                                run_download_test(x, n).await;
                                manager.lock().unwrap().running_tests_num -= 1;
                            }
                        });
                    }
                    Ok(Speedtest::Upload(n)) => {
                        tokio::spawn({
                            manager.lock().unwrap().running_tests_num += 1;
                            let manager = manager.clone();
                            async move {
                                run_upload_test(x, n).await;
                                manager.lock().unwrap().running_tests_num -= 1;
                            }
                        });
                    }
                    Err(description) => {
                        let log_id = x.id();
                        log_id!(debug, log_id, "Invalid request: {}", description);
                        if let Err(e) = x.split().1
                            .send_bad_response(http::StatusCode::BAD_REQUEST, Default::default())
                        {
                            log_id!(debug, log_id, "Failed to send bad response: {}", e);
                        }
                    }
                }
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
            Err(_elapsed) if manager.lock().unwrap().running_tests_num > 0 =>
                log_id!(trace, log_id, "Ignoring timeout due to there are some uncompleted tests"),
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

fn prepare_speedtest(request: &http_codec::RequestHeaders) -> Result<Speedtest, String> {
    match request.method {
        http::Method::GET => request.uri.path().strip_prefix('/')
            .and_then(|x| x.strip_suffix("mb.bin"))
            .and_then(|x| x.parse::<u32>().ok())
            .and_then(|x| (0 < x && x <= MAX_DOWNLOAD_MB).then_some(x))
            .map(|x| Speedtest::Download(x * 1024 * 1024))
            .ok_or_else(|| "Unexpected path".to_string()),
        http::Method::POST => {
            if request.uri.path() != "/upload.html" {
                return Err("Unexpected path".to_string());
            }

            request.headers.get(http::header::CONTENT_LENGTH)
                .and_then(|x| x.to_str().ok())
                .and_then(|x| x.parse::<u32>().ok())
                .and_then(|x| (0 < x && x <= MAX_UPLOAD_MB * 1024 * 1024).then_some(x))
                .map(Speedtest::Upload)
                .ok_or_else(|| format!("Unexpected {} header value", http::header::CONTENT_LENGTH))
        }
        _ => Err("Unexpected method".to_string()),
    }
}

async fn run_download_test(stream: Box<dyn http_codec::Stream>, n: u32) {
    let log_id = stream.id();
    log_id!(trace, log_id, "Running download test");

    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(())
        .unwrap()
        .into_parts().0;

    // @fixme: when running over HTTP/3 response sending fails with `TransportError(FinalSize)`
    let mut sink = match stream.split().1.send_response(response, false) {
        Ok(x) => x.into_pipe_sink(),
        Err(e) => {
            log_id!(debug, log_id, "Failed to respond request: {}", e);
            return;
        }
    };

    static CHUNK: Bytes = Bytes::from_static(&[0; CHUNK_SIZE]);

    let mut n = n as usize;
    while n > 0 {
        let chunk_length = std::cmp::min(CHUNK.len(), n);
        let chunk = CHUNK.slice(..chunk_length);

        match sink.write(chunk) {
            Ok(unsent) => n = n.saturating_sub(chunk_length - unsent.len()),
            Err(e) => {
                log_id!(debug, log_id, "Failed to send chunk: error='{}', remaining unsent {} bytes", e, n);
                return;
            }
        }

        if let Err(e) = sink.wait_writable().await {
            log_id!(debug, log_id, "Error on stream: error='{}', remaining unsent {} bytes", e, n);
            return;
        }
    }

    if let Err(e) = sink.eof() {
        log_id!(debug, log_id, "Failed to close stream gracefully: {}", e);
    }
}

async fn run_upload_test(stream: Box<dyn http_codec::Stream>, n: u32) {
    let log_id = stream.id();
    log_id!(trace, log_id, "Running upload test");
    let (request, respond) = stream.split();

    let mut source = request.finalize();
    let mut n = n as usize;
    while n > 0 {
        match source.read().await {
            Ok(pipe::Data::Chunk(x)) => {
                n = n.saturating_sub(x.len());
                if let Err(e) = source.consume(x.len()) {
                    log_id!(debug, log_id, "Failed to consume: error='{}', remaining unreceived {} bytes", e, n);
                    return;
                }
            }
            Ok(pipe::Data::Eof) => {
                log_id!(debug, log_id, "Stream closed, remaining unreceived {} bytes", n);
                break;
            }
            Err(e) => {
                log_id!(debug, log_id, "Error on stream: error='{}', remaining unreceived {} bytes", e, n);
                return;
            }
        }
    }

    if let Err(e) = respond.send_ok_response(true) {
        log_id!(debug, log_id, "Failed to respond request: {}", e);
    }
}
