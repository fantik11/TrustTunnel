'''use crate::authentication::{Status, SessionGuard};
use crate::downstream::{
    Downstream, PendingDatagramMultiplexerRequest, PendingDemultiplexedRequest,
    PendingTcpConnectRequest,
};
use crate::forwarder::Forwarder;
use crate::pipe::DuplexPipe;
use crate::{
    authentication, core, datagram_pipe, downstream, forwarder, log_id, log_utils, pipe, udp_pipe,
};
use std::fmt::{Display, Formatter};
use std::io;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Clone)]
pub(crate) enum AuthenticationPolicy<'this> {
    Default,
    Authenticated(authentication::Source<'this>),
}

pub(crate) struct Tunnel {
    context: Arc<core::Context>,
    downstream: Box<dyn Downstream>,
    forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
    authentication_policy: AuthenticationPolicy<'static>,
    id: log_utils::IdChain<u64>,
}

#[derive(Debug)]
pub(crate) enum ConnectionError {
    Io(io::Error),
    Authentication(String),
    Timeout,
    HostUnreachable,
    DnsNonroutable,
    DnsLoopback,
    Other(String),
}

impl Display for ConnectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(x) => write!(f, "IO error: {}", x),
            Self::Authentication(x) => write!(f, "Authentication error: {}", x),
            Self::Timeout => write!(f, "Connection timed out"),
            Self::HostUnreachable => write!(f, "Remote host is unreachable"),
            Self::DnsNonroutable => write!(f, "DNS: resolved address in non-routable network"),
            Self::DnsLoopback => write!(f, "DNS: resolved address in loopback"),
            Self::Other(x) => write!(f, "{}", x),
        }
    }
}

impl Tunnel {
    pub fn new(
        context: Arc<core::Context>,
        downstream: Box<dyn Downstream>,
        forwarder: Box<dyn Forwarder>,
        authentication_policy: AuthenticationPolicy<'static>,
        id: log_utils::IdChain<u64>,
    ) -> Self {
        Self {
            context,
            downstream,
            forwarder: Arc::new(Mutex::new(forwarder)),
            authentication_policy,
            id,
        }
    }

    pub async fn listen(&mut self) -> io::Result<()> {
        let (mut shutdown_notification, _shutdown_completion) = {
            let shutdown = self.context.shutdown.lock().unwrap();
            (shutdown.notification_handler(), shutdown.completion_guard())
        };
        tokio::select! {
            x = shutdown_notification.wait() => {
                match x {
                    Ok(_) => self.downstream.graceful_shutdown().await,
                    Err(e) => Err(io::Error::new(ErrorKind::Other, format!("{}", e))),
                }
            }
            x = self.listen_inner() => x,
        }
    }

    async fn listen_inner(&mut self) -> io::Result<()> {
        loop {
            log_id!(trace, self.id, "Tunnel waiting for request");
            let request = match tokio::time::timeout(
                self.context.settings.client_listener_timeout,
                self.downstream.listen(),
            )
            .await
            {
                Ok(Ok(None)) => {
                    log_id!(debug, self.id, "Tunnel closed gracefully");
                    return Ok(());
                }
                Ok(Ok(Some(r))) => {
                    log_id!(trace, self.id, "Tunnel received request");
                    r
                }
                Ok(Err(e)) => {
                    log_id!(trace, self.id, "Tunnel listen error: {}", e);
                    return Err(e);
                }
                Err(_) => {
                    log_id!(trace, self.id, "Tunnel listen timeout");
                    return Err(io::Error::from(ErrorKind::TimedOut));
                }
            };

            let context = self.context.clone();
            let forwarder = self.forwarder.clone();
            let tls_domain = self.downstream.tls_domain().to_string();
            let authentication_policy = self.authentication_policy.clone();
            let log_id = self.id.clone();
            let update_metrics = {
                let metrics = context.metrics.clone();
                let protocol = self.downstream.protocol();
                move |direction, n| match direction {
                    pipe::SimplexDirection::Incoming => metrics.add_inbound_bytes(protocol, n),
                    pipe::SimplexDirection::Outgoing => metrics.add_outbound_bytes(protocol, n),
                }
            };

            tokio::spawn(async move {
                let request_id = request.id();
                log_id!(trace, request_id, "Processing tunnel request");

                // --- Start of Authentication ---
                let (forwarder_auth, _session_guard, kill_signal) = {
                    let auth_source_result = request.auth_info().map(|x| x.map(authentication::Source::into_owned));
                    
                    match (auth_source_result, authentication_policy, context.authenticator.as_ref()) {
                        (Ok(Some(source)), _, Some(authenticator)) => {
                            match authenticator.authenticate(&source, &log_id) {
                                Status::Pass(guard, signal) => (Some(source), guard, signal),
                                Status::Reject => {
                                    let err = ConnectionError::Authentication("Authentication failed".to_string());
                                    log_id!(debug, request_id, "{}", err);
                                    request.fail_request(err);
                                    return;
                                }
                            }
                        }
                        (Ok(None), AuthenticationPolicy::Authenticated(source), _) => {
                             (Some(source), Arc::new(()) as Arc<dyn SessionGuard>, Arc::new(Notify::new()))
                        }
                        (Ok(None), AuthenticationPolicy::Default, Some(_)) => {
                            let err = ConnectionError::Authentication("Request lacks authentication info".to_string());
                            log_id!(debug, request_id, "{}", err);
                            request.fail_request(err);
                            return;
                        }
                        (Err(e), ..) => {
                            log_id!(debug, request_id, "Failed to get auth info: {}", e);
                            request.fail_request(ConnectionError::Io(e));
                            return;
                        }
                        _ => { // No authenticator or no auth info provided
                            (None, Arc::new(()) as Arc<dyn SessionGuard>, Arc::new(Notify::new()))
                        }
                    }
                };
                // --- End of Authentication ---

                let tunnel_task = async {
                    log_id!(trace, request_id, "Authentication complete, promoting request");
                    match request.promote_to_next_state() {
                        Ok(None) => {
                            log_id!(trace, request_id, "Health check request completed");
                        }
                        Ok(Some(PendingDemultiplexedRequest::TcpConnect(request))) => {
                            log_id!(trace, request_id, "Handling TCP connect request");
                            if let Err((request, message, e)) = Tunnel::on_tcp_connect_request(
                                context.clone(),
                                forwarder,
                                request,
                                forwarder_auth,
                                tls_domain,
                                update_metrics,
                            )
                            .await
                            {
                                if let ConnectionError::Io(io) = &e {
                                    if core::Core::is_too_many_open_files_error(io) {
                                        context.report_fatal_io_error(io);
                                    }
                                }
                                log_id!(debug, request_id, "{}: {}", message, e);
                                if let Some(request) = request {
                                    request.fail_request(e);
                                }
                            }
                        }
                        Ok(Some(PendingDemultiplexedRequest::DatagramMultiplexer(request))) => {
                            log_id!(trace, request_id, "Handling datagram multiplexer request");
                             if let Err((request, message, e)) = Tunnel::on_datagram_mux_request(
                                context.clone(),
                                forwarder,
                                request,
                                forwarder_auth,
                                tls_domain,
                                update_metrics,
                            )
                            .await
                            {
                                if let ConnectionError::Io(io) = &e {
                                    if core::Core::is_too_many_open_files_error(io) {
                                        context.report_fatal_io_error(io);
                                    }
                                }
                                log_id!(debug, request_id, "{}: {}", message, e);
                                if let Some(request) = request {
                                    request.fail_request(e);
                                }
                            }
                        }
                        Err(e) => {
                            log_id!(debug, request_id, "Failed to complete request: {}", e);
                        }
                    }
                };

                tokio::select! {
                    _ = tunnel_task => {
                        // Tunnel finished its work normally (or with an error)
                        log_id!(trace, request_id, "Tunnel task finished.");
                    }
                    _ = kill_signal.notified() => {
                        // Received a kill signal due to session limit
                        log_id!(info, request_id, "Session limit exceeded. Forcibly disconnecting.");
                        // By exiting the select!, all local variables including the network socket
                        // will be dropped, causing the connection to terminate.
                    }
                }
            });
        }
    }

    async fn on_tcp_connect_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone>(
        context: Arc<core::Context>,
        forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
        request: Box<dyn PendingTcpConnectRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        tls_domain: String,
        update_metrics: F,
    ) -> Result<(), (Option<Box<dyn PendingTcpConnectRequest>>, &'static str, ConnectionError)> {
        let request_id = request.id();
        log_id!(trace, request_id, "TCP connect: extracting destination");
        let destination = match request.destination() {
            Ok(d) => {
                log_id!(trace, request_id, "TCP connect: destination={:?}", d);
                d
            }
            Err(e) => {
                return Err((Some(request), "Failed to get destination", ConnectionError::Io(e)))
            }
        };

        let meta = forwarder::TcpConnectionMeta {
            client_address: match request.client_address() {
                Ok(x) => x,
                Err(e) => {
                    return Err((Some(request), "Failed to get client address", ConnectionError::Io(e)))
                }
            },
            destination,
            tls_domain,
            auth: forwarder_auth,
            user_agent: request.user_agent(),
        };

        log_id!(trace, request_id, "TCP connect: connecting to peer");
        let connector = forwarder.lock().unwrap().tcp_connector();
        let (fwd_rx, fwd_tx) = match tokio::time::timeout(
            context.settings.connection_establishment_timeout,
            connector.connect(request_id.clone(), meta.clone()),
        )
        .await
        .unwrap_or(Err(ConnectionError::Timeout))
        {
            Ok(x) => {
                log_id!(trace, request_id, "TCP connect: peer connection established");
                x
            }
            Err(e) => return Err((Some(request), "Connection to peer failed", e)),
        };

        log_id!(debug, request_id, "Successfully connected to {:?}", meta);
        log_id!(trace, request_id, "TCP connect: promoting downstream request");
        let (dstr_rx, dstr_tx) = match request.promote_to_next_state() {
            Ok(x) => {
                log_id!(trace, request_id, "TCP connect: downstream ready, starting pipe");
                x
            }
            Err(e) => return Err((None, "Failed to complete request", ConnectionError::Io(e))),
        };

        let mut pipe = DuplexPipe::new(
            (pipe::SimplexDirection::Outgoing, dstr_rx, fwd_tx),
            (pipe::SimplexDirection::Incoming, fwd_rx, dstr_tx),
            update_metrics,
        );

        log_id!(trace, request_id, "TCP connect: pipe exchange started");
        match pipe.exchange(context.settings.tcp_connections_timeout).await {
            Ok(_) => {
                log_id!(trace, request_id, "TCP connect: pipe closed gracefully");
                Ok(())
            }
            Err(e) => {
                log_id!(trace, request_id, "TCP connect: pipe error: {}", e);
                Err((None, "Error on pipe", ConnectionError::Io(e)))
            }
        }
    }

    async fn on_datagram_mux_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone + Sync>(
        context: Arc<core::Context>,
        forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
        request: Box<dyn PendingDatagramMultiplexerRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        tls_domain: String,
        update_metrics: F,
    ) -> Result<(), (Option<Box<dyn PendingDatagramMultiplexerRequest>>, &'static str, ConnectionError)> {
        let request_id = request.id();
        let client_address = match request.client_address() {
            Ok(x) => x,
            Err(e) => {
                return Err((Some(request), "Failed to get client address", ConnectionError::Io(e)))
            }
        };
        let user_agent = request.user_agent();

        if let Some(auth) = &forwarder_auth {
            let authenticator = forwarder.lock().unwrap().datagram_mux_authenticator();
            if let Err(e) = authenticator
                .check_auth(
                    client_address,
                    &tls_domain,
                    auth.clone(),
                    user_agent.as_ref().map(String::as_ref),
                )
                .await
            {
                return Err((Some(request), "Failed to authenticate", e));
            }
        }

        let mut pipe: Box<dyn datagram_pipe::DuplexPipe> = match request.promote_to_next_state() {
            Ok(downstream::DatagramPipeHalves::Udp(dstr_source, dstr_sink)) => {
                let meta = forwarder::UdpMultiplexerMeta {
                    client_address,
                    auth: forwarder_auth,
                    tls_domain,
                    user_agent,
                };
                let (fwd_shared, fwd_source, fwd_sink) = match forwarder
                    .lock()
                    .unwrap()
                    .make_udp_datagram_multiplexer(request_id.clone(), meta)
                {
                    Ok(x) => x,
                    Err(e) => {
                        return Err((None, "Failed to create datagram multiplexer", ConnectionError::Io(e)))
                    }
                };

                Box::new(udp_pipe::DuplexPipe::new(
                    (dstr_source, dstr_sink),
                    (fwd_shared, fwd_source, fwd_sink),
                    update_metrics,
                    context.settings.udp_connections_timeout,
                ))
            }
            Ok(downstream::DatagramPipeHalves::Icmp(dstr_source, dstr_sink)) => {
                let (fwd_source, fwd_sink) = match forwarder
                    .lock()
                    .unwrap()
                    .make_icmp_datagram_multiplexer(request_id.clone())
                {
                    Ok(Some(x)) => x,
                    Ok(None) => {
                        return Err((None, "ICMP forwarding isn't set up", ConnectionError::Other("Not allowed".to_string())))
                    }
                    Err(e) => {
                        return Err((None, "Failed to create datagram multiplexer", ConnectionError::Io(e)))
                    }
                };

                Box::new(datagram_pipe::GenericDuplexPipe::new(
                    (pipe::SimplexDirection::Outgoing, dstr_source, fwd_sink),
                    (pipe::SimplexDirection::Incoming, fwd_source, dstr_sink),
                    update_metrics,
                ))
            }
            Err(e) => {
                return Err((None, "Failed to respond for datagram multiplexer request", ConnectionError::Io(e)))
            }
        };

        match pipe.exchange().await {
            Ok(_) => {
                log_id!(trace, request_id, "Datagram multiplexer gracefully closed");
                Ok(())
            }
            Err(e) => Err((None, "Datagram multiplexer closed with error", ConnectionError::Io(e))),
        }
    }
}
''