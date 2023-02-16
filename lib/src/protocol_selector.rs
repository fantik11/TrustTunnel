use std::io;
use std::io::ErrorKind;
use crate::net_utils;
use crate::settings::{ListenProtocolSettings, Settings};


#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum Protocol {
    Http1,
    Http2,
    Http3,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum Channel {
    Tunnel(Protocol),
    Ping(Protocol),
    Speed(Protocol),
    ReverseProxy(Protocol),
}

impl Protocol {
    pub fn as_alpn(&self) -> &'static str {
        match self {
            Self::Http1 => net_utils::HTTP1_ALPN,
            Self::Http2 => net_utils::HTTP2_ALPN,
            Self::Http3 => net_utils::HTTP3_ALPN,
        }
    }

    fn from_alpn(alpn: &str) -> Option<Self> {
        match alpn {
            net_utils::HTTP1_ALPN => Some(Protocol::Http1),
            net_utils::HTTP2_ALPN => Some(Protocol::Http2),
            net_utils::HTTP3_ALPN => Some(Protocol::Http3),
            _ => None,
        }
    }
}

impl Channel {
    pub fn as_alpn(&self) -> &'static str {
        match self {
            Self::Tunnel(proto) => proto.as_alpn(),
            Self::Ping(proto) => proto.as_alpn(),
            Self::Speed(proto) => proto.as_alpn(),
            Self::ReverseProxy(proto) => proto.as_alpn(),
        }
    }
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http1 => "HTTP1",
            Self::Http2 => "HTTP2",
            Self::Http3 => "HTTP3",
        }
    }
}

pub(crate) fn select(settings: &Settings, alpn: Option<&str>, sni: &str) -> io::Result<Channel> {
    let proto = Protocol::from_alpn(alpn.unwrap_or(net_utils::HTTP1_ALPN))
        .ok_or_else(|| io::Error::new(ErrorKind::Other, format!("Unexpected ALPN: {:?}", alpn)))?;

    let channel = if Some(sni) == settings.reverse_proxy.as_ref().map(|s| s.tls_info.hostname.as_str()) {
        match proto {
            Protocol::Http1 | Protocol::Http3 => Channel::ReverseProxy(proto),
            Protocol::Http2 => return Err(io::Error::new(
                ErrorKind::Other, format!("Unexpected ALPN on reverse proxy connection {:?}", alpn)
            )),
        }
    } else if Some(sni) == settings.ping_tls_host_info.as_ref().map(|i| i.hostname.as_str()) {
        Channel::Ping(proto)
    } else if Some(sni) == settings.speed_tls_host_info.as_ref().map(|i| i.hostname.as_str()) {
        Channel::Speed(proto)
    } else {
        Channel::Tunnel(proto)
    };

    match channel {
        Channel::Tunnel(x) => {
            if settings.listen_protocols.iter()
                .any(|i| matches!(
                    (i, &x),
                    (ListenProtocolSettings::Http1(_), Protocol::Http1)
                        | (ListenProtocolSettings::Http2(_), Protocol::Http2)
                        | (ListenProtocolSettings::Quic(_), Protocol::Http3)
                ))
            {
                Ok(Channel::Tunnel(x))
            } else {
                Err(io::Error::new(
                    ErrorKind::Other, format!("Selected protocol is not being listened to: {:?}", x)
                ))
            }
        }
        x => Ok(x),
    }
}
