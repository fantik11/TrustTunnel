pub mod registry_based;

use crate::log_utils;
use std::borrow::Cow;
use std::sync::Arc;
use tokio::sync::Notify;

/// Authentication request source
#[derive(Debug, Clone, PartialEq)]
pub enum Source<'this> {
    /// A client tries to authenticate using SNI
    Sni(Cow<'this, str>),
    /// A client tries to authenticate using
    /// [the basic authentication scheme](https://datatracker.ietf.org/doc/html/rfc7617)
    ProxyBasic(Cow<'this, str>),
}

/// A marker trait for session guards
pub trait SessionGuard: Send + Sync + 'static {}
impl SessionGuard for () {}

/// Authentication procedure status
#[derive(Clone)]
pub enum Status {
    /// Success. Carries:
    /// 1. A session guard (RAII): the session is considered active as long as this is alive.
    /// 2. A kill signal: the tunnel should terminate itself if this Notify is triggered.
    Pass(Arc<dyn SessionGuard>, Arc<Notify>),
    /// Failure
    Reject,
}

/// The authenticator abstract interface
pub trait Authenticator: Send + Sync {
    /// Authenticate client
    fn authenticate(&self, source: &Source<'_>, log_id: &log_utils::IdChain<u64>) -> Status;
}

impl Source<'_> {
    pub fn into_owned(self) -> Source<'static> {
        match self {
            Source::Sni(x) => Source::Sni(Cow::Owned(x.into_owned())),
            Source::ProxyBasic(x) => Source::ProxyBasic(Cow::Owned(x.into_owned())),
        }
    }
}
