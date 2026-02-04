'''use crate::authentication::{Authenticator, SessionGuard, Status};
use crate::{authentication, log_utils};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use log::info;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// A client descriptor from the configuration.
#[derive(Deserialize, Clone)]
pub struct Client {
    /// The client username.
    pub username: String,
    /// The client password.
    pub password: String,
}

/// Represents an active session in our system.
struct ActiveSession {
    /// A unique ID for logging purposes.
    session_id: u64,
    /// The "kill switch" for this specific session.
    kill_signal: Arc<Notify>,
}

/// A session guard that ensures cleanup when a connection is dropped.
struct RegistrySessionGuard {
    username: String,
    session_id: u64,
    state: Arc<Mutex<HashMap<String, VecDeque<ActiveSession>>>>,
}

impl Drop for RegistrySessionGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(sessions) = state.get_mut(&self.username) {
                if let Some(pos) = sessions.iter().position(|s| s.session_id == self.session_id) {
                    sessions.remove(pos);
                    info!(
                        "Authentication: User '{}' disconnected. Session ID {}. Active sessions: {}/{}",
                        self.username,
                        self.session_id,
                        sessions.len(),
                        // Note: max_devices is not available here, but the count is the most important part.
                        "?" 
                    );
                }
            }
        }
    }
}

impl SessionGuard for RegistrySessionGuard {}

/// An [`Authenticator`] that enforces a strict limit on concurrent devices
/// by kicking the oldest session when a new one connects ("Rolling Sessions").
pub struct RegistryBasedAuthenticator {
    /// A map of base64-encoded "username:password" to plain username.
    clients: HashMap<String, String>,
    /// The core state: maps a username to their queue of active sessions.
    active_sessions: Arc<Mutex<HashMap<String, VecDeque<ActiveSession>>>>,
    /// The maximum number of concurrent devices allowed per user.
    max_devices: usize,
}

impl RegistryBasedAuthenticator {
    pub fn new(clients: &[Client], max_devices: usize) -> Self {
        let client_map = clients
            .iter()
            .map(|c| {
                let encoded = BASE64_ENGINE.encode(format!("{}:{}", c.username, c.password));
                (encoded, c.username.clone())
            })
            .collect();

        Self {
            clients: client_map,
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
            max_devices,
        }
    }
}

impl Authenticator for RegistryBasedAuthenticator {
    fn authenticate(
        &self,
        source: &authentication::Source<'_>,
        log_id: &log_utils::IdChain<u64>,
    ) -> authentication::Status {
        let (encoded_credentials, username) = match source {
            authentication::Source::ProxyBasic(credentials) => {
                if let Some(username) = self.clients.get(credentials.as_ref()) {
                    (credentials.as_ref(), username)
                } else {
                    return Status::Reject; // Invalid username/password
                }
            }
            _ => return Status::Reject, // We only support ProxyBasic auth
        };

        let mut state = self.active_sessions.lock().unwrap();
        let sessions = state.entry(username.clone()).or_insert_with(VecDeque::new);

        // Rolling session logic
        if sessions.len() >= self.max_devices {
            if let Some(victim) = sessions.pop_front() {
                victim.kill_signal.notify_one();
                info!(
                    "Authentication: User '{}' limit reached ({}). Kicking old session ID {}. Request ID: {}",
                    username, self.max_devices, victim.session_id, log_id
                );
            }
        }

        // Create the new session
        let new_id = log_utils::next_internal_id();
        let kill_signal = Arc::new(Notify::new());

        sessions.push_back(ActiveSession {
            session_id: new_id,
            kill_signal: kill_signal.clone(),
        });
        
        info!(
            "Authentication: User '{}' connected. Session ID: {}. Active sessions: {}/{}. Request ID: {}",
            username,
            new_id,
            sessions.len(),
            self.max_devices,
            log_id
        );

        let guard = Arc::new(RegistrySessionGuard {
            username: username.clone(),
            session_id: new_id,
            state: self.active_sessions.clone(),
        });

        Status::Pass(guard, kill_signal)
    }
}

''