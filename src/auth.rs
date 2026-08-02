//! Password authentication and signed session cookies for the web UI.
//!
//! Sessions are stateless: the cookie contains an expiry timestamp signed with
//! an HMAC-SHA256 key. The key is generated once and persisted in the SQLite
//! database, so existing login sessions survive process restarts.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use actix_web::{
    Error, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use base64::Engine;
use bcrypt::{DEFAULT_COST, hash, verify};
use futures::future::{LocalBoxFuture, Ready, ready};
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::{Mutex, RwLock};
use rand::RngExt;
use serde_json::json;
use sha2::Sha256;

pub const SESSION_COOKIE_NAME: &str = "rustblocker_session";

/// Number of seconds a login session remains valid.
pub const SESSION_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

const LOGIN_MAX_CONCURRENT: usize = 2;
const LOGIN_MAX_FAILURES: u8 = 5;
const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_TRACKED_CLIENTS: usize = 4096;

#[derive(Debug)]
struct FailedLogins {
    count: u8,
    window_started: Instant,
}

/// Bounds expensive password checks and failed attempts from each client IP.
pub struct LoginThrottle {
    failures: Mutex<HashMap<IpAddr, FailedLogins>>,
    bcrypt_slots: Arc<tokio::sync::Semaphore>,
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
            bcrypt_slots: Arc::new(tokio::sync::Semaphore::new(LOGIN_MAX_CONCURRENT)),
        }
    }

    pub fn begin(&self, client_ip: IpAddr) -> Result<tokio::sync::OwnedSemaphorePermit, u64> {
        let now = Instant::now();
        if let Some(retry_after) = self.retry_after_at(client_ip, now) {
            return Err(retry_after);
        }
        self.bcrypt_slots.clone().try_acquire_owned().map_err(|_| 1)
    }

    pub fn record_failure(&self, client_ip: IpAddr) {
        self.record_failure_at(client_ip, Instant::now());
    }

    pub fn record_success(&self, client_ip: IpAddr) {
        self.failures.lock().remove(&client_ip);
    }

    fn retry_after_at(&self, client_ip: IpAddr, now: Instant) -> Option<u64> {
        let mut failures = self.failures.lock();
        if failures.len() >= LOGIN_MAX_TRACKED_CLIENTS {
            failures.retain(|_, attempt| {
                now.saturating_duration_since(attempt.window_started) < LOGIN_FAILURE_WINDOW
            });
        }
        if let Some(attempt) = failures.get(&client_ip) {
            let elapsed = now.saturating_duration_since(attempt.window_started);
            if elapsed >= LOGIN_FAILURE_WINDOW {
                failures.remove(&client_ip);
            } else if attempt.count >= LOGIN_MAX_FAILURES {
                return Some(
                    LOGIN_FAILURE_WINDOW
                        .saturating_sub(elapsed)
                        .as_secs()
                        .max(1),
                );
            }
        }
        if !failures.contains_key(&client_ip) && failures.len() >= LOGIN_MAX_TRACKED_CLIENTS {
            return Some(LOGIN_FAILURE_WINDOW.as_secs());
        }
        None
    }

    fn record_failure_at(&self, client_ip: IpAddr, now: Instant) {
        let mut failures = self.failures.lock();
        let attempt = failures.entry(client_ip).or_insert(FailedLogins {
            count: 0,
            window_started: now,
        });
        if now.saturating_duration_since(attempt.window_started) >= LOGIN_FAILURE_WINDOW {
            attempt.count = 0;
            attempt.window_started = now;
        }
        attempt.count = attempt.count.saturating_add(1);
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

/// Authentication state shared across worker threads.
pub struct AuthState {
    session_secret: Arc<RwLock<Vec<u8>>>,
}

impl AuthState {
    /// Generate a new random 256-bit session signing key.
    pub fn generate_secret() -> Vec<u8> {
        let mut session_secret = vec![0u8; 32];
        rand::rng().fill(&mut session_secret);
        session_secret
    }

    /// Create auth state from an existing secret (loaded from persistent storage).
    pub fn from_secret(session_secret: Vec<u8>) -> Self {
        Self {
            session_secret: Arc::new(RwLock::new(session_secret)),
        }
    }

    /// Generate a new session signing key and update the in-memory secret.
    ///
    /// The caller is responsible for persisting the returned secret to
    /// persistent storage (e.g. the `session_secret` database setting).
    pub fn rotate_secret(&self) -> Vec<u8> {
        let new_secret = Self::generate_secret();
        *self.session_secret.write() = new_secret.clone();
        new_secret
    }

    /// Create a new auth state with a randomly generated session signing key.
    pub fn new() -> Self {
        Self::from_secret(Self::generate_secret())
    }

    /// Generate a strong, random plaintext admin password.
    ///
    /// Uses an unambiguous character set (no `0`/`O`, `1`/`l`/`I`, etc.)
    /// so the printed password survives copy/paste and manual typing.
    pub fn generate_password() -> String {
        const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
        let mut rng = rand::rng();
        (0..24)
            .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
            .collect()
    }

    /// Hash a plaintext password with bcrypt for storage in the database.
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        hash(password, DEFAULT_COST)
    }

    /// Verify a plaintext password against a bcrypt hash.
    pub fn verify_password(password: &str, hash: &str) -> bool {
        verify(password, hash).unwrap_or(false)
    }

    /// Issue a new signed session cookie value valid for `max_age_secs`.
    pub fn create_session(&self, max_age_secs: u64) -> String {
        let expires = unix_now() + max_age_secs;
        let payload = format!("admin|{expires}");
        let signature = self.sign(&payload);
        format!("{expires}|{}", base64_encode(&signature))
    }

    /// Validate a session cookie value: parse expiry and verify signature.
    pub fn validate_session(&self, cookie_value: &str) -> bool {
        let (expires_str, signature_b64) = match cookie_value.split_once('|') {
            Some(parts) => parts,
            None => return false,
        };
        let expires: u64 = match expires_str.parse() {
            Ok(ts) => ts,
            Err(_) => return false,
        };
        if unix_now() > expires {
            return false;
        }
        let signature = match base64_decode(signature_b64) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let payload = format!("admin|{expires}");
        self.verify_signature(&payload, &signature)
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

/// Paths that do not require an authenticated session.
pub fn is_public_path(path: &str) -> bool {
    path == "/"
        || path.starts_with("/tailwind.min.css")
        || path == "/app.js"
        || path == "/icon.png"
        || path == "/favicon.png"
        || path == "/favicon.ico"
        || path == "/api/health"
        || path == "/api/version"
        || path == "/api/dns/concurrency"
        || path == "/api/auth/login"
        || path == "/api/auth/logout"
        || path == "/api/auth/check"
}

/// Actix-web middleware that protects API routes with a signed session cookie.
#[derive(Clone)]
pub struct AuthMiddleware {
    auth: Arc<AuthState>,
}

impl AuthMiddleware {
    pub fn new(auth: Arc<AuthState>) -> Self {
        Self { auth }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service,
            auth: self.auth.clone(),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
    auth: Arc<AuthState>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if is_public_path(req.path()) {
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await.map(|res| res.map_into_left_body()) });
        }

        let authed = req
            .cookie(SESSION_COOKIE_NAME)
            .map(|c| self.auth.validate_session(c.value()))
            .unwrap_or(false);

        if authed {
            let fut = self.service.call(req);
            Box::pin(async move { fut.await.map(|res| res.map_into_left_body()) })
        } else {
            Box::pin(async move {
                Ok(req
                    .into_response(
                        HttpResponse::Unauthorized().json(json!({"error": "unauthorized"})),
                    )
                    .map_into_right_body())
            })
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

type HmacSha256 = Hmac<Sha256>;

fn sign(secret: &[u8], payload: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can accept a key of any length");
    mac.update(payload.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn verify_signature(secret: &[u8], payload: &str, signature: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can accept a key of any length");
    mac.update(payload.as_bytes());
    mac.verify_slice(signature).is_ok()
}

impl AuthState {
    fn sign(&self, payload: &str) -> Vec<u8> {
        sign(&self.session_secret.read(), payload)
    }

    fn verify_signature(&self, payload: &str, signature: &[u8]) -> bool {
        verify_signature(&self.session_secret.read(), payload, signature)
    }
}

fn base64_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}

fn base64_decode(input: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| anyhow::anyhow!("base64 decode failed: {e}"))
}

/// Encode a session secret for storage in the database.
pub fn encode_secret(secret: &[u8]) -> String {
    base64_encode(secret)
}

/// Decode a session secret stored in the database.
pub fn decode_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    base64_decode(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip() {
        let password = AuthState::generate_password();
        assert_eq!(password.len(), 24);
        let hash = AuthState::hash_password(&password).unwrap();
        assert!(AuthState::verify_password(&password, &hash));
        assert!(!AuthState::verify_password("wrong-password", &hash));
    }
    #[test]
    fn session_validates_and_expires() {
        let auth = AuthState::new();
        let session = auth.create_session(60);
        assert!(auth.validate_session(&session));
        assert!(!auth.validate_session("malformed"));

        let mut tampered = session.clone();
        tampered.push('x');
        assert!(!auth.validate_session(&tampered));

        let expired = auth.create_session(0);
        // Give the clock one second to move past the instant we created it.
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(!auth.validate_session(&expired));
    }

    #[test]
    fn session_secret_rotation_invalidates_existing_sessions() {
        let auth = AuthState::new();
        let session = auth.create_session(60);
        assert!(auth.validate_session(&session));

        // After rotating the signing secret, the old cookie must no longer validate.
        auth.rotate_secret();
        assert!(!auth.validate_session(&session));

        // A freshly issued session should validate against the new secret.
        let new_session = auth.create_session(60);
        assert!(auth.validate_session(&new_session));
    }

    #[test]
    fn public_paths_do_not_require_auth() {
        assert!(is_public_path("/"));
        assert!(is_public_path("/tailwind.min.css"));
        assert!(is_public_path("/tailwind.min.css?v=1"));
        assert!(is_public_path("/api/health"));
        assert!(is_public_path("/api/version"));
        assert!(is_public_path("/api/dns/concurrency"));
        assert!(is_public_path("/api/auth/login"));
        assert!(is_public_path("/api/auth/logout"));
        assert!(is_public_path("/api/auth/check"));
        assert!(!is_public_path("/api/auth/password"));
        assert!(!is_public_path("/api/settings"));
        assert!(!is_public_path("/api/stats/live"));
    }

    #[test]
    fn login_throttle_locks_and_expires_failed_attempts() {
        let throttle = LoginThrottle::new();
        let client_ip = "192.0.2.1".parse().unwrap();
        let started = Instant::now();

        for _ in 0..LOGIN_MAX_FAILURES - 1 {
            throttle.record_failure_at(client_ip, started);
            assert_eq!(throttle.retry_after_at(client_ip, started), None);
        }
        throttle.record_failure_at(client_ip, started);
        assert_eq!(
            throttle.retry_after_at(client_ip, started),
            Some(LOGIN_FAILURE_WINDOW.as_secs())
        );
        assert_eq!(
            throttle.retry_after_at(client_ip, started + LOGIN_FAILURE_WINDOW),
            None
        );
    }

    #[test]
    fn successful_login_clears_failed_attempts() {
        let throttle = LoginThrottle::new();
        let client_ip = "192.0.2.2".parse().unwrap();
        let now = Instant::now();
        for _ in 0..LOGIN_MAX_FAILURES {
            throttle.record_failure_at(client_ip, now);
        }
        throttle.record_success(client_ip);
        assert_eq!(throttle.retry_after_at(client_ip, now), None);
    }

    #[tokio::test]
    async fn login_throttle_rejects_work_above_bcrypt_limit() {
        let throttle = LoginThrottle::new();
        let first = throttle.begin("192.0.2.3".parse().unwrap()).unwrap();
        let second = throttle.begin("192.0.2.4".parse().unwrap()).unwrap();
        assert_eq!(throttle.begin("192.0.2.5".parse().unwrap()).unwrap_err(), 1);
        drop((first, second));
        assert!(throttle.begin("192.0.2.5".parse().unwrap()).is_ok());
    }
}
