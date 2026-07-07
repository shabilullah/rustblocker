//! Password authentication and signed session cookies for the web UI.
//!
//! Sessions are stateless: the cookie contains an expiry timestamp signed with
//! an HMAC-SHA256 key generated at server startup. This keeps the app
//! zero-config (no Redis/files/server state), at the cost of requiring login
//! again after the process restarts -- acceptable for a single-user admin UI.

use std::sync::Arc;

use actix_web::{
    Error, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use base64::Engine;
use bcrypt::{DEFAULT_COST, hash, verify};
use futures::future::{LocalBoxFuture, Ready, ready};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::distributions::{Alphanumeric, DistString};
use serde_json::json;
use sha2::Sha256;

pub const SESSION_COOKIE_NAME: &str = "rustblocker_session";

/// Number of seconds a login session remains valid.
pub const SESSION_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Authentication state shared across worker threads.
pub struct AuthState {
    session_secret: Vec<u8>,
}

impl AuthState {
    /// Create a new auth state with a randomly generated session signing key.
    pub fn new() -> Self {
        let mut session_secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_secret);
        Self { session_secret }
    }

    /// Generate a strong, random plaintext admin password.
    pub fn generate_password() -> String {
        Alphanumeric.sample_string(&mut rand::thread_rng(), 24)
    }

    /// Hash a plaintext password with bcrypt for storage in the database.
    pub fn hash_password(password: &str) -> String {
        hash(password, DEFAULT_COST).expect("failed to hash password")
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
        || path == "/api/health"
        || path == "/api/version"
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
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC can accept a key of any length");
    mac.update(payload.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn verify_signature(secret: &[u8], payload: &str, signature: &[u8]) -> bool {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC can accept a key of any length");
    mac.update(payload.as_bytes());
    mac.verify_slice(signature).is_ok()
}

impl AuthState {
    fn sign(&self, payload: &str) -> Vec<u8> {
        sign(&self.session_secret, payload)
    }

    fn verify_signature(&self, payload: &str, signature: &[u8]) -> bool {
        verify_signature(&self.session_secret, payload, signature)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip() {
        let password = AuthState::generate_password();
        assert_eq!(password.len(), 24);
        let hash = AuthState::hash_password(&password);
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
    fn public_paths_are_whitelisted() {
        assert!(is_public_path("/"));
        assert!(is_public_path("/tailwind.min.css"));
        assert!(is_public_path("/tailwind.min.css?v=1"));
        assert!(is_public_path("/api/health"));
        assert!(is_public_path("/api/version"));
        assert!(is_public_path("/api/auth/login"));
        assert!(is_public_path("/api/auth/logout"));
        assert!(is_public_path("/api/auth/check"));
        assert!(!is_public_path("/api/auth/password"));
        assert!(!is_public_path("/api/settings"));
        assert!(!is_public_path("/api/stats/live"));
    }
}
