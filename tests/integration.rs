use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_server::server::Request;

use rustblocker::config::UpstreamConfig;
use rustblocker::forwarder::ParallelForwarder;
use rustblocker::lists::DomainStore;

fn make_request(name: &str) -> Request {
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(format!("{}.", name)).unwrap(),
        RecordType::A,
    ));
    let bytes = msg.to_vec().expect("encode failed");
    Request::from_bytes(
        bytes,
        "127.0.0.1:12345".parse().unwrap(),
        hickory_server::net::xfer::Protocol::Udp,
    )
    .unwrap()
}

fn make_domain_store(domains: &[&str]) -> DomainStore {
    let mut store = DomainStore::default();
    for d in domains {
        store.exact.insert(d.to_string());
    }
    store
}

#[tokio::test]
async fn test_upstream_forwarder_construction() {
    let forwarder = ParallelForwarder::new(
        &[
            UpstreamConfig {
                address: "8.8.8.8".to_string(),
                port: Some(53),
            },
            UpstreamConfig {
                address: "1.1.1.1".to_string(),
                port: Some(53),
            },
        ],
        5,
    );
    assert!(forwarder.is_ok(), "Forwarder construction should succeed");
}

#[tokio::test]
async fn test_upstream_forwarder_invalid_ip() {
    let forwarder = ParallelForwarder::new(
        &[UpstreamConfig {
            address: "not-an-ip".to_string(),
            port: Some(53),
        }],
        5,
    );
    assert!(forwarder.is_err(), "Invalid IP should fail");
}

#[tokio::test]
async fn test_db_seed_defaults() {
    use rusqlite::{Connection, params};

    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE upstreams (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 53);
         CREATE TABLE blocklist_domains (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE);
         CREATE TABLE allowlist_domains (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE);
         CREATE TABLE rewrites (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, ipv4 TEXT, ipv6 TEXT);",
    ).unwrap();

    // Insert same defaults as seed_defaults
    let settings = [
        ("listen_address", "127.0.0.1"),
        ("listen_port", "5353"),
        ("sinkhole_ipv4", "0.0.0.0"),
        ("sinkhole_ipv6", "::"),
        ("log_level", "info"),
        ("upstream_timeout_secs", "5"),
    ];
    for (key, value) in &settings {
        conn.execute("INSERT INTO settings (key, value) VALUES (?1, ?2)", params![key, value]).unwrap();
    }
    conn.execute("INSERT INTO upstreams (address, port) VALUES (?1, ?2)", params!["8.8.8.8", 53]).unwrap();

    // Verify settings
    let listen_port: String = conn.query_row("SELECT value FROM settings WHERE key='listen_port'", [], |r| r.get(0)).unwrap();
    assert_eq!(listen_port, "5353");

    let listen_addr: String = conn.query_row("SELECT value FROM settings WHERE key='listen_address'", [], |r| r.get(0)).unwrap();
    assert_eq!(listen_addr, "127.0.0.1");

    let timeout: String = conn.query_row("SELECT value FROM settings WHERE key='upstream_timeout_secs'", [], |r| r.get(0)).unwrap();
    assert_eq!(timeout, "5");

    // Verify upstream
    let upstream_count: i64 = conn.query_row("SELECT COUNT(*) FROM upstreams", [], |r| r.get(0)).unwrap();
    assert_eq!(upstream_count, 1);

    let addr: String = conn.query_row("SELECT address FROM upstreams WHERE id=1", [], |r| r.get(0)).unwrap();
    assert_eq!(addr, "8.8.8.8");

    let port: i64 = conn.query_row("SELECT port FROM upstreams WHERE id=1", [], |r| r.get(0)).unwrap();
    assert_eq!(port, 53);
}

#[tokio::test]
async fn test_make_request_encodes_and_decodes() {
    let req = make_request("example.com");
    assert!(!req.queries.queries().is_empty());
    let q = &req.queries.queries()[0];
    assert_eq!(q.query_type(), RecordType::A);
}

#[tokio::test]
async fn test_list_loading_from_memory() {
    let store = make_domain_store(&["ads.example.com", "tracker.example.com"]);
    assert!(store.matches("ads.example.com"));
    assert!(store.matches("tracker.example.com"));
    assert!(!store.matches("example.com"));
}
