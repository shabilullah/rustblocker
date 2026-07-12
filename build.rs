fn main() {
    println!("cargo:rerun-if-env-changed=RUSTBLOCKER_BUILD_ID");
    println!(
        "cargo:rustc-env=TARGET_TRIPLE={}",
        std::env::var("TARGET").unwrap()
    );
    println!(
        "cargo:rustc-env=RUSTBLOCKER_BUILD_ID={}",
        std::env::var("RUSTBLOCKER_BUILD_ID").unwrap_or_else(|_| "official".to_string())
    );
}
