mod approle;
mod aws;
mod cert;
mod common;
mod database;
mod identity;
mod kv1;
mod kv2;
mod oidc;
mod pki;
mod ssh;
mod sys;
mod token;
mod transit;
mod userpass;

// We use a single binary for integration tests because we want
// them to run in parallel
// https://users.rust-lang.org/t/how-to-execute-the-cargo-test-concurrently/92803/4
