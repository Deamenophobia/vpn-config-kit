//! Optional Xray backend. Its credentials and state never enter WireGuard storage.
pub mod config;
pub mod render;
pub mod runtime;
pub mod state;

pub use config::Config;
pub use runtime::{Native, Running, Runtime};
pub use state::Gateway;
