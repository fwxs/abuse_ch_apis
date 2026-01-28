//! # Feed API Submodules
//!
//! This module provides access to various threat intelligence feeds from URL Haus.
//! Each submodule handles a specific feed format or data type.
//!
//! ## Available Feeds
//!
//! - [`urls_db`]: CSV database dumps of malicious URLs (recent and active)
//! - [`dns_rpz`]: DNS Response Policy Zone (RPZ) format for DNS filtering
//! - [`hosts`]: Hosts file format for blocking malicious domains
//! - [`ids_ips_rules`]: Snort and Suricata IDS/IPS rules for network detection

pub mod dns_rpz;
pub mod hosts;
pub mod ids_ips_rules;
pub mod urls_db;
