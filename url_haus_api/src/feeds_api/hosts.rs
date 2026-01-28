//! # URL Haus Hosts File Feed
//!
//! This module provides functions to fetch and parse hosts files from URL Haus.
//! Hosts files map IP addresses to hostnames and can be used to block malicious domains
//! at the system level by redirecting them to localhost or a sinkhole address.

use std::str::FromStr;

use crate::WebFetch;

/// URL for fetching the URL Haus hosts file.
const URL_HAUS_HOSTS_FILE_URL: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";

/// A hostname entry mapping an IP address to one or more hostnames.
///
/// Represents a single line from a hosts file, including the IP address,
/// primary hostname, and optional aliases. This structure can be used to
/// block malicious domains at the system level.
#[derive(Debug, Default, PartialEq)]
pub struct Hostname {
    /// The IP address to map to (IPv4 or IPv6).
    pub ip_addr: String,

    /// The primary hostname associated with this IP address.
    pub host_name: String,

    /// Optional list of aliases (additional hostnames) for this IP address.
    pub aliases: Option<Vec<String>>,
}

/// Parses a single hostname entry line from a hosts file.
///
/// Expected format: `IP_ADDRESS HOSTNAME [ALIAS1 ALIAS2 ...]`
/// For example: `127.0.0.1 localhost`
/// Or: `::1 localhost ip6-localhost ip6-loopback`
///
/// # Arguments
///
/// * `host_str` - A single line from a hosts file
///
/// # Returns
///
/// A nom parsing result containing the remaining input and parsed [`Hostname`]
fn parse_hostname_line(host_str: &str) -> nom::IResult<&str, Hostname> {
    let (host_str, ip_addr) = nom::combinator::map(
        nom::bytes::complete::take_while(|_char: char| !_char.is_ascii_whitespace()),
        String::from,
    )(host_str)?;
    let (host_str, _) = nom::character::complete::multispace1(host_str)?;

    let (host_str, host_name) = nom::combinator::map(
        nom::bytes::complete::take_while(|_char: char| !_char.is_ascii_whitespace()),
        String::from,
    )(host_str)?;
    let (host_str, _) = nom::character::complete::multispace0(host_str)?;

    let (host_str, aliases) = nom::combinator::opt(nom::multi::separated_list1(
        nom::bytes::complete::tag(" "),
        nom::combinator::map(
            nom::bytes::complete::take_while1(|_char: char| !_char.is_ascii_whitespace()),
            String::from,
        ),
    ))(host_str)?;

    Ok((
        host_str,
        Hostname {
            ip_addr,
            host_name,
            aliases,
        },
    ))
}

/// Converts a hosts file line into a structured [`Hostname`] entry.
///
/// Parses a single line from a hosts file into its components.
/// Supports the standard hosts file format with optional aliases.
///
/// # Returns
///
/// A [`Hostname`] on success, or an [`crate::error::Error`] on parsing failure
impl FromStr for Hostname {
    type Err = crate::error::Error;

    fn from_str(host_str: &str) -> Result<Self, Self::Err> {
        return match parse_hostname_line(host_str) {
            Ok((_, parsed_hostname)) => Ok(parsed_hostname),
            Err(parse_err) => Err(crate::error::Error::General(parse_err.to_string())),
        };
    }
}

/// Parses a complete hosts file content into a vector of hostname entries.
///
/// Skips comment lines (starting with '#') and empty lines,
/// parsing only valid hostname entries.
///
/// # Arguments
///
/// * `hosts_file_content` - The full content of a hosts file as a string
///
/// # Returns
///
/// A vector of successfully parsed [`Hostname`] entries
fn parse_hosts_file(hosts_file_content: &str) -> Result<Vec<Hostname>, crate::error::Error> {
    Ok(hosts_file_content
        .lines()
        .filter(|line: &&str| !line.starts_with('#'))
        .filter_map(|line: &str| Hostname::from_str(line).ok())
        .collect())
}

/// Fetches and parses the URL Haus hosts file.
///
/// Retrieves a hosts file from URL Haus containing mappings of malicious
/// domain names to a blocking IP address (typically 127.0.0.1 or 0.0.0.0).
/// This file can be directly used as a system hosts file for DNS-level blocking.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// A vector of [`Hostname`] entries on success, or an [`crate::error::Error`] on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The HTTP response indicates an error status
/// - The hosts file content cannot be parsed
///
/// # Example
///
/// ```ignore
/// use url_haus_api::{HttpReqwest, feeds_api::hosts::fetch_hosts_file};
///
/// let client = HttpReqwest::default();
/// let hostnames = fetch_hosts_file(&client)?;
/// for hostname in hostnames {
///     println!("{} {}", hostname.ip_addr, hostname.host_name);
/// }
/// ```
pub fn fetch_hosts_file(web_client: &impl WebFetch) -> Result<Vec<Hostname>, crate::error::Error> {
    parse_hosts_file(web_client.fetch(URL_HAUS_HOSTS_FILE_URL)?.as_str())
}

#[cfg(test)]
mod tests {
    use crate::fakers::FakeHttpReqwest;

    use super::*;

    const HOSTS_FILE_LINE: &'static str = "127.0.0.1       localhost";
    const HOSTS_FILE_LINE_WITH_ALIASES: &'static str =
        "::1             localhost ip6-localhost ip6-loopback";

    #[test]
    fn test_parse_host_line() -> Result<(), crate::error::Error> {
        let parsed_host: Hostname = Hostname::from_str(HOSTS_FILE_LINE)?;

        assert_eq!(
            parsed_host,
            Hostname {
                ip_addr: String::from("127.0.0.1"),
                host_name: String::from("localhost"),
                aliases: None
            }
        );

        Ok(())
    }

    #[test]
    fn test_parse_host_line_with_aliases() -> Result<(), crate::error::Error> {
        let parsed_host: Hostname = Hostname::from_str(HOSTS_FILE_LINE_WITH_ALIASES)?;

        assert_eq!(
            parsed_host,
            Hostname {
                ip_addr: String::from("::1"),
                host_name: String::from("localhost"),
                aliases: Some(vec![
                    String::from("ip6-localhost"),
                    String::from("ip6-loopback")
                ])
            }
        );

        Ok(())
    }

    #[test]
    fn test_parse_hosts_file() -> Result<(), crate::error::Error> {
        let file_content = include_str!("test_files/hosts_file");
        let hostnames = parse_hosts_file(file_content)?;

        assert_eq!(hostnames.len(), 9);

        Ok(())
    }

    #[test]
    fn test_fetch_url_haus_hosts_file() -> Result<(), crate::error::Error> {
        let fake_client = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/url_haus_hosts_file").to_string());
        let hostnames = fetch_hosts_file(&fake_client)?;

        assert_eq!(hostnames.len(), 4);

        Ok(())
    }
}
