//! # URL Haus IDS/IPS Rules Feed
//!
//! This module provides functions to fetch and parse Snort and Suricata IDS/IPS rules
//! from URL Haus. These rules can be used to detect malicious network traffic associated
//! with known malware URLs and command-and-control (C2) servers.

use std::str::FromStr;

use crate::WebFetch;

/// URL for fetching Snort IDS rules from URL Haus.
const URL_HAUS_SNORT_RULES_URL: &str = "https://urlhaus.abuse.ch/downloads/ids/";

/// URL for fetching Suricata IDS rules from URL Haus.
const URL_HAUS_SURICATA_RULES_URL: &str = "https://urlhaus.abuse.ch/downloads/suricata-ids/";

/// A parsed Snort or Suricata IDS rule.
///
/// Represents the main components of a Snort/Suricata rule, which consists of
/// an action, protocol, source/destination addresses and ports, traffic direction,
/// and rule options (content matching, metadata, etc.).
#[derive(Debug, Default)]
pub struct SnortRule {
    /// Rule action (e.g., "alert", "drop", "pass", "reject").
    pub action: String,

    /// Network protocol (e.g., "tcp", "udp", "http", "ssl").
    pub protocol: String,

    /// Source IP address or network (e.g., "$HOME_NET", "192.168.1.0/24", "any").
    pub src_addr: String,

    /// Source port or port range (e.g., "any", "80", "1024:65535").
    pub src_port: String,

    /// Traffic direction operator (e.g., "->", "<->").
    pub direction: String,

    /// Destination IP address or network (e.g., "$EXTERNAL_NET", "192.168.1.0/24", "any").
    pub dst_addr: String,

    /// Destination port or port range (e.g., "any", "443", "8080:9090").
    pub dst_port: String,

    /// Rule options including content patterns, metadata, classtype, sid, rev, etc.
    pub options: Vec<String>,
}

/// Parses a Snort/Suricata rule from text format using nom parser combinators.
///
/// Expected format: `action protocol src_addr src_port direction dst_addr dst_port (options)`
/// For example: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"rule"; content:"pattern"; sid:1;)`
///
/// # Arguments
///
/// * `snort_rule` - A single Snort rule line
///
/// # Returns
///
/// A nom parsing result containing the remaining input and parsed [`SnortRule`]
fn parse_snort_rule(snort_rule: &str) -> nom::IResult<&str, SnortRule> {
    let (snort_rule, action) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, protocol) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, src_addr) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, src_port) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, direction) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, dst_addr) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, dst_port) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(snort_rule)?;
    let (snort_rule, _) = nom::character::complete::space0(snort_rule)?;

    let (snort_rule, _) = nom::character::complete::char('(')(snort_rule)?;
    let (snort_rule, options) = nom::multi::separated_list0(
        nom::bytes::complete::tag(";"),
        nom::combinator::map(nom::bytes::complete::take_until(";"), |opt_str: &str| {
            opt_str.trim().to_string()
        }),
    )(snort_rule)?;

    Ok((
        snort_rule,
        SnortRule {
            action,
            direction,
            dst_addr,
            dst_port,
            options,
            protocol,
            src_addr,
            src_port,
        },
    ))
}

/// Converts a Snort rule text line into a structured [`SnortRule`].
///
/// Parses Snort/Suricata rule format: `action protocol src_addr src_port direction dst_addr dst_port (options)`
///
/// # Returns
///
/// A [`SnortRule`] on success, or an [`crate::error::Error`] on parsing failure
impl FromStr for SnortRule {
    type Err = crate::error::Error;

    fn from_str(snort_rule: &str) -> Result<Self, Self::Err> {
        return match parse_snort_rule(snort_rule) {
            Ok((_, rule)) => Ok(rule),
            Err(err) => Err(crate::error::Error::General(err.to_string())),
        };
    }
}

/// Fetches and parses Snort IDS rules from URL Haus.
///
/// Retrieves Snort rules in standard Snort format that can be used with Snort IDS
/// to detect network traffic associated with malicious URLs. Comment lines (starting with '#')
/// are skipped, and invalid rules are filtered out.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// A vector of parsed [`SnortRule`] on success, or an [`crate::error::Error`] on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The HTTP response indicates an error status
///
/// Invalid individual rules are silently skipped and not included in the result vector.
///
/// # Example
///
/// ```ignore
/// use url_haus_api::{HttpReqwest, feeds_api::ids_ips_rules::fetch_snort_rules};
///
/// let client = HttpReqwest::default();
/// let rules = fetch_snort_rules(&client)?;
/// for rule in rules {
///     println!("Action: {}, Protocol: {}", rule.action, rule.protocol);
/// }
/// ```
pub fn fetch_snort_rules(
    web_client: &impl WebFetch,
) -> Result<Vec<SnortRule>, crate::error::Error> {
    let response = web_client.fetch(URL_HAUS_SNORT_RULES_URL)?;

    Ok(response
        .lines()
        .skip_while(|line| line.starts_with('#'))
        .map(SnortRule::from_str)
        .filter_map(|res_snort_rule| res_snort_rule.ok())
        .collect())
}

/// Fetches and parses Suricata IDS rules from URL Haus.
///
/// Retrieves Suricata rules in Suricata format that can be used with the Suricata IDS/IPS engine
/// to detect network traffic associated with malicious URLs. Comment lines (starting with '#')
/// are skipped, and invalid rules are filtered out.
///
/// Suricata rules are largely compatible with Snort rules but may include additional features
/// and options specific to the Suricata engine.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// A vector of parsed [`SnortRule`] on success, or an [`crate::error::Error`] on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The HTTP response indicates an error status
///
/// Invalid individual rules are silently skipped and not included in the result vector.
///
/// # Example
///
/// ```ignore
/// use url_haus_api::{HttpReqwest, feeds_api::ids_ips_rules::fetch_suricata_rules};
///
/// let client = HttpReqwest::default();
/// let rules = fetch_suricata_rules(&client)?;
/// for rule in rules {
///     println!("Suricata rule: {}", rule.action);
/// }
/// ```
pub fn fetch_suricata_rules(
    web_client: &impl WebFetch,
) -> Result<Vec<SnortRule>, crate::error::Error> {
    let response = web_client.fetch(URL_HAUS_SURICATA_RULES_URL)?;

    Ok(response
        .lines()
        .skip_while(|line| line.starts_with('#'))
        .map(SnortRule::from_str)
        .filter_map(|res_snort_rule| res_snort_rule.ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::fakers::FakeHttpReqwest;

    use super::*;

    const SNORT_RULE: &'static str = "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"URLhaus Known malware download URL detected (2594519)\"; flow:established,from_client; content:\"GET\"; http_method; content:\"/f7a5529f1c222f09/vcruntime140.dll\"; http_uri; depth:34; isdataat:!1,relative; nocase; content:\"5.75.232.223\"; http_host; depth:12; isdataat:!1,relative; metadata:created_at 2023_04_02; reference:url, urlhaus.abuse.ch/url/2594519/; classtype:trojan-activity;sid:83457619; rev:1;)";

    #[test]
    fn test_parse_snort_rule() -> Result<(), crate::error::Error> {
        let parsed_rule: SnortRule = SnortRule::from_str(SNORT_RULE)?;

        assert_eq!(parsed_rule.action, "alert");
        assert_eq!(parsed_rule.protocol, "http");
        assert_eq!(parsed_rule.src_addr, "$HOME_NET");
        assert_eq!(parsed_rule.src_port, "any");
        assert_eq!(parsed_rule.direction, "->");
        assert_eq!(parsed_rule.dst_addr, "$EXTERNAL_NET");
        assert_eq!(parsed_rule.dst_port, "any");
        assert!(!parsed_rule.options.is_empty());
        assert_eq!(parsed_rule.options.len(), 18);

        return Ok(());
    }

    #[test]
    fn test_fetch_url_haus_snort_rules() -> Result<(), crate::error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/snort_rules").to_string());
        let snort_rules: Vec<SnortRule> = fetch_snort_rules(&fake_reqwest)?;

        assert_eq!(snort_rules.len(), 2);

        for rule in snort_rules {
            assert_eq!(rule.action, "alert");
            assert_eq!(rule.protocol, "http");
            assert_eq!(rule.src_addr, "$HOME_NET");
            assert_eq!(rule.src_port, "any");
            assert_eq!(rule.direction, "->");
            assert_eq!(rule.dst_addr, "$EXTERNAL_NET");
            assert_eq!(rule.dst_port, "any");
            assert!(!rule.options.is_empty());
        }

        return Ok(());
    }

    #[test]
    fn test_fetch_url_haus_suricata_rules() -> Result<(), crate::error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/suricata_rules").to_string());
        let snort_rules: Vec<SnortRule> = fetch_suricata_rules(&fake_reqwest)?;

        assert_eq!(snort_rules.len(), 3);

        for rule in snort_rules {
            assert_eq!(rule.action, "alert");
            assert_eq!(rule.protocol, "http");
            assert_eq!(rule.src_addr, "$HOME_NET");
            assert_eq!(rule.src_port, "any");
            assert_eq!(rule.direction, "->");
            assert_eq!(rule.dst_addr, "$EXTERNAL_NET");
            assert_eq!(rule.dst_port, "any");
            assert!(!rule.options.is_empty());
        }

        return Ok(());
    }
}
