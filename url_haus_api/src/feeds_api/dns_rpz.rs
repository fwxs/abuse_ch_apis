//! # URL Haus DNS Response Policy Zone (RPZ) Feed
//!
//! This module provides functions to fetch and parse DNS Response Policy Zone (RPZ) files
//! from URL Haus. RPZ is a DNS-based filtering mechanism that allows DNS servers to
//! block or redirect queries for malicious domains without requiring client-side configuration.

use std::str::FromStr;

use nom::AsChar;

use crate::WebFetch;

/// URL for fetching the URL Haus DNS RPZ file.
const URL_HAUS_DNS_RPZ_URL: &str = "https://urlhaus.abuse.ch/downloads/rpz/";

/// DNS Start of Authority (SOA) record information.
///
/// An SOA record defines the zone parameters for a DNS zone, including
/// the primary name server, responsible email, serial number, and timing parameters.
#[derive(Debug, Default, PartialEq)]
pub struct SOARecord {
    /// Primary name server (mname) for the zone.
    pub mname: String,

    /// Responsible email address (rname) for the zone (with dots instead of @).
    pub rname: String,

    /// Serial number used to track zone changes.
    pub serial: u32,

    /// Refresh interval in seconds for secondary name servers.
    pub refresh: u32,

    /// Retry interval in seconds for secondary name servers to retry failed zone transfers.
    pub retry: u32,

    /// Expiration time in seconds for zone data validity.
    pub expire: u32,

    /// Time To Live (TTL) in seconds for cached responses.
    pub ttl: u32,
}

/// Parses an SOA (Start of Authority) record from text format.
///
/// Expected format: `@ SOA mname rname serial refresh retry expire ttl`
/// For example: `@ SOA rpz.urlhaus.abuse.ch. hostmaster.urlhaus.abuse.ch. 2304061510 300 1800 604800 30`
///
/// # Arguments
///
/// * `soa_text` - A line containing the SOA record
///
/// # Returns
///
/// A nom parsing result containing the remaining input and parsed [`SOARecord`]
fn parse_soa_text(soa_text: &str) -> nom::IResult<&str, SOARecord> {
    let (input, _) = nom::bytes::complete::tag("@ SOA")(soa_text)?;
    let (input, _) = nom::character::complete::space1(input)?;

    let (input, mname) =
        nom::bytes::complete::take_while(|_char: char| !_char.is_whitespace())(input)?;
    let (input, _) = nom::character::complete::space1(input)?;

    let (input, rname) =
        nom::bytes::complete::take_while(|_char: char| !_char.is_whitespace())(input)?;
    let (input, _) = nom::character::complete::space1(input)?;

    let (input, serial) = nom::combinator::map_res(
        nom::bytes::complete::take_while(|_char: char| !_char.is_whitespace()),
        |s: &str| s.parse::<u32>(),
    )(input)?;
    let (input, _) = nom::character::complete::space1(input)?;

    let (input, refresh) = nom::combinator::map_res(
        nom::bytes::complete::take_while(|_char: char| !_char.is_whitespace()),
        |s: &str| s.parse::<u32>(),
    )(input)?;
    let (input, _) = nom::character::complete::space1(input)?;

    let (input, retry) = nom::combinator::map_res(
        nom::bytes::complete::take_while(|_char: char| !_char.is_whitespace()),
        |s: &str| s.parse::<u32>(),
    )(input)?;
    let (input, _) = nom::character::complete::space1(input)?;

    let (input, expire) = nom::combinator::map_res(
        nom::bytes::complete::take_while(|_char: char| !_char.is_whitespace()),
        |s: &str| s.parse::<u32>(),
    )(input)?;
    let (input, _) = nom::character::complete::space1(input)?;

    let (input, ttl) = nom::combinator::map_res(nom::character::complete::digit1, |_str: &str| {
        _str.parse::<u32>()
    })(input)?;

    Ok((
        input,
        SOARecord {
            mname: mname.to_string(),
            rname: rname.to_string(),
            serial,
            refresh,
            retry,
            expire,
            ttl,
        },
    ))
}

/// Converts an SOA text line into a structured [`SOARecord`].
///
/// Parses SOA record format: `@ SOA mname rname serial refresh retry expire ttl`
///
/// # Returns
///
/// An [`SOARecord`] on success, or an [`crate::error::Error`] on parsing failure
impl FromStr for SOARecord {
    type Err = crate::error::Error;

    fn from_str(soa_text: &str) -> Result<Self, Self::Err> {
        match parse_soa_text(soa_text) {
            Ok((_, soa_record)) => Ok(soa_record),
            Err(err) => Err(crate::error::Error::General(err.to_string())),
        }
    }
}

/// A DNS Response Policy Zone (RPZ) entry.
///
/// Represents a single DNS policy entry that specifies how queries for a domain
/// should be handled (blocked, redirected, etc.) when using BIND's RPZ feature.
#[derive(Debug, Default, PartialEq)]
pub struct RPZEntry {
    /// The domain name being controlled by this RPZ entry.
    pub domain: String,

    /// The policy action to take (e.g., "CNAME .", "NXDOMAIN", "NODATA").
    pub policy_action: String,

    /// Comment describing the reason for the RPZ entry.
    pub comment: String,
}

/// Parses a single RPZ entry line.
///
/// Expected format: `domain policy_action ; comment`
/// For example: `malware.com CNAME . ; Known malware host`
///
/// # Arguments
///
/// * `rpz_str` - A single RPZ entry line
///
/// # Returns
///
/// A nom parsing result containing the remaining input and parsed [`RPZEntry`]
fn parse_rpz_entry(rpz_str: &str) -> nom::IResult<&str, RPZEntry> {
    let (rpz_str, domain) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.is_whitespace()),
        String::from,
    )(rpz_str)?;
    let (rpz_str, _) = nom::character::complete::space0(rpz_str)?;

    let (rpz_str, policy_action) = nom::combinator::map(
        nom::bytes::complete::take_till(|_char: char| _char.eq(&';')),
        |policy_action_str: &str| policy_action_str.trim_end().to_string(),
    )(rpz_str)?;
    let (rpz_str, _) = nom::sequence::tuple((
        nom::character::complete::space0,
        nom::character::complete::char(';'),
        nom::character::complete::space0,
    ))(rpz_str)?;

    let (rpz_str, comment) = nom::combinator::map(
        nom::bytes::complete::take_while(|_char: char| _char.is_ascii()),
        String::from,
    )(rpz_str)?;

    Ok((
        rpz_str,
        RPZEntry {
            domain,
            policy_action,
            comment,
        },
    ))
}

/// Converts an RPZ entry text line into a structured [`RPZEntry`].
///
/// Parses RPZ entry format: `domain policy_action ; comment`
///
/// # Returns
///
/// An [`RPZEntry`] on success, or an [`crate::error::Error`] on parsing failure
impl FromStr for RPZEntry {
    type Err = crate::error::Error;

    fn from_str(rpz_entry: &str) -> Result<Self, Self::Err> {
        match parse_rpz_entry(rpz_entry) {
            Ok((_, rpz_entry)) => Ok(rpz_entry),
            Err(err) => Err(crate::error::Error::General(err.to_string())),
        }
    }
}

/// A complete DNS Response Policy Zone (RPZ) file.
///
/// Contains all the zone parameters and DNS policy entries needed to configure
/// a DNS server with RPZ-based blocking for malicious domains.
#[derive(Debug, Default)]
pub struct RPZFormat {
    /// Time To Live (TTL) value for all records in the zone.
    pub ttl: u32,

    /// Start of Authority (SOA) record defining zone parameters.
    pub soa_record: SOARecord,

    /// Nameserver (NS) record for the zone.
    pub ns: String,

    /// List of DNS policy entries controlling domain behavior.
    pub dns_entries: Vec<RPZEntry>,
}

/// Parses a complete RPZ file format.
///
/// Expects RPZ file structure with:
/// - $TTL directive
/// - SOA record
/// - NS record
/// - Comment lines (starting with ;)
/// - Domain policy entries
///
/// # Arguments
///
/// * `rpz_file` - The complete RPZ file content as a string
///
/// # Returns
///
/// A nom parsing result containing the remaining input and parsed [`RPZFormat`]
fn parse_rpz_file(rpz_file: &str) -> nom::IResult<&str, RPZFormat> {
    let (rpz_file, _) = nom::bytes::complete::tag("$TTL ")(rpz_file)?;
    let (rpz_file, ttl) = nom::combinator::map_res(
        nom::bytes::complete::take_while(|_char: char| _char.is_dec_digit()),
        |ttl: &str| ttl.parse::<u32>(),
    )(rpz_file)?;
    let (rpz_file, _) = nom::character::complete::multispace0(rpz_file)?;

    let (rpz_file, soa_record) = parse_soa_text(rpz_file)?;
    let (rpz_file, _) = nom::character::complete::multispace0(rpz_file)?;

    let (rpz_file, _) = nom::bytes::complete::tag("NS ")(rpz_file)?;
    let (rpz_file, ns) = nom::combinator::map(
        nom::bytes::complete::take_while(|_char: char| !_char.is_ascii_whitespace()),
        String::from,
    )(rpz_file)?;
    let (rpz_file, _) = nom::character::complete::multispace0(rpz_file)?;

    let (rpz_file, _) = nom::combinator::map(
        nom::multi::many1(nom::sequence::tuple((
            nom::character::complete::char(';'),
            nom::character::complete::space0,
            nom::character::complete::not_line_ending,
            nom::character::complete::newline,
        ))),
        |_| (),
    )(rpz_file)?;

    let (rpz_file, dns_entries) = nom::multi::many1(nom::combinator::map_res(
        nom::sequence::terminated(
            nom::character::complete::not_line_ending,
            nom::character::complete::newline,
        ),
        RPZEntry::from_str,
    ))(rpz_file)?;

    Ok((
        rpz_file,
        RPZFormat {
            dns_entries,
            ns,
            soa_record,
            ttl,
        },
    ))
}

/// Converts an RPZ file content into a structured [`RPZFormat`].
///
/// Parses complete RPZ file format including TTL, SOA record, NS record,
/// and all domain policy entries.
///
/// # Returns
///
/// An [`RPZFormat`] on success, or an [`crate::error::Error`] on parsing failure
impl FromStr for RPZFormat {
    type Err = crate::error::Error;

    fn from_str(rpz_file: &str) -> Result<Self, Self::Err> {
        return match parse_rpz_file(rpz_file) {
            Ok((_, rpz_file)) => Ok(rpz_file),
            Err(err) => Err(crate::error::Error::General(err.to_string())),
        };
    }
}

/// Fetches and parses the URL Haus DNS RPZ file.
///
/// Retrieves a DNS Response Policy Zone (RPZ) file from URL Haus that can be
/// imported into BIND or other RPZ-compatible DNS servers to block queries
/// for malicious domains.
///
/// # Arguments
///
/// * `web_client` - An implementation of [`WebFetch`] for making HTTP requests
///
/// # Returns
///
/// An [`RPZFormat`] on success, or an [`crate::error::Error`] on failure.
///
/// # Errors
///
/// This function returns an error if:
/// - The web request fails (network issues, connection timeout)
/// - The HTTP response indicates an error status
/// - The RPZ file content cannot be parsed
///
/// # Example
///
/// ```ignore
/// use url_haus_api::{HttpReqwest, feeds_api::dns_rpz::fetch_dns_rpz};
///
/// let client = HttpReqwest::default();
/// let rpz = fetch_dns_rpz(&client)?;
/// println!("TTL: {}", rpz.ttl);
/// println!("Entries: {}", rpz.dns_entries.len());
/// ```
pub fn fetch_dns_rpz(web_client: &impl WebFetch) -> Result<RPZFormat, crate::error::Error> {
    RPZFormat::from_str(web_client.fetch(URL_HAUS_DNS_RPZ_URL)?.as_str())
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{error, fakers::FakeHttpReqwest};

    const RAW_SOA_RECORD: &'static str =
        "@ SOA rpz.urlhaus.abuse.ch. hostmaster.urlhaus.abuse.ch. 2304061510 300 1800 604800 30";
    const RPZ_ENTRY: &'static str = "1008691.com CNAME . ; Malware download (2020-10-21), see https://urlhaus.abuse.ch/host/1008691.com/";

    #[test]
    fn test_parse_dns_soa_record() -> Result<(), error::Error> {
        let parsed_soa_record = SOARecord::from_str(RAW_SOA_RECORD)?;

        assert_eq!(
            parsed_soa_record,
            SOARecord {
                mname: String::from("rpz.urlhaus.abuse.ch."),
                rname: String::from("hostmaster.urlhaus.abuse.ch."),
                serial: 2304061510,
                refresh: 300,
                retry: 1800,
                expire: 604800,
                ttl: 30
            },
            "soa records do not match"
        );
        return Ok(());
    }

    #[test]
    fn test_error_parsing_invalid_soa_record() {
        let parsing_error = SOARecord::from_str("bogus").unwrap_err();

        assert!(matches!(parsing_error, error::Error::General(_)));
    }

    #[test]
    fn test_parse_rpz_dns_entry() -> Result<(), error::Error> {
        let rpz_entry = RPZEntry::from_str(RPZ_ENTRY)?;

        assert_eq!(
            rpz_entry,
            RPZEntry {
                domain: String::from("1008691.com"),
                policy_action: String::from("CNAME ."),
                comment: String::from(
                    "Malware download (2020-10-21), see https://urlhaus.abuse.ch/host/1008691.com/"
                )
            }
        );

        return Ok(());
    }

    #[test]
    fn test_parse_dns_rpz_file() -> Result<(), error::Error> {
        let rpz_file = RPZFormat::from_str(include_str!("test_files/dns_rpz.rpz"))?;

        assert_eq!(rpz_file.ns, "localhost.");
        assert_eq!(rpz_file.ttl, 30);
        assert_eq!(rpz_file.dns_entries.len(), 3);
        assert_eq!(
            rpz_file.soa_record,
            SOARecord {
                mname: String::from("rpz.urlhaus.abuse.ch."),
                rname: String::from("hostmaster.urlhaus.abuse.ch."),
                serial: 2304061510,
                refresh: 300,
                retry: 1800,
                expire: 604800,
                ttl: 30
            }
        );

        return Ok(());
    }

    #[test]
    fn test_fetch_rpz_file_from_url_haus() -> Result<(), error::Error> {
        let fake_reqwest = FakeHttpReqwest::default()
            .set_success_response(include_str!("test_files/dns_rpz.rpz").to_string());
        let rpz_file: RPZFormat = fetch_dns_rpz(&fake_reqwest)?;

        assert_eq!(rpz_file.ns, "localhost.");
        assert_eq!(rpz_file.ttl, 30);
        assert_eq!(rpz_file.dns_entries.len(), 3);
        assert_eq!(
            rpz_file.soa_record,
            SOARecord {
                mname: String::from("rpz.urlhaus.abuse.ch."),
                rname: String::from("hostmaster.urlhaus.abuse.ch."),
                serial: 2304061510,
                refresh: 300,
                retry: 1800,
                expire: 604800,
                ttl: 30
            }
        );

        return Ok(());
    }
}
