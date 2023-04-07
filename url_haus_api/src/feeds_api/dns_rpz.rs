use std::str::FromStr;

use nom::AsChar;

use crate::WebFetch;

const URL_HAUS_DNS_RPZ_URL: &str = "https://urlhaus.abuse.ch/downloads/rpz/";

#[derive(Debug, Default, PartialEq)]
pub struct SOARecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub ttl: u32,
}

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

impl FromStr for SOARecord {
    type Err = crate::error::Error;

    fn from_str(soa_text: &str) -> Result<Self, Self::Err> {
        match parse_soa_text(soa_text) {
            Ok((_, soa_record)) => Ok(soa_record),
            Err(err) => Err(crate::error::Error::General(err.to_string())),
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct RPZEntry {
    pub domain: String,
    pub policy_action: String,
    pub comment: String,
}

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

impl FromStr for RPZEntry {
    type Err = crate::error::Error;

    fn from_str(rpz_entry: &str) -> Result<Self, Self::Err> {
        match parse_rpz_entry(rpz_entry) {
            Ok((_, rpz_entry)) => Ok(rpz_entry),
            Err(err) => Err(crate::error::Error::General(err.to_string())),
        }
    }
}

#[derive(Debug, Default)]
pub struct RPZFormat {
    pub ttl: u32,
    pub soa_record: SOARecord,
    pub ns: String,
    pub dns_entries: Vec<RPZEntry>,
}

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

impl FromStr for RPZFormat {
    type Err = crate::error::Error;

    fn from_str(rpz_file: &str) -> Result<Self, Self::Err> {
        return match parse_rpz_file(rpz_file) {
            Ok((_, rpz_file)) => Ok(rpz_file),
            Err(err) => Err(crate::error::Error::General(err.to_string())),
        };
    }
}

pub fn fetch_dns_rpz(web_client: &impl WebFetch) -> Result<RPZFormat, crate::error::Error> {
    RPZFormat::from_str(
        web_client.fetch(URL_HAUS_DNS_RPZ_URL)?.as_str(),
    )
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
