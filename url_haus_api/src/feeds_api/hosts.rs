use std::str::FromStr;

use crate::WebFetch;

const URL_HAUS_HOSTS_FILE_URL: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";

#[derive(Debug, Default, PartialEq)]
pub struct Hostname {
    pub ip_addr: String,
    pub host_name: String,
    pub aliases: Option<Vec<String>>,
}

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

impl FromStr for Hostname {
    type Err = crate::error::Error;

    fn from_str(host_str: &str) -> Result<Self, Self::Err> {
        return match parse_hostname_line(host_str) {
            Ok((_, parsed_hostname)) => Ok(parsed_hostname),
            Err(parse_err) => Err(crate::error::Error::General(parse_err.to_string())),
        };
    }
}

fn parse_hosts_file(hosts_file_content: &str) -> Result<Vec<Hostname>, crate::error::Error> {
    Ok(hosts_file_content
        .lines()
        .filter(|line: &&str| !line.starts_with('#'))
        .filter_map(|line: &str| Hostname::from_str(line).ok())
        .collect())
}

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
        let fake_client = FakeHttpReqwest::default().set_success_response(
            include_str!("test_files/url_haus_hosts_file").to_string()
        );
        let hostnames = fetch_hosts_file(&fake_client)?;

        assert_eq!(hostnames.len(), 4);

        Ok(())
    }
}
