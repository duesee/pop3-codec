use std::str::from_utf8;

use abnf_core::streaming::{is_ALPHA, is_VCHAR, SP};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1, take_while_m_n},
    character::{
        is_alphanumeric,
        streaming::{digit1, line_ending},
    },
    combinator::{map_res, opt, recognize},
    multi::many0,
    sequence::{preceded, terminated, tuple},
    IResult,
};

use crate::{
    parse::{command::*, response::*},
    types::{
        command::Command,
        response::{
            Capability, DropListing, Greeting, LanguageListing, MultiLine, Response, ScanListing,
            SingleLine, UniqueIdListing,
        },
    },
};

mod command;
mod response;

/// Parses the server greeting.
pub fn greeting(input: &[u8]) -> IResult<&[u8], Greeting> {
    // greeting = "+OK" [resp-code] *gchar [timestamp] *gchar CRLF
    //
    // Corrections:
    // * [resp-code] -> [SP resp-code]
    //
    // TODO: 512 octets maximum (?)
    let mut parser = tuple((
        tag_no_case("+OK"),
        opt(preceded(SP, resp_code)),
        opt(preceded(
            SP,
            tuple((
                map_res(take_while(is_gchar), from_utf8),
                opt(timestamp),
                map_res(take_while(is_gchar), from_utf8),
            )),
        )),
        line_ending,
    ));

    let (rem, (_, maybe_code, maybe_body, _)) = parser(input)?;

    let code = maybe_code
        .unwrap_or_default()
        .into_iter()
        .map(|lvl| lvl.to_owned())
        .collect();

    let res = match maybe_body {
        Some((comment1, maybe_timestamp, comment2)) => {
            let timestamp = maybe_timestamp.map(ToOwned::to_owned);

            let comment = match timestamp.as_ref() {
                Some(_) => format!("{}<>{}", comment1, comment2),
                None => format!("{}{}", comment1, comment2),
            };

            Greeting {
                code,
                comment,
                timestamp,
            }
        }
        None => Greeting {
            code,
            comment: "".into(),
            timestamp: None,
        },
    };

    Ok((rem, res))
}

/// Parses any command.
///
/// See the [Command](crate::types::Command) enum for supported commands.
pub fn command(input: &[u8]) -> IResult<&[u8], Command> {
    terminated(
        alt((
            user, pass, apop, stls, // AUTHORIZATION
            capa, quit, // AUTHORIZATION + TRANSACTION
            stat, list, retr, dele, noop, rset, top, uidl, // TRANSACTION
            auth, utf8, lang, // not sorted yet
        )),
        line_ending,
    )(input)
}

/// Parses the response to the [User](crate::types::Command::User) command.
pub fn response_user(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [Pass](crate::types::Command::Pass) command.
pub fn response_pass(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [Stat](crate::types::Command::Stat) command.
pub fn response_stat(input: &[u8]) -> IResult<&[u8], Response<DropListing, SingleLine>> {
    single_line(input, drop_listing, true)
}

/// Parses the response to the [ListAll](crate::types::Command::ListAll) command, i.e. LIST without a parameter.
pub fn response_list_all(
    input: &[u8],
) -> IResult<&[u8], Response<MultiLine<ScanListing>, SingleLine>> {
    multi_line(input, scan_listing)
}

/// Parses the response to the [List](crate::types::Command::List) command, i.e. LIST with a parameter.
pub fn response_list(input: &[u8]) -> IResult<&[u8], Response<ScanListing, SingleLine>> {
    single_line(input, scan_listing, true)
}

/// Parses the response to the [Retr](crate::types::Command::Retr) command.
pub fn response_retr(input: &[u8]) -> IResult<&[u8], Response<MultiLine<String>, SingleLine>> {
    multi_line(input, dot_stuffed)
}

/// Parses the response to the [Dele](crate::types::Command::Dele) command.
pub fn response_dele(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [Noop](crate::types::Command::Noop) command.
pub fn response_noop(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [Rset](crate::types::Command::Rset) command.
pub fn response_rset(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [Quit](crate::types::Command::Quit) command.
pub fn response_quit(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [Apop](crate::types::Command::Apop) command.
pub fn response_apop(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [Top](crate::types::Command::Top) command.
pub fn response_top(input: &[u8]) -> IResult<&[u8], Response<MultiLine<String>, SingleLine>> {
    multi_line(input, dot_stuffed)
}

/// Parses the response to the [UidlAll](crate::types::Command::UidlAll) command, i.e. UIDL when used without a parameter.
pub fn response_uidl_all(
    input: &[u8],
) -> IResult<&[u8], Response<MultiLine<UniqueIdListing>, SingleLine>> {
    multi_line(input, unique_id_listing)
}

/// Parses the response to the [Uidl](crate::types::Command::Uidl) command, i.e. UIDL when used with a parameter.
pub fn response_uidl(input: &[u8]) -> IResult<&[u8], Response<UniqueIdListing, SingleLine>> {
    single_line(input, unique_id_listing, true)
}

/// Parses the response to the [Capa](crate::types::Command::Capa) command.
pub fn response_capa(input: &[u8]) -> IResult<&[u8], Response<MultiLine<Capability>, SingleLine>> {
    // capa-resp = single-line *capability "." CRLF
    multi_line(input, capability)
}

/// Parses the response to the [Stls](crate::types::Command::Stls) command.
pub fn response_stls(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [AuthAll](crate::types::Command::AuthAll) command, i.e. AUTH when used without a parameter.
///
/// Note: This command appears to be non-standard. However, MUAs use it and popular POP3 servers understand it.
pub fn response_auth_all(input: &[u8]) -> IResult<&[u8], Response<MultiLine<String>, SingleLine>> {
    multi_line(input, dot_stuffed)
}

// TODO: response_auth

/// Parses the response to the [Utf8](crate::types::Command::Utf8) command.
pub fn response_utf8(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

/// Parses the response to the [LangAll](crate::types::Command::LangAll) command, i.e. LANG when used without a parameter.
pub fn response_lang_all(
    input: &[u8],
) -> IResult<&[u8], Response<MultiLine<LanguageListing>, SingleLine>> {
    multi_line(input, language_listing)
}

/// Parses the response to the [Lang](crate::types::Command::Lang) command, i.e. LANG when used with a parameter.
pub fn response_lang(input: &[u8]) -> IResult<&[u8], Response<SingleLine, SingleLine>> {
    single_line(input, head, false)
}

// -------------------------------------------------------------------------------------------------

pub(crate) fn number(input: &[u8]) -> IResult<&[u8], u32> {
    map_res(map_res(digit1, from_utf8), str::parse::<u32>)(input)
}

// -------------------------------------------------------------------------------------------------

/// language-range = (1*8ALPHA *("-" 1*8alphanum)) / "*"
///
/// alphanum       = ALPHA / DIGIT
///
/// Note: don't use wildcard here, because it is only useful in command?
pub(crate) fn language(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        recognize(tuple((
            take_while_m_n(1, 8, is_ALPHA),
            many0(tuple((tag(b"-"), take_while_m_n(1, 8, is_alphanumeric)))),
        ))),
        from_utf8,
    )(input)
}

// -------------------------------------------------------------------------------------------------
//
// ABNF from RFC2449

// ----- Generic -----

// param = 1*VCHAR
pub(crate) fn param(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while1(is_VCHAR), from_utf8)(input)
}

// VCHAR = <from ABNF core rules>

// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_greeting() {
        let tests: &[(&[u8], Greeting)] = &[
            (
                b"+OK\r\n",
                Greeting {
                    code: vec![],
                    comment: "".into(),
                    timestamp: None,
                },
            ),
            (
                b"+OK \r\n",
                Greeting {
                    code: vec![],
                    comment: "".into(),
                    timestamp: None,
                },
            ),
            (
                b"+OK A\r\n",
                Greeting {
                    code: vec![],
                    comment: "A".into(),
                    timestamp: None,
                },
            ),
            (
                b"+OK Z\r\n",
                Greeting {
                    code: vec![],
                    comment: "Z".into(),
                    timestamp: None,
                },
            ),
            (
                b"+ok Hello World!\r\n",
                Greeting {
                    code: vec![],
                    comment: "Hello World!".into(),
                    timestamp: None,
                },
            ),
            (
                b"+ok Hello <123> World!\r\n",
                Greeting {
                    code: vec![],
                    comment: "Hello <> World!".into(),
                    timestamp: Some("123".into()),
                },
            ),
            (
                b"+ok [a] Hello World!\r\n",
                Greeting {
                    code: vec!["a".into()],
                    comment: "Hello World!".into(),
                    timestamp: None,
                },
            ),
            (
                b"+ok [a] Hello <123> World!\r\n",
                Greeting {
                    code: vec!["a".into()],
                    comment: "Hello <> World!".into(),
                    timestamp: Some("123".into()),
                },
            ),
        ];

        for (test, expected) in tests {
            let (rem, got) = greeting(test).unwrap();
            assert!(rem.is_empty());
            assert_eq!(*expected, got);
        }
    }

    #[test]
    fn test_command() {
        // Extracted via "C: ([^\n]*\n)" regex from RFC 1939
        let commands = "\
QUIT
STAT
LIST
LIST 2
LIST 3
RETR 1
DELE 1
DELE 2
NOOP
RSET
QUIT
QUIT
TOP 1 10
TOP 100 3
UIDL
UIDL 2
UIDL 3
USER frated
USER mrose
USER mrose
PASS secret
USER mrose
PASS secret
APOP mrose c4c9334bac560ecc979e58001b3e22fb
APOP mrose c4c9334bac560ecc979e58001b3e22fb
STAT
LIST
RETR 1
DELE 1
RETR 2
DELE 2
QUIT
LANG MUL
LANG
LANG
LANG es
LANG uga
LANG sv
LANG *
UTF8
";

        for cmd in commands.lines() {
            let cmd = cmd.to_string() + "\r\n";
            print!("C: {}", cmd);
            let (rem, cmd) = super::command(cmd.as_bytes()).unwrap();
            assert!(rem.is_empty());
            println!("{:?}\n", cmd);
        }
    }

    #[test]
    fn test_response() {
        println!(
            "{:#?}",
            response_quit(b"+OK dewey POP3 server signing off\r\n")
                .unwrap()
                .1
        );
        println!("{:#?}", response_stat(b"+OK 2 320\r\n").unwrap().1);
        println!(
            "{:#?}",
            response_list_all(
                b"+OK 2 messages (320 octets)
1 120
2 200
.
",
            )
            .unwrap()
            .1
        );
        println!("{:#?}", response_list(b"+OK 2 200\r\n").unwrap().1);
        println!(
            "{:#?}",
            response_list(b"-ERR no such message, only 2 messages in maildrop\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_retr(
                b"+OK 120 octets
<the POP3 server sends the entire message here>
.
",
            )
            .unwrap()
            .1
        );
        println!(
            "{:#?}",
            response_dele(b"+OK message 1 deleted\r\n").unwrap().1
        );
        println!(
            "{:#?}",
            response_dele(b"-ERR message 2 already deleted\r\n")
                .unwrap()
                .1
        );
        println!("{:#?}", response_noop(b"+OK\r\n").unwrap().1);
        println!(
            "{:#?}",
            response_rset(b"+OK maildrop has 2 messages (320 octets)\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_quit(b"+OK dewey POP3 server signing off (maildrop empty)\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_quit(b"+OK dewey POP3 server signing off (2 messages left)\r\n")
                .unwrap()
                .1
        );
        println!("{:#?}", response_top(b"+OK
<the POP3 server sends the headers of the message, a blank line, and the first 10 lines of the body of the message>
.
").unwrap().1);
        println!(
            "{:#?}",
            response_top(b"-ERR no such message\r\n").unwrap().1
        );
        println!(
            "{:#?}",
            response_uidl_all(
                b"+OK
1 whqtswO00WBw418f9t5JxYwZ
2 QhdPYR:00WBw1Ph7x7
.
",
            )
            .unwrap()
            .1
        );
        println!(
            "{:#?}",
            response_uidl(b"+OK 2 QhdPYR:00WBw1Ph7x7\r\n").unwrap().1
        );
        println!(
            "{:#?}",
            response_uidl(b"-ERR no such message, only 2 messages in maildrop\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_user(b"-ERR sorry, no mailbox for frated here\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_user(b"+OK mrose is a real hoopy frood\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_pass(b"-ERR maildrop already locked\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_pass(b"+OK mrose's maildrop has 2 messages (320 octets)\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_apop(b"+OK maildrop has 1 message (369 octets)\r\n")
                .unwrap()
                .1
        );

        println!(
            "{:#?}",
            response_lang(b"-ERR invalid language MUL\r\n").unwrap().1
        );
        println!(
            "{:#?}",
            response_lang_all(
                b"+OK Language listing follows:
en English
en-boont English Boontling dialect
de Deutsch
it Italiano
es Espanol
sv Svenska
i-default Default language
.
"
            )
            .unwrap()
            .1
        );
        println!(
            "{:#?}",
            response_lang_all(b"-ERR Server is unable to list languages\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_lang(b"+OK es Idioma cambiado\r\n").unwrap().1
        );
        println!(
            "{:#?}",
            response_lang(b"-ERR es Idioma <<UGA>> no es conocido\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_lang(b"+OK sv Kommandot \"LANG\" lyckades\r\n")
                .unwrap()
                .1
        );
        println!(
            "{:#?}",
            response_lang(b"+OK es Idioma cambiado\r\n").unwrap().1
        );
    }

    #[test]
    fn test_example_session() {
        let client = b"\
APOP mrose c4c9334bac560ecc979e58001b3e22fb
STAT
LIST
RETR 1
DELE 1
RETR 2
DELE 2
QUIT
";

        let server = b"\
+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
+OK mrose's maildrop has 2 messages (320 octets)
+OK 2 320
+OK 2 messages (320 octets)
1 120
2 200
.
+OK 120 octets
<the POP3 server sends message 1>
.
+OK message 1 deleted
+OK 200 octets
<the POP3 server sends message 2>
.
+OK message 2 deleted
+OK dewey POP3 server signing off (maildrop empty)
";

        let mut rem_client = client.as_ref();
        let mut rem_server = server.as_ref();

        let (rem, greeting) = greeting(rem_server).unwrap();
        println!("{:#?}", greeting);
        rem_server = rem;

        while !rem_client.is_empty() {
            let (rem, cmd) = command(rem_client).unwrap();
            println!("{:#?}", cmd);
            rem_client = rem;

            use Command::*;
            match cmd {
                User(_) => {
                    let (rem, resp) = response_user(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Pass(_) => {
                    let (rem, resp) = response_pass(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Stat => {
                    let (rem, resp) = response_stat(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                ListAll => {
                    let (rem, resp) = response_list_all(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                List { .. } => {
                    let (rem, resp) = response_list(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Retr { .. } => {
                    let (rem, resp) = response_retr(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Dele { .. } => {
                    let (rem, resp) = response_dele(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Noop => {
                    let (rem, resp) = response_noop(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Rset => {
                    let (rem, resp) = response_rset(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Quit => {
                    let (rem, resp) = response_quit(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Apop { .. } => {
                    let (rem, resp) = response_apop(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Top { .. } => {
                    let (rem, resp) = response_top(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                UidlAll => {
                    let (rem, resp) = response_uidl_all(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Uidl { .. } => {
                    let (rem, resp) = response_uidl(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Capa => {
                    let (rem, resp) = response_user(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Stls => {
                    let (rem, resp) = response_stls(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                AuthAll => {
                    let (rem, resp) = response_auth_all(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Auth { .. } => {
                    unimplemented!()
                }
                Utf8 => {
                    let (rem, resp) = response_utf8(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                LangAll => {
                    let (rem, resp) = response_lang_all(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
                Lang { .. } => {
                    let (rem, resp) = response_lang(rem_server).unwrap();
                    println!("{:#?}", resp);
                    rem_server = rem;
                }
            }
        }
    }
}
