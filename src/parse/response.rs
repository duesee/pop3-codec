use crate::{
    parse::{language, number, param},
    types::response::{
        Capability, DropListing, ExpirePolicy, LanguageListing, MultiLine, Response, ScanListing,
        SingleLine, UniqueIdListing,
    },
};
use abnf_core::streaming::SP;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_till, take_while, take_while1, take_while_m_n},
    character::streaming::{line_ending, not_line_ending},
    combinator::{map, map_res, opt, value},
    error::ErrorKind,
    multi::{many0, separated_list1},
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult,
};
use std::str::from_utf8;

// ----- # Response -----

// response = greeting /
//            single-line /
//            multi-line /
//            capa-resp

// ----- ## Greeting -----

/// resp-code = "[" resp-level *("/" resp-level) "]"
pub(crate) fn resp_code(input: &[u8]) -> IResult<&[u8], Vec<&str>> {
    delimited(tag("["), separated_list1(tag("/"), resp_level), tag("]"))(input)
}

/// resp-level = 1*rchar
pub(crate) fn resp_level(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while1(is_rchar), from_utf8)(input)
}

/// Printable ASCII, excluding "/" and "]"
///
/// rchar = %x21-2E / %x30-5C / %x5E-7F
pub(crate) fn is_rchar(byte: u8) -> bool {
    matches!(byte, 0x21..=0x2E | 0x30..=0x5C | 0x5E..=0x7F)
}

/// Printable ASCII, excluding "<"
///
/// gchar = %x21-3B / %x3D-7F
///
/// Correction:
/// * %x21 --> %x20 // include SPACE?
///
pub(crate) fn is_gchar(byte: u8) -> bool {
    matches!(byte, 0x20..=0x3B | 0x3D..=0x7F)
}

/// timestamp = "<" *VCHAR ">"
///
/// Note: MUST conform to RFC-822 msg-id
///
/// Correction:
/// * *VCHAR must not contain ">"
///
pub(crate) fn timestamp(input: &[u8]) -> IResult<&[u8], &str> {
    delimited(
        tag("<"),
        map_res(take_till(|b| b == b'>'), from_utf8),
        tag(">"),
    )(input)
}

// VCHAR = <from ABNF core rules>

// ----- ## Single Line -----

/// single-line = status [SP text] CRLF
///
/// Note: 512 octets maximum
///
/// Edit: we use a version, where [SP text] is replaced by a `parser` and use it for
/// positive responses. Negative responses are parsed as showed in the single-line ABNF.
pub(crate) fn single_line<P, O>(
    input: &[u8],
    parser: P,
    payload_required: bool,
) -> IResult<&[u8], Response<O, SingleLine>>
where
    P: Fn(&[u8]) -> IResult<&[u8], O>,
    O: std::fmt::Debug + Clone + PartialEq + Eq,
{
    let (rem, status) = status(input)?;

    match status {
        Status::Ok => {
            let rem = if payload_required {
                let (rem, _) = SP(rem)?;
                rem
            } else {
                rem
            };

            let mut parser = tuple((parser, line_ending));

            let (rem, (something, _)) = parser(rem)?;

            Ok((rem, Response::Ok(something)))
        }
        Status::Err => {
            let mut parser = tuple((head, line_ending));

            let (rem, (head, _)) = parser(rem)?;

            Ok((rem, Response::Err(head)))
        }
    }
}

pub(crate) fn head(input: &[u8]) -> IResult<&[u8], SingleLine> {
    let mut parser = opt(preceded(SP, text));

    let (rem, maybe_text) = parser(input)?;

    let (code, comment) = match maybe_text {
        Some((code, comment)) => {
            let code = code.into_iter().map(|lvl| lvl.to_owned()).collect();

            let comment = comment.to_owned();

            (code, comment)
        }
        None => (Vec::default(), String::default()),
    };

    Ok((rem, SingleLine { code, comment }))
}

pub(crate) fn drop_listing(input: &[u8]) -> IResult<&[u8], DropListing> {
    let mut parser = separated_pair(number, SP, number);

    let (rem, (message_count, maildrop_size)) = parser(input)?;

    Ok((
        rem,
        DropListing {
            message_count,
            maildrop_size,
        },
    ))
}

pub(crate) fn scan_listing(input: &[u8]) -> IResult<&[u8], ScanListing> {
    let mut parser = separated_pair(number, SP, number);

    let (rem, (message_id, message_size)) = parser(input)?;

    Ok((
        rem,
        ScanListing {
            message_id,
            message_size,
        },
    ))
}

pub(crate) fn unique_id_listing(input: &[u8]) -> IResult<&[u8], UniqueIdListing> {
    // The unique-id of a message is an arbitrary server-determined
    // string, consisting of one to 70 characters in the range 0x21
    // to 0x7E, ...
    fn unique_id(input: &[u8]) -> IResult<&[u8], &str> {
        fn is_uid_char(b: u8) -> bool {
            matches!(b, 0x21..=0x7e)
        }

        map(take_while_m_n(1, 70, is_uid_char), |bytes| {
            from_utf8(bytes).unwrap()
        })(input)
    }

    let mut parser = separated_pair(number, SP, unique_id);

    let (rem, (message_id, message_uid)) = parser(input)?;

    Ok((
        rem,
        UniqueIdListing {
            message_id,
            message_uid: message_uid.to_owned(),
        },
    ))
}

pub(crate) fn language_listing(input: &[u8]) -> IResult<&[u8], LanguageListing> {
    let mut parser = separated_pair(language, SP, map_res(not_line_ending, from_utf8));

    let (rem, (tag, description)) = parser(input)?;

    Ok((
        rem,
        LanguageListing {
            tag: tag.to_owned(),
            description: description.to_owned(),
        },
    ))
}
// -------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
/// Private helper to pass `Status`
/// from `status` parser to `single_line` parser
enum Status {
    Ok,
    Err,
}

/// status = "+OK" / "-ERR"
fn status(input: &[u8]) -> IResult<&[u8], Status> {
    alt((
        value(Status::Ok, tag_no_case("+OK")),
        value(Status::Err, tag_no_case("-ERR")),
    ))(input)
}

/// text = *schar / resp-code *CHAR
///
/// Corrections:
/// resp-code --> resp-code SP
/// * *CHAR --> <read until \r\n excluding NULL>
/// *schar also matches empty sequence...
fn text(input: &[u8]) -> IResult<&[u8], (Vec<&str>, &str)> {
    let mut parser = alt((
        map(
            tuple((
                terminated(resp_code, SP),
                map_res(not_line_ending, from_utf8),
            )),
            |(code, comment)| (code, comment),
        ),
        map(map_res(take_while(is_schar), from_utf8), |comment| {
            (vec![], comment)
        }),
    ));

    let (rem, status) = parser(input)?;

    Ok((rem, status))
}

/// Printable ASCII, excluding "["
///
/// schar = %x21-5A / %x5C-7F
///
/// Corrections:
/// * %x21 --> %x20 // include SPACE
///
fn is_schar(byte: u8) -> bool {
    matches!(byte, 0x20..=0x5A | 0x5C..=0x7F)
}

// resp-code = <from response>

// CHAR = <from ABNF core rules>

// ----- ## Multi Line -----

/// multi-line = single-line *dot-stuffed "." CRLF
pub(crate) fn multi_line<P, O>(
    input: &[u8],
    parser: P,
) -> IResult<&[u8], Response<MultiLine<O>, SingleLine>>
where
    P: Fn(&[u8]) -> IResult<&[u8], O>,
    O: std::fmt::Debug + Clone + PartialEq + Eq,
{
    let (rem, single) = single_line(input, head, false)?;

    match single {
        Response::Ok(head) => {
            let mut parser = tuple((
                many0(terminated(parser, line_ending)),
                tuple((tag("."), line_ending)),
            ));

            let (rem, (something, _)) = parser(rem)?;

            Ok((
                rem,
                Response::Ok(MultiLine {
                    head,
                    body: something,
                }),
            ))
        }
        Response::Err(head) => Ok((rem, Response::Err(head))),
    }
}

// single-line = <from response>

// dot-stuffed = *CHAR CRLF
//
// Note: must be dot-stuffed
//
// Note: Do not consume CRLF, because it is done in higher-level multi-line parser
pub(crate) fn dot_stuffed(input: &[u8]) -> IResult<&[u8], String> {
    // Read until \r\n ...
    let mut parser = map_res(not_line_ending, from_utf8);

    let (rem, line) = parser(input)?;

    // ... and accept every line, which is not "."
    if line == "." {
        Err(nom::Err::Error(nom::error::Error::new(
            input,
            ErrorKind::IsNot,
        )))
    } else {
        Ok((rem, line.to_owned()))
    }
}

// -------------------------------------------------------------------------------------------------

/// capability = capa-tag *(SP param) CRLF
///
/// Note: 512 octets maximum
pub(crate) fn capability(input: &[u8]) -> IResult<&[u8], Capability> {
    let mut parser = alt((
        value(Capability::Top, tuple((tag_no_case("TOP"), line_ending))),
        value(Capability::User, tuple((tag_no_case("USER"), line_ending))),
        map(
            tuple((tag_no_case("SASL"), many0(preceded(SP, param)), line_ending)),
            |(_, params, _)| Capability::Sasl {
                mechanisms: params.into_iter().map(ToOwned::to_owned).collect(),
            },
        ),
        value(
            Capability::RespCodes,
            tuple((tag_no_case("RESP-CODES"), line_ending)),
        ),
        map(
            tuple((
                tag_no_case("LOGIN-DELAY"),
                SP,
                number,
                opt(tag_no_case(" USER")),
                line_ending,
            )),
            |(_, _, minimum_seconds, differ_per_user, _)| Capability::LoginDelay {
                minimum_seconds,
                per_user: differ_per_user.is_some(),
            },
        ),
        value(
            Capability::Pipelining,
            tuple((tag_no_case("PIPELINING"), line_ending)),
        ),
        map(
            tuple((
                tag_no_case("EXPIRE"),
                SP,
                alt((
                    map(number, ExpirePolicy::MinimumDays),
                    value(ExpirePolicy::Never, tag_no_case("NEVER")),
                )),
                opt(tag_no_case(" USER")),
                line_ending,
            )),
            |(_, _, policy, per_user, _)| Capability::Expire {
                policy,
                per_user: per_user.is_some(),
            },
        ),
        value(Capability::Uidl, tuple((tag_no_case("UIDL"), line_ending))),
        map(
            tuple((
                tag_no_case("IMPLEMENTATION"),
                SP,
                map_res(not_line_ending, from_utf8),
                line_ending,
            )),
            |(_, _, tag, _)| Capability::Implementation {
                text: tag.to_owned(),
            },
        ),
        value(Capability::Stls, tuple((tag_no_case("STLS"), line_ending))),
        value(
            Capability::AuthRespCode,
            tuple((tag_no_case("AUTH-RESP-CODE"), line_ending)),
        ),
        value(Capability::Lang, tuple((tag_no_case("LANG"), line_ending))),
        map(
            tuple((tag_no_case("UTF8"), opt(tag_no_case(" USER")), line_ending)),
            |(_, in_credentials, _)| Capability::Utf8 {
                in_credentials: in_credentials.is_some(),
            },
        ),
        map(
            tuple((capa_tag, many0(preceded(SP, param)), line_ending)),
            |(tag, params, _)| Capability::Other {
                tag: tag.to_owned(),
                parameters: params.into_iter().map(ToOwned::to_owned).collect(),
            },
        ),
    ));

    let (rem, capability) = parser(input)?;

    Ok((rem, capability))
}

/// capa-tag = 1*cchar
fn capa_tag(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while1(is_cchar), from_utf8)(input)
}

/// Printable ASCII, excluding "."
///
/// cchar = %x21-2D / %x2F-7F
///
/// Corrections:
/// * also excluding SPACE!
fn is_cchar(byte: u8) -> bool {
    matches!(byte, 0x21..=0x2D | 0x2F..=0x7F)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        parse::greeting,
        types::response::{Greeting, Response},
    };

    #[test]
    fn test_greetings() {
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
    fn test_single_lines() {
        let tests: &[(&[u8], Response<SingleLine, SingleLine>)] = &[
            (
                b"+OK\r\n",
                Response::Ok(SingleLine {
                    code: vec![],
                    comment: "".into(),
                }),
            ),
            (
                b"+OK \r\n",
                Response::Ok(SingleLine {
                    code: vec![],
                    comment: "".into(),
                }),
            ),
            (
                b"+OK ABC!\r\n",
                Response::Ok(SingleLine {
                    code: vec![],
                    comment: "ABC!".into(),
                }),
            ),
            (
                b"+OK [a] ABC!\r\n",
                Response::Ok(SingleLine {
                    code: vec!["a".into()],
                    comment: "ABC!".into(),
                }),
            ),
            (
                b"+OK [a/b] ABC! 1 < 3\r\n",
                Response::Ok(SingleLine {
                    code: vec!["a".into(), "b".into()],
                    comment: "ABC! 1 < 3".into(),
                }),
            ),
            (
                b"-ERR\r\n",
                Response::Err(SingleLine {
                    code: vec![],
                    comment: "".into(),
                }),
            ),
            (
                b"-Err \r\n",
                Response::Err(SingleLine {
                    code: vec![],
                    comment: "".into(),
                }),
            ),
            (
                b"-ERR ABC!\r\n",
                Response::Err(SingleLine {
                    code: vec![],
                    comment: "ABC!".into(),
                }),
            ),
            (
                b"-eRr [a] ABC!\r\n",
                Response::Err(SingleLine {
                    code: vec!["a".into()],
                    comment: "ABC!".into(),
                }),
            ),
            (
                b"-eRR [a/b] ABC! 1 < 3\r\n",
                Response::Err(SingleLine {
                    code: vec!["a".into(), "b".into()],
                    comment: "ABC! 1 < 3".into(),
                }),
            ),
        ];

        for (test, expected) in tests {
            let (rem, got) = single_line(test, head, false).unwrap();
            assert!(rem.is_empty());
            assert_eq!(*expected, got);
        }
    }

    #[test]
    fn test_multi_lines() {
        let tests: &[(&[u8], Vec<String>)] = &[
            (b"+OK\r\n.\r\n", vec![]),
            (b"+OK\r\n..\r\n.\r\n", vec!["..".into()]),
            (
                b"+OK\r\n...\r\n..\r\n.\r\n",
                vec!["...".into(), "..".into()],
            ),
            (b"+OK\r\n\r\n.\r\n", vec!["".into()]),
            (b"+OK\r\n \r\n.\r\n", vec![" ".into()]),
        ];

        for (test, expected) in tests {
            let (rem, got) = multi_line(test, dot_stuffed).unwrap();
            assert!(rem.is_empty());
            assert_eq!(*expected, got.unwrap().body);
        }
    }

    #[test]
    fn test_capa_resp_lines() {
        let tests: &[(&[u8], Capability)] = &[
            (b"TOP\r\n", Capability::Top),
            (b"USER\r\n", Capability::User),
            (
                b"SASL AUTH PLAIN\r\n",
                Capability::Sasl {
                    mechanisms: vec!["AUTH".into(), "PLAIN".into()],
                },
            ),
            (b"RESP-CODES\r\n", Capability::RespCodes),
            (
                b"LOGIN-DELAY 0\r\n",
                Capability::LoginDelay {
                    minimum_seconds: 0,
                    per_user: false,
                },
            ),
            (
                b"LOGIN-DELAY 4294967295 USER\r\n",
                Capability::LoginDelay {
                    minimum_seconds: u32::MAX,
                    per_user: true,
                },
            ),
            (
                b"LOGIN-DELAY 0\r\n",
                Capability::LoginDelay {
                    minimum_seconds: 0,
                    per_user: false,
                },
            ),
            (
                b"LOGIN-DELAY 4294967295 USER\r\n",
                Capability::LoginDelay {
                    minimum_seconds: u32::MAX,
                    per_user: true,
                },
            ),
            (b"PIPELINING\r\n", Capability::Pipelining),
            (
                b"EXPIRE 0\r\n",
                Capability::Expire {
                    policy: ExpirePolicy::MinimumDays(0),
                    per_user: false,
                },
            ),
            (
                b"EXPIRE 4294967295\r\n",
                Capability::Expire {
                    policy: ExpirePolicy::MinimumDays(u32::MAX),
                    per_user: false,
                },
            ),
            (
                b"EXPIRE NEVER\r\n",
                Capability::Expire {
                    policy: ExpirePolicy::Never,
                    per_user: false,
                },
            ),
            (
                b"EXPIRE 0 USER\r\n",
                Capability::Expire {
                    policy: ExpirePolicy::MinimumDays(0),
                    per_user: true,
                },
            ),
            (
                b"EXPIRE 4294967295 USER\r\n",
                Capability::Expire {
                    policy: ExpirePolicy::MinimumDays(u32::MAX),
                    per_user: true,
                },
            ),
            (
                b"EXPIRE NEVER USER\r\n",
                Capability::Expire {
                    policy: ExpirePolicy::Never,
                    per_user: true,
                },
            ),
            (b"UIDL\r\n", Capability::Uidl),
            (
                b"IMPLEMENTATION fake\r\n",
                Capability::Implementation {
                    text: "fake".into(),
                },
            ),
            (b"STLS\r\n", Capability::Stls),
            (b"AUTH-RESP-CODE\r\n", Capability::AuthRespCode),
            (b"LANG\r\n", Capability::Lang),
            (
                b"UTF8\r\n",
                Capability::Utf8 {
                    in_credentials: false,
                },
            ),
            (
                b"UTF8 USER\r\n",
                Capability::Utf8 {
                    in_credentials: true,
                },
            ),
            (
                b"X-SPECIAL something different\r\n",
                Capability::Other {
                    tag: "X-SPECIAL".into(),
                    parameters: vec!["something".into(), "different".into()],
                },
            ),
        ];

        for (test, expected) in tests {
            // Parse ...
            let (rem, got) = capability(test).unwrap();
            assert!(rem.is_empty());
            assert_eq!(*expected, got);

            // Serialize...
            let serialized = got.to_string() + "\r\n";
            assert_eq!(serialized.as_bytes(), *test);
        }
    }
}
