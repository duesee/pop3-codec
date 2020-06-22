use crate::types::Command;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1},
    character::streaming::{digit1, line_ending, not_line_ending},
    combinator::{map, map_res, opt, recognize, value},
    sequence::tuple,
    IResult,
};
use std::str::from_utf8;

pub fn single_line(input: &[u8]) -> IResult<&[u8], String> {
    let parser = tuple((
        map(not_line_ending, |data: &[u8]| {
            String::from_utf8(data.to_vec()).unwrap()
        }),
        line_ending,
    ));

    let (remaining, (parsed, _)) = parser(input)?;

    Ok((remaining, parsed))
}

pub fn number(input: &[u8]) -> IResult<&[u8], u32> {
    let parser = map_res(map_res(digit1, from_utf8), str::parse::<u32>);

    let (remaining, number) = parser(input)?;

    Ok((remaining, number))
}

// ABNF from RFC2449.

// POP3 commands:

// command = keyword *(SP param) CRLF
//            ; 255 octets maximum

// keyword = 3*4VCHAR

// param = 1*VCHAR

pub fn command(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        alt((
            user, pass, apop, stls, // AUTHORIZATION
            capa, quit, // AUTHORIZATION + TRANSACTION
            stat, list, retr, dele, noop, rset, top, uidl, // TRANSACTION
            auth, // not sorted yet
        )),
        line_ending,
    ));

    let (remaining, (parsed, _)) = parser(input)?;

    Ok((remaining, parsed))
}

pub fn user(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case("USER"),
        tag(" "),
        map_res(not_line_ending, from_utf8),
    ));

    let (remaining, (_, _, name)) = parser(input)?;

    Ok((remaining, Command::User(name.into())))
}

pub fn pass(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case("PASS"),
        tag(" "),
        map_res(not_line_ending, from_utf8),
    ));

    let (remaining, (_, _, pass)) = parser(input)?;

    Ok((remaining, Command::Pass(pass.into())))
}

pub fn apop(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case("APOP"),
        tag(" "),
        map_res(take_while(|byte| byte != b' '), from_utf8),
        tag(" "),
        map_res(take_while(|byte| byte != b'\r' || byte != b'\n'), from_utf8),
    ));

    let (remaining, (_, _, name, _, digest)) = parser(input)?;

    Ok((
        remaining,
        Command::Apop {
            name: name.into(),
            digest: digest.into(),
        },
    ))
}

pub fn stat(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Stat, tag_no_case("STAT"))(input)
}

pub fn list(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case("LIST"),
        opt(map(tuple((tag(" "), number)), |(_, msg)| msg)),
    ));

    let (remaining, (_, maybe_msg)) = parser(input)?;

    Ok((remaining, Command::List { msg: maybe_msg }))
}

pub fn uidl(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case("UIDL"),
        opt(map(tuple((tag(" "), number)), |(_, msg)| msg)),
    ));

    let (remaining, (_, maybe_msg)) = parser(input)?;

    Ok((remaining, Command::Uidl { msg: maybe_msg }))
}

pub fn retr(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case("RETR"), tag(" "), number));

    let (remaining, (_, _, msg)) = parser(input)?;

    Ok((remaining, Command::Retr { msg }))
}

pub fn dele(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case("DELE"), tag(" "), number));

    let (remaining, (_, _, msg)) = parser(input)?;

    Ok((remaining, Command::Dele { msg }))
}

pub fn noop(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Noop, tag_no_case("NOOP"))(input)
}

pub fn rset(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Rset, tag_no_case("RSET"))(input)
}

pub fn top(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case("TOP"), tag(" "), number, tag(" "), number));

    let (remaining, (_, _, msg, _, n)) = parser(input)?;

    Ok((remaining, Command::Top { msg, n }))
}

pub fn capa(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Capa, tag_no_case("CAPA"))(input)
}

pub fn stls(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Stls, tag_no_case("STLS"))(input)
}

pub fn auth(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = alt((
        map(
            tuple((
                tag_no_case(b"AUTH"),
                tag(" "),
                auth_type,
                opt(map(
                    tuple((
                        tag(" "),
                        alt((base64, map_res(tag("="), std::str::from_utf8))),
                    )),
                    |(_, maybe_ir)| maybe_ir,
                )),
            )),
            |(_, _, mechanism, initial_response)| Command::Auth {
                mechanism: mechanism.to_owned(),
                initial_response: initial_response.map(|i| i.to_owned()),
            },
        ),
        map(tag_no_case("AUTH"), |_| Command::AuthList),
    ));

    let (remaining, cmd) = parser(input)?;

    Ok((remaining, cmd))
}

pub fn is_auth_char(i: u8) -> bool {
    is_alpha(i) || is_digit(i) || i == b'-' || i == b'_'
}

pub fn auth_type(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while1(is_auth_char), std::str::from_utf8)(input)
}

pub fn base64(input: &[u8]) -> IResult<&[u8], &str> {
    let parser = map_res(
        recognize(tuple((
            take_while(is_base64_char),
            opt(alt((tag("=="), tag("=")))),
        ))),
        from_utf8,
    );

    let (remaining, base64) = parser(input)?;

    Ok((remaining, base64))
}

fn is_base64_char(i: u8) -> bool {
    is_alpha(i) || is_digit(i) || i == b'+' || i == b'/'
}

pub fn is_alpha(i: u8) -> bool {
    match i as char {
        'a'..='z' | 'A'..='Z' => true,
        _ => false,
    }
}

pub fn is_digit(byte: u8) -> bool {
    match byte {
        b'0'..=b'9' => true,
        _ => false,
    }
}

pub fn quit(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Quit, tag_no_case("QUIT"))(input)
}

// POP3 responses:

// response = greeting / single-line / capa-resp / multi-line

// ---

// greeting = "+OK" [resp-code] *gchar [timestamp] *gchar CRLF
//             ; 512 octets maximum

// resp-code = "[" resp-level *("/" resp-level) "]"

// resp-level = 1*rchar

// timestamp = "<" *VCHAR ">"
//              ; MUST conform to RFC-822 msg-id

// --

// single-line = status [SP text] CRLF
//                ; 512 octets maximum

// status = "+OK" / "-ERR"

// text = *schar / resp-code *CHAR

// --

// capa-resp = single-line *capability "." CRLF

// capability = capa-tag *(SP param) CRLF
//               ; 512 octets maximum

// capa-tag = 1*cchar

// --

// multi-line = single-line *dot-stuffed "." CRLF

// dot-stuffed = *CHAR CRLF
//                ; must be dot-stuffed

// --

// cchar = %x21-2D / %x2F-7F
//          ; printable ASCII, excluding "."
pub fn is_cchar(b: u8) -> bool {
    match b {
        0x21..=0x2D | 0x2F..=0x7F => true,
        _ => false,
    }
}

// gchar = %x21-3B / %x3D-7F
//          ;printable ASCII, excluding "<"
pub fn is_gchar(b: u8) -> bool {
    match b {
        0x21..=0x3B | 0x3D..=0x7F => true,
        _ => false,
    }
}

// rchar = %x21-2E / %x30-5C / %x5E-7F
//          ;printable ASCII, excluding "/" and "]"
pub fn is_rchar(b: u8) -> bool {
    match b {
        0x21..=0x2E | 0x30..=0x5C | 0x5E..=0x7F => true,
        _ => false,
    }
}

// schar = %x21-5A / %x5C-7F
//          ;printable ASCII, excluding "["
pub fn is_schar(b: u8) -> bool {
    match b {
        0x21..=0x5A | 0x5C..=0x7F => true,
        _ => false,
    }
}
