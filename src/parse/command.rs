use crate::{
    parse::{language, number},
    types::command::{Command, Language},
};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1},
    character::streaming::not_line_ending,
    combinator::{map, map_res, opt, recognize, value},
    sequence::{preceded, tuple},
    IResult,
};
use std::str::from_utf8;

pub(crate) fn user(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case("USER"),
        tag(" "),
        map_res(not_line_ending, from_utf8),
    ));

    let (remaining, (_, _, name)) = parser(input)?;

    Ok((remaining, Command::User(name.into())))
}

pub(crate) fn pass(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case("PASS"),
        tag(" "),
        map_res(not_line_ending, from_utf8),
    ));

    let (remaining, (_, _, pass)) = parser(input)?;

    Ok((remaining, Command::Pass(pass.into())))
}

pub(crate) fn stat(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Stat, tag_no_case("STAT"))(input)
}

pub(crate) fn list(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case("LIST"),
        opt(map(tuple((tag(" "), number)), |(_, msg)| msg)),
    ));

    let (remaining, (_, maybe_msg)) = parser(input)?;

    Ok((
        remaining,
        match maybe_msg {
            Some(msg) => Command::List { msg },
            None => Command::ListAll,
        },
    ))
}

pub(crate) fn retr(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((tag_no_case("RETR"), tag(" "), number));

    let (remaining, (_, _, msg)) = parser(input)?;

    Ok((remaining, Command::Retr { msg }))
}

pub(crate) fn dele(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((tag_no_case("DELE"), tag(" "), number));

    let (remaining, (_, _, msg)) = parser(input)?;

    Ok((remaining, Command::Dele { msg }))
}

pub(crate) fn noop(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Noop, tag_no_case("NOOP"))(input)
}

pub(crate) fn rset(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Rset, tag_no_case("RSET"))(input)
}

pub(crate) fn quit(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Quit, tag_no_case("QUIT"))(input)
}

pub(crate) fn apop(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case("APOP"),
        tag(" "),
        map_res(take_while(|byte| byte != b' '), from_utf8),
        tag(" "),
        map_res(not_line_ending, from_utf8),
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

pub(crate) fn top(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((tag_no_case("TOP"), tag(" "), number, tag(" "), number));

    let (remaining, (_, _, msg, _, n)) = parser(input)?;

    Ok((remaining, Command::Top { msg, n }))
}

pub(crate) fn uidl(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = preceded(tag_no_case("UIDL"), opt(preceded(tag(" "), number)));

    let (remaining, maybe_msg) = parser(input)?;

    Ok((
        remaining,
        match maybe_msg {
            Some(msg) => Command::Uidl { msg },
            None => Command::UidlAll,
        },
    ))
}

pub(crate) fn capa(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Capa, tag_no_case("CAPA"))(input)
}

pub(crate) fn stls(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Stls, tag_no_case("STLS"))(input)
}

pub(crate) fn auth(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = alt((
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
        map(tag_no_case("AUTH"), |_| Command::AuthAll),
    ));

    let (remaining, cmd) = parser(input)?;

    Ok((remaining, cmd))
}

pub(crate) fn utf8(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Utf8, tag_no_case("UTF8"))(input)
}

pub(crate) fn lang(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = preceded(tag_no_case("LANG"), opt(preceded(tag(" "), lang_or_wild)));

    let (remaining, maybe_lang) = parser(input)?;

    Ok((
        remaining,
        match maybe_lang {
            Some(lang_or_wild) => Command::Lang { lang_or_wild },
            None => Command::LangAll,
        },
    ))
}

// -------------------------------------------------------------------------------------------------

fn auth_type(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(take_while1(is_auth_char), std::str::from_utf8)(input)
}

fn is_auth_char(i: u8) -> bool {
    is_alpha(i) || is_digit(i) || i == b'-' || i == b'_'
}

fn base64(input: &[u8]) -> IResult<&[u8], &str> {
    let mut parser = map_res(
        recognize(tuple((
            take_while(is_base64_char),
            opt(alt((tag("=="), tag("=")))),
        ))),
        from_utf8,
    );

    let (remaining, base64) = parser(input)?;

    Ok((remaining, base64))
}

fn is_base64_char(byte: u8) -> bool {
    is_alpha(byte) || is_digit(byte) || byte == b'+' || byte == b'/'
}

fn is_alpha(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'A'..=b'Z')
}

fn is_digit(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9')
}

fn lang_or_wild(input: &[u8]) -> IResult<&[u8], Language> {
    alt((
        value(Language::Wild, tag("*")),
        map(language, |lang| Language::Lang(lang.to_string())),
    ))(input)
}
