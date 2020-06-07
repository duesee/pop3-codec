use crate::types::Command;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while},
    character::streaming::{digit1, line_ending, not_line_ending},
    combinator::{map, map_res, opt, value},
    sequence::tuple,
    IResult,
};
use std::str::from_utf8;

// TODO: there is an ABNF in rfc2449, which I havn't noticed.

pub fn command(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        alt((
            user, pass, apop, // AUTHORIZATION
            stat, list, retr, dele, noop, rset, top, uidl, // TRANSACTION
            capa, stls, auth_plain, auth, quit, // OTHER
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

pub fn auth_plain(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::AuthPlain, tag_no_case("AUTH PLAIN"))(input)
}

pub fn auth(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Auth, tag_no_case("AUTH"))(input)
}

pub fn quit(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Quit, tag_no_case("QUIT"))(input)
}

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
