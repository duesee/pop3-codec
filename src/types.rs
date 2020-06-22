#[derive(Clone)]
pub enum State {
    Authorization,
    Transaction,
    Update,
}

// 9. POP3 Command Summary
#[derive(Clone, Debug)]
pub enum Command {
    // Minimal POP3 Commands:
    // -- AUTHORIZATION state --
    /// USER name
    User(String),
    /// PASS string
    Pass(String),
    // -- TRANSACTION state --
    /// STAT
    Stat,
    /// LIST [msg]
    List {
        msg: Option<u32>,
    },
    /// RETR msg
    Retr {
        msg: u32,
    },
    /// DELE msg
    Dele {
        msg: u32,
    },
    /// NOOP
    Noop,
    /// RSET
    Rset,
    // -- AUTHORIZATION state + TRANSACTION state --
    /// QUIT
    Quit,

    // Optional POP3 Commands:
    // -- AUTHORIZATION state --
    /// APOP name digest
    Apop {
        name: String,
        digest: String,
    },
    // -- TRANSACTION state --
    /// TOP msg n
    Top {
        msg: u32,
        n: u32,
    },
    /// UIDL [msg]
    Uidl {
        msg: Option<u32>,
    },

    // RFC2449 (POP3 Extension Mechanism):
    /// CAPA
    Capa,

    // RFC2595 (Using TLS with IMAP, POP3 and ACAP):
    /// STLS
    Stls,
    // RFC5034 (POP3 SASL Authentication Mechanism)
    Auth {
        mechanism: String,
        initial_response: Option<String>,
    },
    // TODO: Where is "AUTH\r\n" (without mechanism) defined?
    // rfc1939? no.
    // rfc1734? yes, but mechanism is required due to formal syntax and obsoleted.
    // rfc5034? yes, but mechanism is required due to formal syntax.
    AuthList,
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::User(_) => "USER",
            Command::Pass(_) => "PASS",
            Command::Stat => "STAT",
            Command::List { .. } => "LIST",
            Command::Retr { .. } => "RETR",
            Command::Dele { .. } => "DELE",
            Command::Noop => "NOOP",
            Command::Rset => "RSET",
            Command::Quit => "QUIT",
            Command::Apop { .. } => "APOP",
            Command::Top { .. } => "TOP",
            Command::Uidl { .. } => "UIDL",
            Command::Capa => "CAPA",
            Command::Stls => "STLS",
            Command::Auth { .. } => "AUTH",
            Command::AuthList => "AUTHLIST",
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Command::User(user) => format!("USER {}\r\n", user).into_bytes(),
            Command::Pass(pass) => format!("PASS {}\r\n", pass).into_bytes(),
            Command::Stat => b"STAT\r\n".to_vec(),
            Command::List { msg } => match msg {
                None => b"LIST\r\n".to_vec(),
                Some(msg) => format!("LIST {}\r\n", msg).into_bytes(),
            },
            Command::Retr { msg } => format!("RETR {}\r\n", msg).into_bytes(),
            Command::Dele { msg } => format!("DELE {}\r\n", msg).into_bytes(),
            Command::Noop => b"NOOP\r\n".to_vec(),
            Command::Rset => b"RSET\r\n".to_vec(),
            Command::Quit => b"QUIT\r\n".to_vec(),
            Command::Apop { name, digest } => format!("APOP {} {}\r\n", name, digest).into_bytes(),
            Command::Top { msg, n } => format!("TOP {} {}\r\n", msg, n).into_bytes(),
            Command::Uidl { msg } => match msg {
                None => b"UIDL\r\n".to_vec(),
                Some(msg) => format!("UIDL {}\r\n", msg).into_bytes(),
            },
            Command::Capa => b"CAPA\r\n".to_vec(),
            Command::Stls => b"STLS\r\n".to_vec(),
            Command::Auth {
                mechanism,
                initial_response,
            } => match initial_response {
                Some(initial_response) => {
                    format!("AUTH {} {}\r\n", mechanism, initial_response).into_bytes()
                }
                None => format!("AUTH {}\r\n", mechanism).into_bytes(),
            },
            Command::AuthList => b"AUTH\r\n".to_vec(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Command;

    #[test]
    fn test_serialize() {
        assert_eq!(Command::User("alice".into()).serialize(), b"USER alice\r\n");
        assert_eq!(
            Command::Pass("password".into()).serialize(),
            b"PASS password\r\n"
        );
        assert_eq!(Command::Stat.serialize(), b"STAT\r\n");
        assert_eq!(Command::List { msg: None }.serialize(), b"LIST\r\n");
        assert_eq!(Command::List { msg: Some(1) }.serialize(), b"LIST 1\r\n");
        assert_eq!(Command::Retr { msg: 1 }.serialize(), b"RETR 1\r\n");
        assert_eq!(Command::Dele { msg: 1 }.serialize(), b"DELE 1\r\n");
        assert_eq!(Command::Noop.serialize(), b"NOOP\r\n");
        assert_eq!(Command::Rset.serialize(), b"RSET\r\n");
        assert_eq!(Command::Quit.serialize(), b"QUIT\r\n");
        assert_eq!(
            Command::Apop {
                name: "alice".into(),
                digest: "aabbccddeeff".into()
            }
            .serialize(),
            b"APOP alice aabbccddeeff\r\n"
        );
        assert_eq!(Command::Top { msg: 1, n: 5 }.serialize(), b"TOP 1 5\r\n");
        assert_eq!(Command::Uidl { msg: None }.serialize(), b"UIDL\r\n");
        assert_eq!(Command::Uidl { msg: Some(1) }.serialize(), b"UIDL 1\r\n");
        assert_eq!(Command::Capa.serialize(), b"CAPA\r\n");
        assert_eq!(Command::Stls.serialize(), b"STLS\r\n");
        assert_eq!(
            Command::Auth {
                mechanism: "PLAIN".into(),
                initial_response: None
            }
            .serialize(),
            b"AUTH PLAIN\r\n"
        );
        assert_eq!(
            Command::Auth {
                mechanism: "PLAIN".into(),
                initial_response: Some("XXX".into())
            }
            .serialize(),
            b"AUTH PLAIN XXX\r\n"
        );
        assert_eq!(Command::AuthList.serialize(), b"AUTH\r\n");
    }
}
