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

    // Other
    Capa,
    Stls,
    // TODO: Where is "AUTH\r\n" (without mechanism) defined?
    // rfc1939? no.
    // rfc1734? yes, but mechanism is required due to formal syntax and obsoleted.
    // rfc5034? yes, but mechanism is required due to formal syntax.
    Auth,
    AuthPlain,
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
            Command::AuthPlain => "AUTHPLAIN",
            Command::Auth => "AUTH",
        }
    }
}
