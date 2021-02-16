use std::fmt::Debug;

// -- Greeting --

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// An empty vector is used for "no code"
    pub code: Vec<String>,
    pub comment: String,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleLine {
    /// An empty vector is used for "no code"
    pub code: Vec<String>,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiLine<T>
where
    // TODO: relax trait bound
    T: Debug + Clone + PartialEq + Eq,
{
    pub head: SingleLine,
    pub body: Vec<T>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response<O, E>
where
    // TODO: relax trait bounds
    O: Debug + Clone + PartialEq + Eq,
    E: Debug + Clone + PartialEq + Eq,
{
    Ok(O),
    Err(E),
}

impl<O, E> Response<O, E>
where
    // TODO: relax trait bound
    O: Debug + Clone + PartialEq + Eq,
    E: Debug + Clone + PartialEq + Eq,
{
    pub fn unwrap(self) -> O {
        match self {
            Response::Ok(o) => o,
            Response::Err(e) => panic!("{:?}", e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropListing {
    pub message_count: u32,
    pub maildrop_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanListing {
    pub message_id: u32,
    pub message_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueIdListing {
    pub message_id: u32,
    pub message_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageListing {
    pub tag: String, // TODO: see RFC5646
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    // -- RFC2449 --
    Top,
    User,
    Sasl {
        mechanisms: Vec<String>, // TODO: String --> Mechanism
    },
    RespCodes,
    LoginDelay {
        minimum_seconds: u32,
        per_user: bool,
    },
    Pipelining,
    Expire {
        policy: ExpirePolicy,
        per_user: bool,
    },
    Uidl,
    Implementation {
        text: String,
    },
    // -- RFC2595 --
    Stls,
    // -- RFC3206 --
    AuthRespCode,
    // -- RFC6856 --
    Utf8 {
        in_credentials: bool,
    },
    Lang,
    // -----------------------
    Other {
        tag: String,
        parameters: Vec<String>,
    },
}

impl ToString for Capability {
    fn to_string(&self) -> String {
        use Capability::*;

        match self {
            Top => "TOP".into(),
            User => "USER".into(),
            Sasl { mechanisms } => {
                format!("SASL {}", mechanisms.join(" "))
            }
            RespCodes => "RESP-CODES".into(),
            LoginDelay {
                minimum_seconds,
                per_user,
            } => {
                let mut out = format!("LOGIN-DELAY {}", minimum_seconds);
                if *per_user {
                    out.push_str(" USER");
                }
                out
            }
            Pipelining => "PIPELINING".into(),
            Expire { policy, per_user } => {
                let mut out = format!("EXPIRE {}", policy.to_string());
                if *per_user {
                    out.push_str(" USER");
                }
                out
            }
            Uidl => "UIDL".into(),
            Implementation { text: tag } => format!("IMPLEMENTATION {}", tag),
            Stls => "STLS".into(),
            AuthRespCode => "AUTH-RESP-CODE".into(),
            Utf8 { in_credentials } => {
                if *in_credentials {
                    "UTF8 USER".into()
                } else {
                    "UTF8".into()
                }
            }
            Lang => "LANG".into(),
            Other { tag, parameters } => format!("{} {}", tag, parameters.join(" ")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpirePolicy {
    Never,
    MinimumDays(u32),
}

impl ToString for ExpirePolicy {
    fn to_string(&self) -> String {
        match self {
            ExpirePolicy::Never => "NEVER".into(),
            ExpirePolicy::MinimumDays(days) => days.to_string(),
        }
    }
}
