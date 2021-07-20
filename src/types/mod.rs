pub(crate) mod command;
pub(crate) mod response;

pub use command::{Command, Language};
pub use response::Response;

#[derive(Clone)]
pub enum State {
    Authorization,
    Transaction,
    Update,
}
