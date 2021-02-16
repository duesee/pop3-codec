use md5::Context;

/// Convenience function, which calculates hexlify(md5("<{timestamp}>{password}"))
/// as used by POP3's APOP mechanism.
///
/// The timestamp must be provided *without* angle brackets, as they are
/// added by the function internally.
///
/// Note: This function (and the dependency on md5) is gated by the "utils"
/// feature (and used by default).
pub fn calculate_apop_digest(timestamp: &str, password: &str) -> String {
    let mut ctx = Context::new();
    ctx.consume("<");
    ctx.consume(timestamp);
    ctx.consume(">");
    ctx.consume(password);

    format!("{:x}", ctx.compute())
}
