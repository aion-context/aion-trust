//! Tiny typed getters over `serde_json::Value` — untrusted input must fail soft (typed errors,
//! never a panic or an `unwrap`).

use serde_json::Value;

use crate::error::{InteropError, Result};

/// A required string field.
pub(crate) fn get_str<'a>(v: &'a Value, key: &'static str) -> Result<&'a str> {
    v.get(key)
        .ok_or(InteropError::MissingField(key))?
        .as_str()
        .ok_or(InteropError::WrongType(key))
}

/// A required object field.
pub(crate) fn get_obj<'a>(v: &'a Value, key: &'static str) -> Result<&'a Value> {
    let field = v.get(key).ok_or(InteropError::MissingField(key))?;
    if field.is_object() {
        Ok(field)
    } else {
        Err(InteropError::WrongType(key))
    }
}

/// A required field returned as an owned `Value` (for re-embedding).
pub(crate) fn take<'a>(v: &'a Value, key: &'static str) -> Result<&'a Value> {
    v.get(key).ok_or(InteropError::MissingField(key))
}
