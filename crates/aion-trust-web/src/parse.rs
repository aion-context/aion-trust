//! Pure parsing helpers for the web forms — kept dependency-free and in the mutation-testing
//! scope. Two jobs: decode an `application/x-www-form-urlencoded` body into key/value pairs
//! (preserving repeated keys, which checkboxes need), and parse the verifier's predicate lines
//! (mirroring the CLI's `<category>:<field>:<op>:<bound>[:<schema_id>]` grammar).

use aion_trust_claims::{PredicateOp, PredicateRequest};

/// Decode a form-urlencoded body into ordered `(key, value)` pairs. Repeated keys are kept
/// (so multiple checked checkboxes all survive). `+` becomes space; `%XX` is percent-decoded.
pub(crate) fn form_pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// All values for a given key, in order.
pub(crate) fn values<'a>(pairs: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    pairs
        .iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .collect()
}

/// First value for a key, if present.
pub(crate) fn first<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Percent- and `+`-decode one urlencoded component. Invalid `%` escapes are passed through
/// literally rather than panicking (untrusted input must fail soft).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match hex2(bytes[i + 1], bytes[i + 2]) {
                Some(byte) => {
                    out.push(byte);
                    i += 2;
                }
                None => out.push(b'%'),
            },
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex2(hi: u8, lo: u8) -> Option<u8> {
    Some(nibble(hi)? * 16 + nibble(lo)?)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a textarea of predicate lines (blank lines ignored).
///
/// # Errors
/// Returns a human-readable message on the first malformed line.
pub(crate) fn parse_predicates(text: &str) -> Result<Vec<PredicateRequest>, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(parse_line)
        .collect()
}

fn parse_line(line: &str) -> Result<PredicateRequest, String> {
    let parts: Vec<&str> = line.split(':').collect();
    let [category, field, op, bound, rest @ ..] = parts.as_slice() else {
        return Err(format!(
            "predicate needs <category>:<field>:<op>:<bound>: {line}"
        ));
    };
    Ok(PredicateRequest {
        category: (*category).to_string(),
        field: (*field).to_string(),
        op: parse_op(op)?,
        bound: parse_bound(bound),
        scale_version: rest.first().map(|s| (*s).to_string()),
    })
}

fn parse_op(op: &str) -> Result<PredicateOp, String> {
    match op {
        "ge" => Ok(PredicateOp::Ge),
        "le" => Ok(PredicateOp::Le),
        "gt" => Ok(PredicateOp::Gt),
        "lt" => Ok(PredicateOp::Lt),
        "eq" => Ok(PredicateOp::Eq),
        other => Err(format!("unknown predicate op: {other}")),
    }
}

/// A bound is an integer if it parses as one, else a (date/text) string.
fn parse_bound(bound: &str) -> serde_json::Value {
    match bound.parse::<i64>() {
        Ok(n) => serde_json::Value::from(n),
        Err(_) => serde_json::Value::from(bound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_no_predicates() {
        assert!(parse_predicates("").unwrap().is_empty());
        assert!(parse_predicates("  \n \n").unwrap().is_empty());
    }

    #[test]
    fn parses_a_full_line_with_scale() {
        let reqs = parse_predicates("education:degree_rank:ge:3:aion-trust/education/v1").unwrap();
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.category, "education");
        assert_eq!(r.field, "degree_rank");
        assert_eq!(r.op, PredicateOp::Ge);
        assert_eq!(r.bound, serde_json::json!(3)); // integer bound
        assert_eq!(r.scale_version.as_deref(), Some("aion-trust/education/v1"));
    }

    #[test]
    fn string_bound_when_not_an_integer() {
        let r = &parse_predicates("background_check:performed:ge:2025-06-21").unwrap()[0];
        assert_eq!(r.bound, serde_json::json!("2025-06-21"));
        assert!(r.scale_version.is_none());
    }

    #[test]
    fn each_op_maps_and_unknown_is_rejected() {
        for (s, op) in [
            ("ge", PredicateOp::Ge),
            ("le", PredicateOp::Le),
            ("gt", PredicateOp::Gt),
            ("lt", PredicateOp::Lt),
            ("eq", PredicateOp::Eq),
        ] {
            let r = &parse_predicates(&format!("c:f:{s}:1")).unwrap()[0];
            assert_eq!(r.op, op);
        }
        assert!(parse_predicates("c:f:zz:1").is_err());
    }

    #[test]
    fn malformed_line_is_rejected() {
        assert!(parse_predicates("too:few:parts").is_err());
    }

    #[test]
    fn form_pairs_keeps_repeated_keys_and_decodes() {
        let pairs = form_pairs("claim=a&claim=b&purpose=senior+eng&ttl=3600");
        assert_eq!(values(&pairs, "claim"), vec!["a", "b"]); // repeated keys survive
        assert_eq!(first(&pairs, "purpose"), Some("senior eng")); // + → space
        assert_eq!(first(&pairs, "ttl"), Some("3600"));
        assert_eq!(first(&pairs, "absent"), None);
    }

    #[test]
    fn form_pairs_percent_decodes_and_fails_soft() {
        let pairs = form_pairs("a=%41%42&b=role%3Ax&flag");
        assert_eq!(first(&pairs, "a"), Some("AB"));
        assert_eq!(first(&pairs, "b"), Some("role:x"));
        assert_eq!(first(&pairs, "flag"), Some("")); // no '=' → empty value
                                                     // a dangling/invalid percent escape passes through literally, not a panic
        assert_eq!(first(&form_pairs("x=50%"), "x"), Some("50%"));
        assert_eq!(first(&form_pairs("x=%zz"), "x"), Some("%zz"));
        // lowercase hex decodes (pins the a..=f arm and its arithmetic)
        assert_eq!(first(&form_pairs("x=%2f"), "x"), Some("/"));
        // a `%` with only one trailing char must NOT read past the end (pins the bounds guard)
        assert_eq!(first(&form_pairs("x=%4"), "x"), Some("%4"));
    }
}
