//! Parse and serialize KEY=VALUE pairs stored in a Bitwarden note's notes field.

use std::collections::HashMap;

/// Return `true` if `key` is a valid POSIX environment-variable name:
/// `[A-Za-z_][A-Za-z0-9_]*` with no null bytes.
fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() || key.contains('\0') {
        return false;
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse note content into a map of env-var key → value.
/// - Splits on the **first** `=` only (values may contain `=`).
/// - Trims whitespace from both the key and the value.
/// - Skips blank lines and lines starting with `#`.
/// - Skips and warns about lines whose key is not a valid POSIX env-var name
///   (catches empty keys, null bytes, and names with illegal characters).
pub fn parse(notes: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in notes.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if is_valid_env_key(k) {
                map.insert(k.to_string(), v.to_string());
            } else {
                eprintln!("WARNING: skipping line with invalid env-var key: {line:?}");
            }
        }
    }
    map
}

/// Serialize a map into sorted `KEY=VALUE` lines.
pub fn serialize(pairs: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = pairs.keys().collect();
    keys.sort();
    keys.iter()
        .map(|k| format!("{}={}", k, pairs[*k]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Upsert a single key in existing note content, preserving other lines.
pub fn update(existing: &str, key: &str, value: &str) -> String {
    let mut pairs = parse(existing);
    pairs.insert(key.to_string(), value.to_string());
    serialize(&pairs)
}

/// Remove a single key from existing note content, preserving other lines.
/// Returns `None` if the key was not present.
pub fn remove(existing: &str, key: &str) -> Option<String> {
    let mut pairs = parse(existing);
    if pairs.remove(key).is_none() {
        return None;
    }
    Some(serialize(&pairs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let m = parse("A=1\nB=hello=world\n");
        assert_eq!(m["A"], "1");
        assert_eq!(m["B"], "hello=world");
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let m = parse("# comment\n\nA=1\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m["A"], "1");
    }

    // C1: empty key must be skipped
    #[test]
    fn parse_skips_empty_key() {
        let m = parse("=value\nA=1\n");
        assert!(!m.contains_key(""), "empty key must be rejected");
        assert_eq!(m["A"], "1");
    }

    // C2: null byte in key must be skipped
    #[test]
    fn parse_skips_null_byte_in_key() {
        let m = parse("KEY\x00INJECTED=value\nA=1\n");
        assert_eq!(m.len(), 1, "key with null byte must be rejected");
        assert_eq!(m["A"], "1");
    }

    // H2: non-POSIX key names must be rejected
    #[test]
    fn parse_rejects_invalid_key_names() {
        let m = parse("1STARTS_WITH_DIGIT=x\nKEY WITH SPACE=y\nVALID=z\n");
        assert!(!m.contains_key("1STARTS_WITH_DIGIT"));
        assert!(!m.contains_key("KEY WITH SPACE"));
        assert_eq!(m["VALID"], "z");
    }

    // H4: whitespace around = is stripped
    #[test]
    fn parse_trims_key_and_value() {
        let m = parse("KEY  =  value  \n");
        assert!(
            !m.contains_key("KEY  "),
            "trailing spaces in key must be trimmed"
        );
        assert_eq!(m["KEY"], "value");
    }

    #[test]
    fn roundtrip() {
        let original = "A=1\nB=2\n";
        let m = parse(original);
        let s = serialize(&m);
        assert_eq!(s, "A=1\nB=2");
    }

    #[test]
    fn update_existing() {
        let s = update("A=1\nB=2", "A", "99");
        let m = parse(&s);
        assert_eq!(m["A"], "99");
        assert_eq!(m["B"], "2");
    }

    #[test]
    fn remove_key() {
        let s = remove("A=1\nB=2", "A").unwrap();
        let m = parse(&s);
        assert!(!m.contains_key("A"));
        assert_eq!(m["B"], "2");
    }

    #[test]
    fn remove_missing_returns_none() {
        assert!(remove("A=1", "MISSING").is_none());
    }
}
