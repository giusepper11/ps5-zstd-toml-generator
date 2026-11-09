//! Verification of the restricted profile syntax emitted by this crate, against Forge 0.5.4.
//! This is deliberately not a parser for arbitrary user-supplied Forge profiles.
use crate::{Entry, Profile};

/// Optional integration with the effective Forge selector. Parse the profile
/// once in the host, then capture that parsed object in `select`. Every file
/// must agree with the exact intended set before the host starts packing.
pub fn verify_with_selector(
    files: &[Entry],
    selected: &BTreeSet<String>,
    mut select: impl FnMut(&Entry) -> io::Result<bool>,
) -> io::Result<()> {
    let mut seen = BTreeSet::new();
    for entry in files {
        if !seen.insert(entry.path.as_str()) {
            return Err(invalid("duplicate inventory path"));
        }
        if select(entry)? != selected.contains(&entry.path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("effective Forge selector differs for {}", entry.path),
            ));
        }
    }
    if selected.iter().any(|p| !seen.contains(p.as_str())) {
        return Err(invalid("selected path absent from inventory"));
    }
    Ok(())
}
use std::collections::{BTreeMap, BTreeSet};
use std::io;

fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}

#[derive(Debug)]
enum Token {
    Lit(char),
    Star,
}
fn pattern(s: &str) -> io::Result<Vec<Token>> {
    if s.starts_with('/') || s.contains('\\') || s.chars().any(char::is_control) {
        return Err(invalid("invalid generated pattern"));
    }
    let mut chars = s.chars();
    let mut out = Vec::new();
    while let Some(c) = chars.next() {
        match c {
            '*' => out.push(Token::Star),
            '?' => return Err(invalid("unsupported wildcard")),
            '[' => {
                let x = chars.next().ok_or_else(|| invalid("invalid bracket"))?;
                if x == '!' || chars.next() != Some(']') {
                    return Err(invalid("unsupported bracket"));
                }
                out.push(Token::Lit(x));
            }
            c => out.push(Token::Lit(c)),
        }
    }
    Ok(out)
}
fn matches(t: &[Token], path: &str) -> bool {
    let c: Vec<char> = path.chars().collect();
    let (mut p, mut i) = (0, 0);
    let mut star = None;
    while i < c.len() {
        match t.get(p) {
            Some(Token::Star) => {
                star = Some((p, i));
                p += 1;
            }
            Some(Token::Lit(x)) if *x == c[i] => {
                p += 1;
                i += 1;
            }
            _ => {
                if let Some((sp, si)) = star {
                    star = Some((sp, si + 1));
                    p = sp + 1;
                    i = si + 1;
                } else {
                    return false;
                }
            }
        }
    }
    t[p..].iter().all(|x| matches!(x, Token::Star))
}
fn quoted(s: &str) -> io::Result<String> {
    let s = s.strip_suffix(',').unwrap_or(s).trim_end();
    let s = s
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .ok_or_else(|| invalid("expected TOML string"))?;
    let mut c = s.chars();
    let mut out = String::new();
    while let Some(x) = c.next() {
        if x != '\\' {
            if x == '"' || x.is_control() {
                return Err(invalid("unescaped quote or control in TOML"));
            }
            out.push(x);
            continue;
        }
        match c.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('u') => {
                let hex: String = c.by_ref().take(4).collect();
                if hex.len() != 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(invalid("bad escape"));
                }
                let n = u32::from_str_radix(&hex, 16).map_err(|_| invalid("bad escape"))?;
                out.push(char::from_u32(n).ok_or_else(|| invalid("bad escape"))?);
            }
            _ => return Err(invalid("unsupported TOML escape")),
        }
    }
    Ok(out)
}
fn protected(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    let first = l.split('/').next().unwrap_or("");
    let file = l.rsplit('/').next().unwrap_or("");
    file == "eboot.bin"
        || [".elf", ".self", ".prx", ".sprx"]
            .iter()
            .any(|x| l.ends_with(x))
        || (l.contains('/')
            && (first == "sce_sys" || first == "sce_module" || first.starts_with("fakelib")))
        || [
            "ampr_assets.index",
            "ampr_assets.index.crc",
            "ampr_assets.index.runtime",
            "ampr_emu.index",
            "ampr_commands.bin",
            "ampr_emu.log",
            "apr_emu.log",
            "ampr_zstd.index",
        ]
        .contains(&l.as_str())
        || (l.starts_with("ampr_zstd-")
            && l.ends_with(".pak")
            && l[10..l.len() - 4].len() == 3
            && l[10..l.len() - 4].bytes().all(|c| c.is_ascii_digit()))
}
/// Checks selection and Forge preflight constraints for the exact generated syntax.
pub fn verify_generated(
    profile: &Profile,
    files: &[Entry],
    selected: &BTreeSet<String>,
) -> io::Result<()> {
    if profile.toml.len() > 1_048_576 {
        return Err(invalid("TOML too large"));
    }
    let lines: Vec<&str> = profile
        .toml
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    if lines.len() < 2 || lines[0] != "[pack]" || lines[1] != "default_action = \"loose\"" {
        return Err(invalid("unsupported profile"));
    }
    let mut pats = Vec::new();
    let mut used = BTreeSet::new();
    let mut external = false;
    if lines.len() > 2 {
        if lines.len() < 6
            || lines[2] != "[[rule]]"
            || lines[3] != "action = \"compress\""
            || lines.last() != Some(&"]")
        {
            return Err(invalid("unsupported profile rule"));
        }
        external = match lines[4] {
            "include = [" => false,
            "include_from = [" => true,
            _ => return Err(invalid("unsupported include")),
        };
        let entries = &lines[5..lines.len() - 1];
        for (index, line) in entries.iter().enumerate() {
            if index + 1 < entries.len() && !line.ends_with(',') {
                return Err(invalid("expected comma between array entries"));
            }
            let v = quoted(line)?;
            if external {
                if v.is_empty()
                    || v.contains(['/', '\\', ':'])
                    || v == "."
                    || v == ".."
                    || !used.insert(v.clone())
                {
                    return Err(invalid("unsupported list path"));
                }
                let data = profile
                    .lists
                    .get(&v)
                    .ok_or_else(|| invalid("missing list"))?;
                if data.len() > 1_048_576 {
                    return Err(invalid("list too large"));
                }
                if data.chars().any(|c| {
                    matches!(
                        c,
                        '\r' | '\x0b' | '\x0c' | '\x1c'
                            ..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
                    )
                }) {
                    return Err(invalid("unsupported list line separator"));
                }
                for p in data.lines() {
                    let p = p.trim();
                    if !p.is_empty() && !p.starts_with('#') {
                        pats.push(p.to_owned());
                    }
                }
            } else {
                pats.push(v)
            }
        }
        if pats.is_empty() {
            return Err(invalid("empty include"));
        }
    }
    if used.len() != profile.lists.len() {
        return Err(invalid("unreferenced lists"));
    }
    if external
        && (profile.lists.values().map(String::len).sum::<usize>() > 16 * 1_048_576
            || pats.len() > 200_000)
    {
        return Err(invalid("lists too large"));
    }
    let mut exact = BTreeSet::new();
    let mut globs = Vec::new();
    for p in pats {
        let t = pattern(&p)?;
        if t.iter().any(|x| matches!(x, Token::Star)) {
            globs.push(t)
        } else {
            exact.insert(
                t.iter()
                    .map(|x| match x {
                        Token::Lit(c) => *c,
                        _ => unreachable!(),
                    })
                    .collect::<String>(),
            );
        }
    }
    if external && globs.len() > 10_000 {
        return Err(invalid("too many globs"));
    }
    let mut seen = BTreeMap::new();
    for f in files {
        if seen.insert(&f.path, f.size).is_some() {
            return Err(invalid("duplicate inventory path"));
        }
        let hit = f.size > 0
            && !protected(&f.path)
            && (exact.contains(&f.path) || globs.iter().any(|t| matches(t, &f.path)));
        if hit != selected.contains(&f.path) {
            return Err(invalid(&format!("selection mismatch: {}", f.path)));
        }
    }
    if selected.iter().any(|p| !seen.contains_key(p)) {
        return Err(invalid("selection outside inventory"));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn effective_selector_must_agree_for_every_path() {
        let files = vec![
            Entry {
                path: "data/a.bin".into(),
                size: 10,
            },
            Entry {
                path: "data/sub/b.bin".into(),
                size: 20,
            },
        ];
        let selected = BTreeSet::from(["data/a.bin".to_owned()]);
        verify_with_selector(&files, &selected, |e| Ok(e.path == "data/a.bin")).unwrap();
        assert!(verify_with_selector(&files, &selected, |_| Ok(true)).is_err());
        let mut missing = selected.clone();
        missing.insert("absent.bin".into());
        assert!(verify_with_selector(&files, &missing, |e| Ok(e.path == "data/a.bin")).is_err());
        assert!(verify_with_selector(&files, &selected, |_| Err(invalid("host error"))).is_err());
    }

    #[test]
    fn unsupported_rules_fail_closed_in_generated_subset() {
        for rule in ["min_size = 2048", "exclude = [\"x\"]", "action = \"loose\""] {
            let profile = Profile { toml: format!("[pack]\ndefault_action = \"loose\"\n[[rule]]\naction = \"compress\"\n{rule}\ninclude = [\n\"data/*\",\n]\n"), lists: BTreeMap::new() };
            assert!(verify_generated(&profile, &[], &BTreeSet::new()).is_err());
        }
    }
    #[test]
    fn generated_glob_and_literal() {
        assert!(matches(&pattern("data/*.x").unwrap(), "data/sub/a.x"));
        assert!(matches(&pattern("data/a[[]0].x").unwrap(), "data/a[0].x"));
        assert!(pattern("data/[ab].x").is_err());
        assert!(matches(&pattern("[#]file[ ]").unwrap(), "#file "));
        assert!(matches(
            &pattern("data/[*][?][[]x].bin").unwrap(),
            "data/*?[x].bin"
        ));
        assert!(!matches(&pattern("DATA/*.x").unwrap(), "data/sub/a.x"));
    }

    #[test]
    fn rejects_malformed_generated_arrays_and_nonliteral_brackets() {
        for value in [
            "\"data/a\"\n\"data/b\",",
            "\"data/a\"b\",",
            "\"data/[!].bin\",",
        ] {
            let profile = Profile {
                toml: format!("[pack]\ndefault_action = \"loose\"\n[[rule]]\naction = \"compress\"\ninclude = [\n{value}\n]\n"),
                lists: BTreeMap::new(),
            };
            assert!(verify_generated(&profile, &[], &BTreeSet::new()).is_err());
        }
    }
}
