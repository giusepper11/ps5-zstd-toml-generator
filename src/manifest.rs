use std::collections::{BTreeMap, BTreeSet};

use crate::Entry;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Catalog {
    PlayGoNames,
    OdxPaths,
}

pub(crate) struct Paths<'a> {
    pub files: BTreeSet<&'a str>,
    names: BTreeMap<&'a str, Option<&'a str>>,
}

impl<'a> Paths<'a> {
    pub fn new(files: &'a [Entry]) -> Self {
        let mut names = BTreeMap::new();
        for file in files {
            let name = file.path.rsplit('/').next().unwrap_or(&file.path);
            names
                .entry(name)
                .and_modify(|existing| *existing = None)
                .or_insert(Some(file.path.as_str()));
        }
        Self {
            files: files.iter().map(|f| f.path.as_str()).collect(),
            names,
        }
    }

    pub fn lookup(&self, path: &str) -> Option<&'a str> {
        let path = path.trim();
        let normalized;
        let path = if path.contains('\\') {
            normalized = path.replace('\\', "/");
            normalized.as_str()
        } else {
            path
        };
        let path = path
            .strip_prefix("/app0/")
            .unwrap_or(path)
            .trim_start_matches('/');
        self.files.get(path).copied().or_else(|| {
            (!path.contains('/'))
                .then(|| self.names.get(path).copied().flatten())
                .flatten()
        })
    }

    pub fn exact_argument(&self, path: &str) -> Option<&'a str> {
        let relative = if path.starts_with('/') {
            path.strip_prefix("/app0/")?
        } else {
            path
        };
        self.files.get(relative).copied()
    }
}

pub(crate) fn has_catalogue_header(header: &[u8]) -> bool {
    if header.starts_with(b"DMGP") {
        return true;
    }
    let text = header.strip_prefix(b"\xef\xbb\xbf").unwrap_or(header);
    let text = text.trim_ascii_start();
    let root = if text.starts_with(b"<?xml") {
        let Some(end) = text.windows(2).position(|pair| pair == b"?>") else {
            return false;
        };
        text[end + 2..].trim_ascii_start()
    } else {
        text
    };
    root.strip_prefix(b"<ResourceList")
        .and_then(|rest| rest.first())
        .is_some_and(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
}

// roxmltree 0.20 checks duplicate attributes and namespace declarations
// quadratically. Bound the number of assignments in each tag before parsing.
fn bounded_xml_tags(mut bytes: &[u8]) -> Option<()> {
    const MAX_ATTRIBUTES: usize = 128;
    while let Some(start) = bytes.iter().position(|&b| b == b'<') {
        let markup = &bytes[start + 1..];
        let section = [
            (b"!--".as_slice(), b"-->".as_slice()),
            (b"![CDATA[", b"]]>"),
            (b"?", b"?>"),
        ]
        .into_iter()
        .find_map(|(prefix, end)| Some((markup.strip_prefix(prefix)?, end)));
        if let Some((body, end)) = section {
            let close = body.windows(end.len()).position(|part| part == end)?;
            bytes = &body[close + end.len()..];
            continue;
        }
        // DTDs are also disabled in roxmltree's default parsing options.
        if markup.starts_with(b"!") {
            return None;
        }
        let mut quote = None;
        let mut attributes = 0;
        let mut tag = markup.iter();
        loop {
            let byte = *tag.next()?;
            if let Some(delimiter) = quote {
                if byte == delimiter {
                    quote = None;
                }
                continue;
            }
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'>' => break,
                b'=' => {
                    attributes += 1;
                    if attributes > MAX_ATTRIBUTES {
                        return None;
                    }
                }
                _ => {}
            }
        }
        bytes = tag.as_slice();
    }
    Some(())
}

pub(crate) fn references<'a>(
    bytes: &[u8],
    paths: &Paths<'a>,
) -> Option<(Catalog, BTreeSet<&'a str>)> {
    if bytes.starts_with(b"DMGP") {
        let version = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
        let header_size = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
        if version == 0 || !(32..bytes.len()).contains(&header_size) {
            return None;
        }
        // These are literal names present in the binary manifest. Membership
        // here supplies catalogue evidence, without asserting a read API.
        let names = bytes[header_size..]
            .split(|&b| b == 0)
            .filter(|s| (4..=1024).contains(&s.len()))
            .filter_map(|s| std::str::from_utf8(s).ok())
            .filter_map(|name| paths.lookup(name))
            .collect();
        return Some((Catalog::PlayGoNames, names));
    }
    bounded_xml_tags(bytes)?;
    let xml = roxmltree::Document::parse(std::str::from_utf8(bytes).ok()?).ok()?;
    let mut out = BTreeSet::new();
    let mut found = false;
    for node in xml.descendants().filter(|n| n.has_tag_name("OdxPath")) {
        let Some(text) = node.text().map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        found = true;
        // Keep binary and text variants distinct. The .odxb is the binary
        // asset selected by an ODX path without an explicit extension.
        if text.ends_with(".odxb") {
            out.extend(paths.lookup(text));
        } else if !text.ends_with(".odx") {
            out.extend(paths.lookup(&format!("{text}.odxb")));
        }
    }
    found.then_some((Catalog::OdxPaths, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_only_unambiguous_catalogue_members_after_the_header() {
        let files = [
            "folder/one.sps",
            "folder/two.sps",
            "other/two.sps",
            "folder/dummy",
        ]
        .map(|path| Entry {
            path: path.to_owned(),
            size: 128,
        });
        let paths = Paths::new(&files);
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"DMGP");
        bytes[4..8].copy_from_slice(&5u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&64u32.to_le_bytes());
        bytes[32..37].copy_from_slice(b"dummy");
        bytes.extend_from_slice(b"one.sps\0two.sps\0other/two.sps\0missing.sps\0");
        assert_eq!(
            references(&bytes, &paths),
            Some((
                Catalog::PlayGoNames,
                BTreeSet::from(["folder/one.sps", "other/two.sps"])
            ))
        );
        bytes[8..12].copy_from_slice(&1024u32.to_le_bytes());
        assert_eq!(references(&bytes, &paths), None);
    }

    #[test]
    fn discovers_odx_catalogue_from_its_xml_root() {
        let xml = b"\xef\xbb\xbf<?xml version='1.0'?>\n<ResourceList><OdxPath>data/item</OdxPath></ResourceList>";
        let files = [Entry {
            path: "data/item.odxb".to_owned(),
            size: 128,
        }];
        let paths = Paths::new(&files);
        assert!(has_catalogue_header(&xml[..64]));
        assert!(!has_catalogue_header(b"<ResourceListOther>"));
        assert_eq!(
            references(xml, &paths),
            Some((Catalog::OdxPaths, BTreeSet::from(["data/item.odxb"])))
        );
    }

    #[test]
    fn bounds_xml_attributes_and_respects_quoted_tag_delimiters() {
        use std::fmt::Write;

        let mut xml = format!("<ResourceList first='> {}'", "=".repeat(256));
        for i in 0..128 {
            write!(xml, " a{i}='x'").unwrap();
        }
        xml.push_str("/>");
        assert!(bounded_xml_tags(xml.as_bytes()).is_none());

        let xml = format!(
            "<?xml version='1.0'?><!-- <ignore {0} -->\n<ResourceList attr='> {0}'><![CDATA[<ignore {0}]]></ResourceList>",
            "=".repeat(256)
        );
        assert!(bounded_xml_tags(xml.as_bytes()).is_some());
    }
}
