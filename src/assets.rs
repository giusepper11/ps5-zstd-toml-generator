#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AssetKind {
    Payload(PayloadKind),
    FrostbiteCas,
    Control,
    Media,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PayloadKind {
    Texture,
    Mesh,
    SmbsMesh,
    Archive,
    Animation,
    Object,
    AudioBank,
}

pub(crate) fn frostbite_layout(header: &[u8], size: u64) -> bool {
    size >= 0x22c && header.starts_with(b"\x00\xd1\xce\x01\x00\x00\x00\x00")
}

// CAS files can start with different kinds of blocks. Identify this layout
// from its companion TOC and archive path instead of assuming one CAS magic.
pub(crate) fn frostbite_cas_path(lower: &str) -> bool {
    let Some(relative) = lower
        .strip_prefix("data/ps5/superbundlelayout/")
        .or_else(|| lower.strip_prefix("patch/ps5/superbundlelayout/"))
    else {
        return false;
    };
    relative
        .rsplit_once('/')
        .and_then(|(_, name)| name.strip_prefix("cas_"))
        .and_then(|name| name.strip_suffix(".cas"))
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// Format evidence from a file header and its inventory size. Compatibility
/// with the runtime's intercepted read APIs is a separate policy decision.
pub(crate) fn classify(path: &str, size: u64, header: &[u8]) -> AssetKind {
    let path = path.to_ascii_lowercase();
    let name = path.rsplit('/').next().unwrap_or(&path);
    let ext = name.rsplit_once('.').map_or("", |(_, ext)| ext);
    if size == 0
        || !path.contains('/')
        || path.starts_with("sce_sys/")
        || path.starts_with("sce_module/")
        || path.starts_with("fakelib")
        || name.starts_with("pgc_") && name.ends_with("_dummy_file")
        || matches!(
            ext,
            "elf"
                | "self"
                | "prx"
                | "sprx"
                | "esbak"
                | "sfo"
                | "pgm"
                | "xml"
                | "json"
                | "toml"
                | "ini"
                | "cfg"
                | "log"
                | "bus"
                | "dml"
                | "gmx"
                | "texmeshman"
                | "packman"
        )
        || frostbite_layout(header, size)
        || control_magic(header)
    {
        return AssetKind::Control;
    }

    if media_magic(header)
        || media_extension(ext)
        || header.starts_with(b"SNDZ") && le32(header, 8).is_some_and(|companion| companion != 0)
    {
        return AssetKind::Media;
    }

    match payload(header, size) {
        Some(kind) => AssetKind::Payload(kind),
        None if ext == "szd" || header.starts_with(b"SNDZ") => AssetKind::Media,
        None => AssetKind::Unknown,
    }
}

fn media_extension(ext: &str) -> bool {
    matches!(
        ext,
        "mp4"
            | "m4v"
            | "mov"
            | "bsf"
            | "h264"
            | "bik"
            | "bk2"
            | "usm"
            | "webm"
            | "at9"
            | "xvag"
            | "wav"
            | "wem"
            | "mid"
            | "midi"
            | "ogg"
            | "opus"
            | "flac"
            | "mp3"
            | "aac"
            | "szd1"
            | "szd2"
    )
}

pub(crate) fn larc_index_len(header: &[u8], file_size: u64) -> Option<usize> {
    if !header.starts_with(b"cral") || le32(header, 4)? != 0x0501 {
        return None;
    }
    let end = le32(header, 24)?;
    (end >= 36 && u64::from(end) < file_size).then_some(end as usize)
}

fn control_magic(header: &[u8]) -> bool {
    if matches!(
        header.get(..4),
        Some(
            b"\x7fELF"
                | b"\x4f\x15\x3d\x1d"
                | b"\x00PSF"
                | b"DMGP"
                | b"FNMS"
                | b"DMLF"
                | b"GMXF"
                | b"GFCB"
                | b"SXDF"
        )
    ) {
        return true;
    }
    let text = header.strip_prefix(b"\xef\xbb\xbf").unwrap_or(header);
    match text.iter().find(|b| !b.is_ascii_whitespace()) {
        Some(b'<') => text.contains(&b'>'),
        Some(b'{') => text.iter().copied().filter(|b| *b == b'"').take(2).count() == 2,
        _ => false,
    }
}

fn media_magic(header: &[u8]) -> bool {
    matches!(
        header.get(..4),
        Some(b"XVAG" | b"MThd" | b"OggS" | b"fLaC" | b"@SFV" | b"\x1a\x45\xdf\xa3")
    ) || header.starts_with(b"BIK")
        || header.starts_with(b"KB2")
        || header.get(4..8) == Some(b"ftyp")
        || header.starts_with(b"RIFF") && header.get(8..12) == Some(b"WAVE")
}

fn payload(header: &[u8], size: u64) -> Option<PayloadKind> {
    use PayloadKind::*;

    let version = le32(header, 4).unwrap_or(0);
    let data_offset = le32(header, 24).unwrap_or(0);
    let asset = match header.get(..4)? {
        b"GNF " if gnf(header, size, version) => Texture,
        b"DDS " if version == 124 && size > 128 && le32(header, 76) == Some(32) => Texture,
        b"\xabKTX" if ktx(header, size) => Texture,
        // These containers have an identifier followed by an offset into their payload.
        b"XTBS" if (1..=0xffff).contains(&version) && payload_offset(data_offset, size) => Texture,
        // A mesh may have only a descriptor, with its payload starting at EOF.
        b"SMBS" if version >> 16 != 0 && (32..=size).contains(&u64::from(data_offset)) => SmbsMesh,
        b"cral" if (1..=0xffff).contains(&version) && payload_offset(data_offset, size) => Archive,
        // KCAP's version and section count share the same 32-bit word.
        b"KCAP"
            if size > 64
                && (1..=0xff).contains(&(version & 0xffff))
                && (1..=256).contains(&(version >> 16))
                && (1..=8).contains(&data_offset)
                && le32(header, 28) == Some(0) =>
        {
            Archive
        }
        b"JXMD"
            if u64::from(version) < size
                && le32(header, 8) == Some(0)
                && le32(header, 12).is_some_and(|offset| (32..version).contains(&offset)) =>
        {
            Mesh
        }
        b"80AE"
            if f32::from_bits(version).is_finite()
                && f32::from_bits(version) >= 0.0
                && le32(header, 8)
                    .is_some_and(|bits| (1.0..=480.0).contains(&f32::from_bits(bits)))
                && le32(header, 12).is_some_and(|word| payload_offset(word & 0xffff, size)) =>
        {
            Animation
        }
        b"60SE"
            if u64::from(version) == size
                && le32(header, 8).is_some_and(|offset| payload_offset(offset, size)) =>
        {
            Animation
        }
        b"SNDZ"
            if size >= 32
                && u64::from(version) == size
                && le32(header, 8) == Some(0)
                && le32(header, 12) == Some(0x00010001) =>
        {
            AudioBank
        }
        _ if version == 1
            && size % 16 == 0
            && le32(header, 0).map(u64::from) == Some(size)
            && le32(header, 8) == Some(0x4aa5690b)
            && le32(header, 16).is_some_and(|offset| payload_offset(offset, size)) =>
        {
            Object
        }
        _ => return None,
    };
    Some(asset)
}

fn gnf(header: &[u8], size: u64, contents_size: u32) -> bool {
    if header.get(9).is_none_or(|count| *count == 0) || contents_size < 32 {
        return false;
    }
    let contents_end = u64::from(contents_size) + 8;
    match header.get(8) {
        Some(4) => contents_end < size && le32(header, 12).map(u64::from) == Some(size),
        Some(5) => {
            le64(header, 16).is_some_and(|offset| (contents_end..size).contains(&offset))
                && le64(header, 24) == Some(size)
        }
        _ => false,
    }
}

fn ktx(header: &[u8], size: u64) -> bool {
    match header.get(..12) {
        Some(b"\xabKTX 11\xbb\r\n\x1a\n") => {
            size > 64 && matches!(le32(header, 12), Some(0x04030201 | 0x01020304))
        }
        Some(b"\xabKTX 20\xbb\r\n\x1a\n") => {
            size > 80 && le32(header, 20).is_some_and(|width| width != 0)
        }
        _ => false,
    }
}

fn payload_offset(offset: u32, size: u64) -> bool {
    offset >= 32 && u64::from(offset) < size
}

fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ArchiveSource {
        entry: Entry,
        bytes: Vec<u8>,
        short: bool,
        short_member: bool,
        error_at: Option<u64>,
    }
    impl SourceTree for ArchiveSource {
        fn files(&self) -> &[Entry] {
            std::slice::from_ref(&self.entry)
        }
        fn read_range(&mut self, _: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
            if self.error_at == Some(offset) {
                return Err(io::Error::other("simulated source failure"));
            }
            let start = offset as usize;
            let stop = start.checked_add(len).unwrap();
            let data = self.bytes.get(start..stop).unwrap_or(&[]);
            Ok(
                if (self.short || self.short_member && offset != 0) && !data.is_empty() {
                    &data[..data.len() - 1]
                } else {
                    data
                }
                .to_vec(),
            )
        }
    }

    fn archive(name: &str, payload: &[u8]) -> ArchiveSource {
        let mut bytes = vec![0; 32];
        bytes[..4].copy_from_slice(b"cral");
        bytes[4..8].copy_from_slice(&0x501u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0x12345678u32.to_le_bytes()); // unknown field
        bytes.extend_from_slice(&0xaabbccddu32.to_le_bytes()); // unknown footer
        let end = bytes.len() as u32;
        bytes[24..28].copy_from_slice(&end.to_le_bytes());
        bytes.extend_from_slice(payload);
        ArchiveSource {
            entry: Entry {
                path: "test.larc".into(),
                size: bytes.len() as u64,
            },
            bytes,
            short: false,
            short_member: false,
            error_at: None,
        }
    }

    fn inspect(source: &mut ArchiveSource) -> LarcInspection {
        let entry = source.entry.clone();
        let head = source.bytes[..source.bytes.len().min(32)].to_vec();
        inspect_larc(source, &entry, &head).unwrap()
    }

    #[test]
    fn larc_checks_member_prefix_even_with_bin_name() {
        let mut media = archive("voice.bin", b"XVAG1234");
        let found = inspect(&mut media);
        assert_eq!(found.status, LarcStatus::Media);
        assert_eq!(found.inspected, 1);
        assert!(found.signature_media);
        assert!(!found.named_media);
        let mut ordinary = archive("voice.bin", b"ordinary");
        assert_eq!(inspect(&mut ordinary).status, LarcStatus::NoMediaInPrefixes);
        let mut named = archive("voice.XVAG", b"ordinary");
        let found = inspect(&mut named);
        assert_eq!(found.status, LarcStatus::Media);
        assert!(found.named_media);
        assert!(!found.signature_media);
        assert!(found.prefixes_complete);
        let mut named_short = archive("voice.XVAG", b"ordinary");
        named_short.short_member = true;
        let found = inspect(&mut named_short);
        assert_eq!(found.status, LarcStatus::Unverified);
        assert!(found.named_media);
        assert!(!found.prefixes_complete);
    }

    #[test]
    fn larc_rejects_truncation_bounds_unknown_version_and_limits() {
        let mut short = archive("a.bin", b"ordinary");
        short.short = true;
        assert_eq!(inspect(&mut short).status, LarcStatus::Unverified);
        let mut bounds = archive("a.bin", b"ordinary");
        let size_pos = 32 + 4 + "a.bin".len() + 4;
        bounds.bytes[size_pos..size_pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(inspect(&mut bounds).status, LarcStatus::Unverified);
        let mut version = archive("a.bin", b"ordinary");
        version.bytes[4..8].copy_from_slice(&0x502u32.to_le_bytes());
        assert_eq!(inspect(&mut version).status, LarcStatus::Unverified);
        let mut budget = archive("a.bin", b"ordinary");
        budget.bytes[28..32].copy_from_slice(&((LARC_MAX_MEMBERS + 1) as u32).to_le_bytes());
        assert_eq!(inspect(&mut budget).status, LarcStatus::Unverified);
        let mut truncated = archive("a.bin", b"ordinary");
        truncated.bytes[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(inspect(&mut truncated).status, LarcStatus::Unverified);
    }

    #[test]
    fn larc_propagates_source_errors_for_index_and_member() {
        let mut index = archive("a.bin", b"ordinary");
        index.error_at = Some(0);
        let entry = index.entry.clone();
        let head = index.bytes[..32].to_vec();
        assert!(inspect_larc(&mut index, &entry, &head).is_err());

        let mut member = archive("voice.XVAG", b"ordinary");
        let end = le32(&member.bytes, 24).unwrap() as u64;
        member.error_at = Some(end);
        let entry = member.entry.clone();
        let head = member.bytes[..32].to_vec();
        assert!(inspect_larc(&mut member, &entry, &head).is_err());
    }

    fn header(magic: &[u8; 4], words: &[(usize, u32)]) -> [u8; 80] {
        let mut bytes = [0; 80];
        bytes[..4].copy_from_slice(magic);
        for &(offset, word) in words {
            bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn classifies_payloads_from_structure_without_names() {
        for (magic, words, expected) in [
            (
                b"XTBS",
                &[(4, 0x1e01), (24, 0x91)][..],
                PayloadKind::Texture,
            ),
            (b"SMBS", &[(4, 0x20001), (24, 0x175)], PayloadKind::SmbsMesh),
            (b"cral", &[(4, 0x501), (24, 0x4ec)], PayloadKind::Archive),
            (b"KCAP", &[(4, 0xa0029), (24, 5)], PayloadKind::Archive),
            (b"JXMD", &[(4, 0x110), (12, 0xe0)], PayloadKind::Mesh),
            (
                b"GNF ",
                &[(4, 0xff8), (8, 0x104), (12, 16384)],
                PayloadKind::Texture,
            ),
            (
                b"GNF ",
                &[(4, 0xff8), (8, 0x105), (16, 0x1000), (24, 16384)],
                PayloadKind::Texture,
            ),
        ] {
            let bytes = header(magic, words);
            assert_eq!(
                classify("files/no-extension", 16384, &bytes),
                AssetKind::Payload(expected)
            );
        }
    }

    #[test]
    fn verifies_size_and_protects_control_and_media() {
        let bytes = header(b"GNF ", &[(4, 0xff8), (8, 0x104), (12, 16384)]);
        assert_eq!(
            classify("files/asset.gnfp", 8192, &bytes),
            AssetKind::Unknown
        );
        assert_eq!(
            classify("files/asset.gnfp", 16384, &bytes[..4]),
            AssetKind::Unknown
        );
        assert_eq!(classify("sce_sys/asset", 16384, &bytes), AssetKind::Control);
        assert_eq!(
            classify("files/asset.xml", 16384, &bytes),
            AssetKind::Control
        );
        assert_eq!(
            classify(
                "files/asset.unknown",
                80,
                b"\xef\xbb\xbf <?xml version='1.0'?>"
            ),
            AssetKind::Control
        );
        assert_eq!(classify("files/asset.jxm", 8192, b"XVAG"), AssetKind::Media);
        assert_eq!(classify("files/asset.szd", 8192, b"SNDZ"), AssetKind::Media);
        let sound = header(b"SNDZ", &[(4, 8192), (12, 0x00010001)]);
        assert_eq!(
            classify("files/asset.szd", 8192, &sound),
            AssetKind::Payload(PayloadKind::AudioBank)
        );
        assert_eq!(classify("files/asset.szd2", 8192, &sound), AssetKind::Media);
        let split = header(b"SNDZ", &[(4, 8192), (8, 32768), (12, 0x00010001)]);
        assert_eq!(classify("files/renamed", 8192, &split), AssetKind::Media);
        let mesh_descriptor = header(b"SMBS", &[(4, 0x20001), (24, 57)]);
        assert_eq!(
            classify("files/mesh", 57, &mesh_descriptor[..57]),
            AssetKind::Payload(PayloadKind::SmbsMesh)
        );
        assert_eq!(
            classify("files/mesh", 56, &mesh_descriptor[..56]),
            AssetKind::Unknown
        );
    }
}
use std::io;

use crate::{Entry, SourceTree};

const LARC_MAX_INDEX: usize = 1024 * 1024;
const LARC_MAX_MEMBERS: usize = 4096;
const LARC_PREFIX_BYTES: usize = 64;

/// Prefix inspection does not establish that a member is not compressed,
/// nested, or media encoded in a format unknown to this analyzer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LarcStatus {
    Media,
    NoMediaInPrefixes,
    Unverified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LarcInspection {
    pub status: LarcStatus,
    pub members: usize,
    pub inspected: usize,
    pub named_media: bool,
    pub signature_media: bool,
    pub prefixes_complete: bool,
}

/// Inspect a bounded index and each member's bounded prefix. The index's
/// four-byte per-member field and footer have unknown semantics: their mere
/// presence is validated, but no interpretation of their values is assumed.
/// A negative result is prefix evidence only, never proof of safe I/O.
pub(crate) fn inspect_larc(
    tree: &mut (impl SourceTree + ?Sized),
    entry: &Entry,
    head: &[u8],
) -> io::Result<LarcInspection> {
    let mut result = LarcInspection {
        status: LarcStatus::Unverified,
        members: 0,
        inspected: 0,
        named_media: false,
        signature_media: false,
        prefixes_complete: false,
    };
    let Some(end) = larc_index_len(head, entry.size).filter(|&n| n <= LARC_MAX_INDEX) else {
        return Ok(result);
    };
    let index = if head.len() >= end {
        head[..end].to_vec()
    } else {
        let data = tree.read_range(&entry.path, 0, end)?;
        if data.len() != end {
            return Ok(result);
        }
        data
    };
    let Some(count) = le32(&index, 28).map(|v| v as usize) else {
        return Ok(result);
    };
    result.members = count;
    if count > LARC_MAX_MEMBERS {
        return Ok(result);
    }
    let Some(table) = index.get(32..end - 4) else {
        return Ok(result);
    };
    let mut offset = 0usize;
    let mut members = Vec::with_capacity(count);
    let mut named_media = false;
    for _ in 0..count {
        let Some(length) = le32(table, offset).map(|v| v as usize) else {
            return Ok(result);
        };
        let Some(start) = offset.checked_add(4) else {
            return Ok(result);
        };
        let Some(stop) = start.checked_add(length) else {
            return Ok(result);
        };
        let Some(name) = table
            .get(start..stop)
            .and_then(|v| std::str::from_utf8(v).ok())
        else {
            return Ok(result);
        };
        if name.is_empty() || name.chars().any(char::is_control) {
            return Ok(result);
        }
        let Some(relative) = le32(table, stop) else {
            return Ok(result);
        };
        let Some(size_pos) = stop.checked_add(4) else {
            return Ok(result);
        };
        let Some(size) = le32(table, size_pos) else {
            return Ok(result);
        };
        let Some(next) = stop.checked_add(12) else {
            return Ok(result);
        };
        if next > table.len() {
            return Ok(result);
        }
        let Some(absolute) = (end as u64).checked_add(u64::from(relative)) else {
            return Ok(result);
        };
        if absolute
            .checked_add(u64::from(size))
            .is_none_or(|end| end > entry.size)
        {
            return Ok(result);
        }
        named_media |= name
            .rsplit_once('.')
            .is_some_and(|(_, ext)| media_extension(&ext.to_ascii_lowercase()));
        members.push((absolute, size));
        offset = next;
    }
    if offset != table.len() {
        return Ok(result);
    }
    result.named_media = named_media;
    if named_media {
        result.status = LarcStatus::Media;
    }
    for (absolute, size) in members {
        let len = (size as usize).min(LARC_PREFIX_BYTES);
        let data = tree.read_range(&entry.path, absolute, len)?;
        if data.len() != len {
            result.status = LarcStatus::Unverified;
            return Ok(result);
        }
        result.inspected += 1;
        if media_magic(&data) {
            result.signature_media = true;
            result.prefixes_complete = result.inspected == result.members;
            result.status = LarcStatus::Media;
            return Ok(result);
        }
    }
    result.prefixes_complete = true;
    if !named_media {
        result.status = LarcStatus::NoMediaInPrefixes;
    }
    Ok(result)
}
