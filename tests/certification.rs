use std::collections::{BTreeMap, BTreeSet};
use std::io;

use ps5_pack_analyzer::{
    analyze,
    audit::AuditedSource,
    certificate::{self, Certificate},
    Entry, Options, Profile, SourceTree,
};

#[derive(Clone)]
struct MemoryDump {
    files: Vec<Entry>,
    data: BTreeMap<String, Vec<u8>>,
}

impl MemoryDump {
    fn new(data: BTreeMap<String, Vec<u8>>) -> Self {
        let files = data
            .iter()
            .map(|(path, bytes)| Entry {
                path: path.clone(),
                size: bytes.len() as u64,
            })
            .collect();
        Self { files, data }
    }
}

impl SourceTree for MemoryDump {
    fn files(&self) -> &[Entry] {
        &self.files
    }
    fn read_range(&mut self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let data = self
            .data
            .get(path)
            .ok_or_else(|| io::Error::other("missing file"))?;
        let start = usize::try_from(offset).map_err(|_| io::Error::other("offset"))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| io::Error::other("length"))?;
        Ok(data
            .get(start..end)
            .ok_or_else(|| io::Error::other("range"))?
            .to_vec())
    }
}

fn fixture() -> (MemoryDump, BTreeSet<String>, Profile, Certificate) {
    let dump = MemoryDump::new(BTreeMap::from([
        ("data/a.bin".into(), b"abcdefgh".to_vec()),
        ("data/b.bin".into(), b"12345678".to_vec()),
    ]));
    let selected = BTreeSet::from(["data/a.bin".to_owned()]);
    let profile = Profile {
        toml: "[pack]\ndefault_action = \"loose\"\n\n[[rule]]\naction = \"compress\"\ninclude_from = [\n  \"paths.txt\",\n]\n".into(),
        lists: BTreeMap::from([("paths.txt".into(), "data/a.bin\n".into())]),
    };
    let mut source = AuditedSource::new(dump.clone());
    source.read_range("data/a.bin", 0, 4).unwrap();
    let cert = certificate::create(
        source.files(),
        &selected,
        &profile,
        &source.ranges().unwrap(),
    )
    .unwrap();
    (dump, selected, profile, cert)
}

#[test]
fn roundtrip_verifies_recorded_ranges_but_not_unsampled_bytes() {
    let (mut dump, selected, profile, cert) = fixture();
    let serialized = cert.serialize();
    assert!(serialized.contains("coverage=evidence-ranges-only"));
    let parsed = Certificate::parse(&serialized).unwrap();
    assert_eq!(parsed, cert);
    parsed.verify(&mut dump, &selected, &profile).unwrap();

    // Bytes outside every recorded range are deliberately not covered.
    dump.data.get_mut("data/a.bin").unwrap()[6] ^= 1;
    parsed.verify(&mut dump, &selected, &profile).unwrap();
    dump.data.get_mut("data/a.bin").unwrap()[1] ^= 1;
    assert!(parsed.verify(&mut dump, &selected, &profile).is_err());
}

#[test]
fn verifies_certificates_from_version_0_3_0() {
    let (mut dump, selected, profile, cert) = fixture();
    let legacy = cert.serialize().replacen(
        concat!("analyzer=", env!("CARGO_PKG_VERSION")),
        "analyzer=0.3.0",
        1,
    );
    let parsed = Certificate::parse(&legacy).unwrap();
    parsed.verify(&mut dump, &selected, &profile).unwrap();
    assert_eq!(parsed.serialize(), legacy);
}

#[test]
fn inventory_profile_lists_and_selection_are_bound() {
    let (mut dump, selected, mut profile, cert) = fixture();
    let mut wrong = selected.clone();
    wrong.clear();
    assert!(cert.verify(&mut dump, &wrong, &profile).is_err());

    // Comments keep the Forge selection identical while changing artifact bytes.
    profile.toml.push_str("# changed\n");
    assert!(cert.verify(&mut dump, &selected, &profile).is_err());
    profile.toml = profile.toml.trim_end_matches("# changed\n").to_owned();
    profile
        .lists
        .get_mut("paths.txt")
        .unwrap()
        .push_str("# changed\n");
    assert!(cert.verify(&mut dump, &selected, &profile).is_err());
    profile
        .lists
        .get_mut("paths.txt")
        .unwrap()
        .truncate("data/a.bin\n".len());
    cert.verify(&mut dump, &selected, &profile).unwrap();

    dump.files.push(Entry {
        path: "data/new.bin".into(),
        size: 1,
    });
    dump.data.insert("data/new.bin".into(), vec![0]);
    assert!(cert.verify(&mut dump, &selected, &profile).is_err());
}

#[test]
fn non_full_analysis_can_be_certified_with_its_recorded_evidence() {
    let dump = MemoryDump::new(BTreeMap::from([
        ("eboot.bin".into(), b"not a valid executable".to_vec()),
        ("data/asset.bin".into(), vec![1; 1024]),
    ]));
    let mut source = AuditedSource::new(dump.clone());
    let analysis = analyze(&mut source, Options::default()).unwrap();
    assert_eq!(analysis.header_count, 0);
    let profile = analysis.profile().unwrap();
    let selected = analysis.selected_paths();
    let cert = certificate::create(
        analysis.inventory(),
        &selected,
        &profile,
        &source.ranges().unwrap(),
    )
    .unwrap();
    let parsed = Certificate::parse(&cert.serialize()).unwrap();
    parsed
        .verify(&mut dump.clone(), &selected, &profile)
        .unwrap();
}
