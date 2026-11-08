use std::{collections::BTreeMap, io};

use ps5_pack_analyzer::{analyze, Entry, Options, SourceTree};

struct MemoryDump {
    files: Vec<Entry>,
    data: BTreeMap<String, Vec<u8>>,
}

impl MemoryDump {
    fn new(eboot: Vec<u8>) -> Self {
        let data = BTreeMap::from([
            ("eboot.bin".to_owned(), eboot),
            ("data/a[0].odxb".to_owned(), vec![0; 4]),
            ("data/unknown.bin".to_owned(), vec![0; 6]),
            ("sce_sys/param.json".to_owned(), b"{}".to_vec()),
        ]);
        let files = data
            .iter()
            .map(|(path, b)| Entry {
                path: path.clone(),
                size: b.len() as u64,
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
        let offset = offset as usize;
        Ok(self.data[path][offset..offset + len].to_vec())
    }
}

#[test]
fn resolver_candidates_remain_loose_and_are_reproducible_for_reordered_sources() {
    let executable = synthetic_elf(false);
    let mut first = MemoryDump::new(executable.clone());
    let mut second = MemoryDump::new(executable);
    second.files.reverse();
    let first = analyze(&mut first, Options::default()).unwrap();
    let second = analyze(&mut second, Options::default()).unwrap();
    assert_eq!(first.selected_files, 0);
    assert_eq!(first.selected_bytes, 0);
    assert!(first.selected_paths().is_empty());
    assert!(first.candidate_paths().contains("data/a[0].odxb"));
    let profile = first.profile().unwrap();
    assert!(!profile.toml.contains("\"data/a[[]0].odxb\""));
    assert!(first
        .candidate_profile()
        .unwrap()
        .toml
        .contains("\"data/a[[]0].odxb\""));
    assert!(!profile.toml.contains("data/unknown.bin"));
    assert_eq!(profile.toml, second.profile().unwrap().toml);
    assert_eq!(first.report(), second.report());

    let mut exploratory = MemoryDump::new(synthetic_elf(false));
    let options = Options {
        exploratory: true,
        ..Options::default()
    };
    let exploratory = analyze(&mut exploratory, options).unwrap();
    assert_eq!(exploratory.selected_files, 1);
    assert!(exploratory.profile().unwrap().toml.contains("EXPERIMENTAL"));
    assert_eq!(exploratory.selected_paths(), first.candidate_paths());
}

#[test]
fn unresolved_aio_and_an_unreadable_executable_leave_assets_loose() {
    let mut aio = MemoryDump::new(synthetic_elf(true));
    let result = analyze(&mut aio, Options::default()).unwrap();
    assert!(result.report().contains("Aio: 1 call sites"));
    assert_eq!(result.selected_files, 0);

    let mut truncated = MemoryDump::new(b"\x54\x14\xf5\xee".to_vec());
    let result = analyze(&mut truncated, Options::default()).unwrap();
    assert!(result.report().contains("incomplete executable view: true"));
    assert_eq!(result.selected_files, 0);
}

#[test]
fn apr_scope_is_a_candidate_not_a_compatibility_proof() {
    let mut executable = synthetic_elf(false);
    // Add a GNU EH frame header for one function containing the directory
    // reference and APR calls. The reference is not an argument to APR read.
    executable.resize(0x600, 0);
    executable.copy_within(64..232, 0x500);
    put(&mut executable, 32, 0x500u64.to_le_bytes());
    put(&mut executable, 56, 4u16.to_le_bytes());
    header(&mut executable, 0x5a8, 0x6474_e550, 4, 0x4a0, 20);
    put(&mut executable, 0x4a0, [1, 0x1b, 0x03, 0x3b]);
    put(&mut executable, 0x4a8, 1u32.to_le_bytes());
    put(&mut executable, 0x4ac, (-0x3a0i32).to_le_bytes());
    put(&mut executable, 0x230, *b"data/assets/\0");
    put(&mut executable, 0x103, (0x1230i32 - 0x1107).to_le_bytes());

    let mut dump = MemoryDump::new(executable);
    let path = "data/assets/mesh.xmesh";
    let mut mesh = vec![0; 4096];
    put(&mut mesh, 0, *b"SMBS");
    put(&mut mesh, 4, 0x20001u32.to_le_bytes());
    put(&mut mesh, 24, 64u32.to_le_bytes());
    dump.files.push(Entry {
        path: path.into(),
        size: mesh.len() as u64,
    });
    dump.data.insert(path.into(), mesh);
    let analysis = analyze(&mut dump, Options::full()).unwrap();
    assert!(analysis.report().contains("APR code scope: data/assets/"));
    assert!(analysis.candidate_paths().contains(path));
    assert!(!analysis.selected_paths().contains(path));
    assert!(!analysis.profile().unwrap().toml.contains(path));
    assert!(analysis.candidate_profile().unwrap().toml.contains(path));
}

#[test]
fn full_scan_measures_savings_and_preserves_control_files() {
    let mut dump = MemoryDump::new(synthetic_elf(false));
    let path = "data/a[0].odxb";
    dump.data.get_mut(path).unwrap().resize(16_384, 0);
    dump.data
        .get_mut("sce_sys/param.json")
        .unwrap()
        .resize(16_384, 0);
    for file in &mut dump.files {
        file.size = dump.data[&file.path].len() as u64;
    }
    let opts = || Options {
        exploratory: true,
        ..Options::full()
    };
    let first = analyze(&mut dump, opts()).unwrap();
    dump.files.reverse();
    let reordered = analyze(&mut dump, opts()).unwrap();
    let profile = first.profile().unwrap();
    assert_eq!(first.header_count, dump.files.len());
    assert_eq!(first.selected_files, 1);
    assert_eq!(first.selected_bytes, 16_384);
    assert!(profile.toml.contains("\"data/a[[]0].odxb\""));
    assert!(!profile.toml.contains("sce_sys/param.json"));
    assert_eq!(profile.toml, reordered.profile().unwrap().toml);
    assert_eq!(profile.lists, reordered.profile().unwrap().lists);
    assert_eq!(first.report(), reordered.report());

    let mut state = 1u32;
    for byte in dump.data.get_mut(path).unwrap() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = state as u8;
    }
    let result = analyze(&mut dump, opts()).unwrap();
    assert_eq!(result.selected_files, 0);
    assert!(result
        .report()
        .contains("family samples show little savings"));
}

#[test]
fn a_media_member_keeps_its_archive_loose_even_with_direct_apr_evidence() {
    let mut dump = MemoryDump::new(synthetic_elf(false));
    let path = "data/a[0].odxb";
    let mut archive = vec![0; 32];
    put(&mut archive, 0, *b"cral");
    put(&mut archive, 4, 0x0501u32.to_le_bytes());
    put(&mut archive, 28, 2u32.to_le_bytes());
    for (name, offset) in [("index.bin", 0u32), ("voice.XVAG", 32u32)] {
        archive.extend((name.len() as u32).to_le_bytes());
        archive.extend(name.as_bytes());
        archive.extend(offset.to_le_bytes());
        archive.extend(32u32.to_le_bytes());
        archive.extend([0; 4]);
    }
    archive.extend([0; 4]);
    let end = archive.len() as u32;
    put(&mut archive, 24, end.to_le_bytes());
    archive.resize(16_384, 0);
    dump.files
        .iter_mut()
        .find(|file| file.path == path)
        .unwrap()
        .size = archive.len() as u64;
    dump.data.insert(path.to_owned(), archive);

    let result = analyze(
        &mut dump,
        Options {
            exploratory: true,
            ..Options::full()
        },
    )
    .unwrap();
    assert_eq!(result.selected_files, 0);
    assert!(result
        .report()
        .contains("1 with media evidence, 0 with incomplete content coverage"));
}

#[test]
fn groups_small_meshes_with_their_family_without_matching_loose_descendants() {
    let mut dump = MemoryDump::new(synthetic_elf(true));
    let mut manifest = vec![0; 64];
    put(&mut manifest, 0, *b"DMGP");
    put(&mut manifest, 4, 1u32.to_le_bytes());
    put(&mut manifest, 8, 64u32.to_le_bytes());
    for index in 0..64 {
        let path = format!("data/meshes/mesh-{index}.xmesh");
        manifest.extend(path.as_bytes());
        manifest.push(0);
        let (size, data_offset) = match index {
            0 => (4096, 64u32),
            1 => (128, 64),
            _ => (57, 57),
        };
        let mut mesh = vec![0; size];
        put(&mut mesh, 0, *b"SMBS");
        put(&mut mesh, 4, 0x20001u32.to_le_bytes());
        put(&mut mesh, 24, data_offset.to_le_bytes());
        dump.files.push(Entry {
            path: path.clone(),
            size: size as u64,
        });
        dump.data.insert(path, mesh);
    }
    dump.files.push(Entry {
        path: "data/playgo.pgm".into(),
        size: manifest.len() as u64,
    });
    dump.data.insert("data/playgo.pgm".into(), manifest);
    let conservative = analyze(&mut dump, Options::full()).unwrap();
    assert_eq!(conservative.selected_files, 0);
    assert_eq!(conservative.candidate_paths().len(), 64);
    assert!(conservative
        .candidate_profile()
        .unwrap()
        .toml
        .contains("data/meshes/*.xmesh"));
    let result = analyze(
        &mut dump,
        Options {
            exploratory: true,
            ..Options::full()
        },
    )
    .unwrap();
    assert_eq!(result.selected_files, 64);
    let profile = result.profile().unwrap();
    assert!(profile.toml.contains("\"data/meshes/*.xmesh\""));
    assert!(!profile.toml.contains("mesh-0.xmesh"));
    assert!(profile.lists.is_empty());

    let loose = "data/meshes/nested/loose.xmesh";
    let bytes = dump.data["data/meshes/mesh-0.xmesh"].clone();
    dump.files.push(Entry {
        path: loose.into(),
        size: bytes.len() as u64,
    });
    dump.data.insert(loose.into(), bytes);
    let result = analyze(
        &mut dump,
        Options {
            exploratory: true,
            ..Options::full()
        },
    )
    .unwrap();
    assert_eq!(result.selected_files, 64);
    let profile = result.profile().unwrap();
    assert!(!profile.toml.contains("*.xmesh"));
    assert!(profile.toml.contains("\"data/meshes/mesh-0.xmesh\""));
    assert!(!profile.toml.contains(loose));
}

// Small self-authored ELF. The direct calls reach PLT stubs for APR resolve and
// APR read. The resolve argument points to a relocated array of file names.
fn synthetic_elf(aio: bool) -> Vec<u8> {
    let mut b = vec![0u8; 0x500];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put(&mut b, 18, 62u16.to_le_bytes());
    put(&mut b, 32, 64u64.to_le_bytes());
    put(&mut b, 54, 56u16.to_le_bytes());
    put(&mut b, 56, 3u16.to_le_bytes());
    header(&mut b, 64, 1, 5, 0x100, 0x80);
    header(&mut b, 120, 1, 6, 0x200, 0x300);
    header(&mut b, 176, 2, 6, 0x250, 0x70);

    b[0x100..0x180].fill(0x90);
    put(&mut b, 0x100, [0x48, 0x8d, 0x3d]);
    put(&mut b, 0x103, (0x1220i32 - 0x1107).to_le_bytes());
    let count = if aio { 3 } else { 2 };
    for i in 0..count {
        let call = 0x107 + 5 * i;
        let stub = 0x140 + 8 * i;
        b[call] = 0xe8;
        put(
            &mut b,
            call + 1,
            (stub as i32 - call as i32 - 5).to_le_bytes(),
        );
        put(&mut b, stub, [0xff, 0x25]);
        put(
            &mut b,
            stub + 2,
            ((0x480 + 8 * i) as i32 - stub as i32 - 6).to_le_bytes(),
        );
    }
    b[0x107 + 5 * count] = 0xc3;
    put(&mut b, 0x210, *b"data/a[0].odxb\0");
    let tags = [
        (5, 0x1300),
        (10, 37),
        (6, 0x1380),
        (23, 0x1400),
        (2, count as u64 * 24),
        (7, 0x1450),
        (8, 24),
    ];
    for (i, (tag, value)) in tags.into_iter().enumerate() {
        put(&mut b, 0x250 + 16 * i, (tag as u64).to_le_bytes());
        put(&mut b, 0x258 + 16 * i, value.to_le_bytes());
    }
    for (i, name) in [*b"WT-5NKy42fw", *b"mQ16-QdKv7k", *b"HgX7+AORI58"]
        .into_iter()
        .enumerate()
    {
        put(&mut b, 0x301 + 12 * i, name);
        put(
            &mut b,
            0x380 + 24 * (i + 1),
            (1 + 12 * i as u32).to_le_bytes(),
        );
        put(
            &mut b,
            0x400 + 24 * i,
            (0x1480 + 8 * i as u64).to_le_bytes(),
        );
        put(
            &mut b,
            0x408 + 24 * i,
            (((i as u64 + 1) << 32) | 7).to_le_bytes(),
        );
    }
    put(&mut b, 0x450, 0x1220u64.to_le_bytes());
    put(&mut b, 0x458, 8u64.to_le_bytes());
    put(&mut b, 0x460, 0x1210u64.to_le_bytes());
    b
}

fn header(b: &mut [u8], at: usize, kind: u32, flags: u32, offset: u64, size: u64) {
    put(b, at, kind.to_le_bytes());
    put(b, at + 4, flags.to_le_bytes());
    put(b, at + 8, offset.to_le_bytes());
    put(b, at + 16, (0x1000 + offset).to_le_bytes());
    put(b, at + 32, size.to_le_bytes());
    put(b, at + 40, size.to_le_bytes());
}

fn put<const N: usize>(b: &mut [u8], at: usize, data: [u8; N]) {
    b[at..at + N].copy_from_slice(&data);
}
