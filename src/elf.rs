use std::collections::{BTreeMap, BTreeSet};

const ELF: &[u8] = b"\x7fELF";
const SELF: [[u8; 4]; 2] = [[0x4f, 0x15, 0x3d, 0x1d], [0x54, 0x14, 0xf5, 0xee]];
const LOAD: u32 = 1;
const DYNAMIC: u32 = 2;
const GNU_EH_FRAME: u32 = 0x6474_e550;
const SCE_DYNLIB: u32 = 0x6100_0000;
const RELATIVE: u32 = 8;

pub(crate) fn executable_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(ELF) || SELF.iter().any(|magic| bytes.starts_with(magic))
}

struct Header {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    size: u64,
}

pub(crate) struct Segment<'a> {
    kind: u32,
    flags: u32,
    pub address: u64,
    pub data: &'a [u8],
}

pub(crate) struct Image<'a> {
    segments: Vec<Segment<'a>>,
    pub imports: BTreeMap<u64, &'a str>,
    pub pointers: BTreeMap<u64, u64>,
    pub function_starts: Vec<u64>,
    pub inaccessible_code: bool,
}

impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let is_self = SELF.iter().any(|magic| bytes.starts_with(magic));
        let records = if is_self {
            word(bytes, 24)? as usize
        } else {
            0
        };
        let elf_at = if is_self { 32 + 32 * records } else { 0 };
        let elf = bytes.get(elf_at..)?;
        if !elf.starts_with(ELF) || elf.get(4..7)? != [2, 1, 1] || word(elf, 18)? != 62 {
            return None;
        }
        let headers_at = qword(elf, 32)?;
        let count = word(elf, 56)? as usize;
        if word(elf, 54)? != 56 {
            return None;
        }
        let headers: Vec<_> = range(elf, headers_at, count as u64 * 56)?
            .chunks_exact(56)
            .map(|h| {
                Some(Header {
                    kind: dword(h, 0)?,
                    flags: dword(h, 4)?,
                    offset: qword(h, 8)?,
                    address: qword(h, 16)?,
                    size: qword(h, 32)?,
                })
            })
            .collect::<Option<_>>()?;
        let mut self_offsets = BTreeMap::new();
        for row in bytes
            .get(if is_self { 32..elf_at } else { 0..0 })?
            .chunks_exact(32)
        {
            let flags = qword(row, 0)?;
            if flags & 0x800 != 0 && flags & 0xa == 0 && qword(row, 16)? == qword(row, 24)? {
                self_offsets.insert(
                    ((flags >> 20) & 0xffff) as usize,
                    (qword(row, 8)?, qword(row, 24)?),
                );
            }
        }
        let mut image = Self {
            segments: Vec::new(),
            imports: BTreeMap::new(),
            pointers: BTreeMap::new(),
            function_starts: Vec::new(),
            inaccessible_code: false,
        };
        for (id, h) in headers.iter().enumerate() {
            if !matches!(h.kind, LOAD | SCE_DYNLIB) || h.size == 0 {
                continue;
            }
            let offset = if is_self {
                self_offsets
                    .get(&id)
                    .filter(|(_, len)| *len >= h.size)
                    .map(|(off, _)| *off)
            } else {
                Some(h.offset)
            };
            if let Some(data) = offset.and_then(|at| range(bytes, at, h.size)) {
                h.address.checked_add(h.size)?;
                image.segments.push(Segment {
                    kind: h.kind,
                    flags: h.flags,
                    address: h.address,
                    data,
                });
            } else if h.kind == LOAD && h.flags & 1 != 0 {
                image.inaccessible_code = true;
            }
        }
        image.function_starts = headers
            .iter()
            .filter(|h| h.kind == GNU_EH_FRAME)
            .filter_map(|h| unwind_starts(image.at(h.address, h.size)?, h.address))
            .flatten()
            .filter(|&start| {
                image.code().any(|code| {
                    start >= code.address && start - code.address < code.data.len() as u64
                })
            })
            .collect();
        image.function_starts.sort_unstable();
        image.function_starts.dedup();

        let Some((dyn_id, dyn_header)) = headers
            .iter()
            .enumerate()
            .find(|(_, h)| h.kind == DYNAMIC && h.size > 0)
        else {
            return Some(image);
        };
        let dyn_segment = if is_self {
            self_offsets
                .get(&dyn_id)
                .filter(|(_, size)| *size >= dyn_header.size)
                .and_then(|(offset, _)| range(bytes, *offset, dyn_header.size))
                .or_else(|| {
                    headers.iter().enumerate().find_map(|(i, h)| {
                        let relative = dyn_header.offset.checked_sub(h.offset)?;
                        if relative.checked_add(dyn_header.size)? > h.size {
                            return None;
                        }
                        let (offset, _) = self_offsets.get(&i)?;
                        range(bytes, offset.checked_add(relative)?, dyn_header.size)
                    })
                })
        } else {
            range(bytes, dyn_header.offset, dyn_header.size)
        };
        let Some(dynamic) = dyn_segment else {
            image.inaccessible_code = true;
            return Some(image);
        };
        let mut tags = BTreeMap::new();
        for row in dynamic.chunks_exact(16) {
            let tag = qword(row, 0)?;
            if tag == 0 {
                break;
            }
            tags.insert(tag, qword(row, 8)?);
        }
        let tables = Tables {
            image: &image,
            tags,
        };
        let mut imports = BTreeMap::new();
        let mut pointers = BTreeMap::new();
        for (table, size, sce_table, sce_size) in [(23, 2, 0x29, 0x2d), (7, 8, 0x2f, 0x31)] {
            if let Some(relocs) = tables.table(table, size, sce_table, sce_size) {
                for row in relocs.chunks_exact(24) {
                    let address = qword(row, 0)?;
                    let info = qword(row, 8)?;
                    if info == u64::from(RELATIVE) {
                        pointers.insert(address, qword(row, 16)?);
                    }
                    if info >> 32 != 0 {
                        if let Some(name) = tables.symbol(info >> 32) {
                            imports.insert(address, name);
                        }
                    }
                }
            }
        }
        image.imports = imports;
        image.pointers = pointers;
        Some(image)
    }

    pub fn code(&self) -> impl Iterator<Item = &Segment<'a>> {
        self.segments
            .iter()
            .filter(|s| s.kind == LOAD && s.flags & 1 != 0)
    }

    pub fn at(&self, address: u64, size: u64) -> Option<&'a [u8]> {
        self.segments
            .iter()
            .find_map(|s| range(s.data, address.checked_sub(s.address)?, size))
    }

    pub fn text_at(&self, address: u64) -> Option<&'a str> {
        let data = self
            .segments
            .iter()
            .filter(|s| s.flags & 1 == 0)
            .find_map(|s| {
                s.data
                    .get(usize::try_from(address.checked_sub(s.address)?).ok()?..)
            })?;
        cstr(data.get(..data.len().min(4096))?)
    }

    pub fn literals(&self) -> BTreeSet<&'a str> {
        self.segments
            .iter()
            .filter(|s| s.kind == LOAD && s.flags & 1 == 0)
            .flat_map(|s| s.data.split(|&b| b == 0))
            .filter(|s| (4..=1024).contains(&s.len()))
            .filter_map(|s| std::str::from_utf8(s).ok())
            .filter(|s| s.contains('/'))
            .collect()
    }
}

fn unwind_starts(bytes: &[u8], address: u64) -> Option<Vec<u64>> {
    // Version 1 with a PC-relative i32 EH frame pointer, a u32 count,
    // and data-relative i32 pairs in the binary search table.
    if bytes.get(..4)? != [1, 0x1b, 0x03, 0x3b] {
        return None;
    }
    let count = u64::from(dword(bytes, 8)?);
    range(bytes, 12, count * 8)?
        .chunks_exact(8)
        .map(|row| address.checked_add_signed(i64::from(dword(row, 0)? as i32)))
        .collect()
}

struct Tables<'i, 'a> {
    image: &'i Image<'a>,
    tags: BTreeMap<u64, u64>,
}

impl<'a> Tables<'_, 'a> {
    fn sce(&self, tag: u64) -> Option<u64> {
        self.tags.get(&(0x6100_0000 + tag)).copied()
    }

    fn region(&self, elf: u64, sce: u64, offset: u64, size: u64) -> Option<&'a [u8]> {
        if let Some(&address) = self.tags.get(&elf) {
            self.image.at(address.checked_add(offset)?, size)
        } else {
            let segment = self.image.segments.iter().find(|s| s.kind == SCE_DYNLIB)?;
            range(segment.data, self.sce(sce)?.checked_add(offset)?, size)
        }
    }

    fn table(&self, elf: u64, size: u64, sce: u64, sce_size: u64) -> Option<&'a [u8]> {
        self.region(
            elf,
            sce,
            0,
            self.tags
                .get(&size)
                .copied()
                .or_else(|| self.sce(sce_size))?,
        )
    }

    fn symbol(&self, index: u64) -> Option<&'a str> {
        let offset = index.checked_mul(24)?;
        if self.sce(0x3f).is_some_and(|len| offset >= len) {
            return None;
        }
        let row = self.region(6, 0x39, offset, 24)?;
        if word(row, 6)? != 0 {
            return None;
        }
        let strings = self.table(5, 10, 0x35, 0x37)?;
        cstr(strings.get(dword(row, 0)? as usize..)?)
    }
}

pub(crate) fn cstr(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes.get(..bytes.iter().position(|&b| b == 0)?)?).ok()
}

pub(crate) fn range(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    bytes.get(usize::try_from(offset).ok()?..usize::try_from(offset.checked_add(size)?).ok()?)
}

fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn dword(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn qword(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}
