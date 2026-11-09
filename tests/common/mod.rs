// Small self-authored ELF. The direct calls reach PLT stubs for APR resolve and
// APR read. The resolve argument points to a relocated array of file names.
pub(crate) fn synthetic_elf(aio: bool) -> Vec<u8> {
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

pub(crate) fn header(b: &mut [u8], at: usize, kind: u32, flags: u32, offset: u64, size: u64) {
    put(b, at, kind.to_le_bytes());
    put(b, at + 4, flags.to_le_bytes());
    put(b, at + 8, offset.to_le_bytes());
    put(b, at + 16, (0x1000 + offset).to_le_bytes());
    put(b, at + 32, size.to_le_bytes());
    put(b, at + 40, size.to_le_bytes());
}

pub(crate) fn put<const N: usize>(b: &mut [u8], at: usize, data: [u8; N]) {
    b[at..at + N].copy_from_slice(&data);
}
