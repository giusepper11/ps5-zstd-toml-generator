use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};

use crate::elf::Image;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Api {
    AprResolve,
    AprRead,
    Aio,
    Video,
    Open,
    Read,
    Directory,
    Dynamic,
    Map,
}

// PS5 NIDs for the public API names next to them. See the NID algorithm
// linked in the project's ps5-dump-pack-audit skill.
const IO_APIS: &[(&str, &str, Api)] = &[
    (
        "sceKernelAprResolveFilepathsToIds",
        "WT-5NKy42fw",
        Api::AprResolve,
    ),
    (
        "sceKernelAprResolveFilepathsToIdsAndFileSizes",
        "gEpBkcwxUjw",
        Api::AprResolve,
    ),
    (
        "sceKernelAprResolveFilepathsToIdsAndFileSizesForEach",
        "QzB4O+bJQyA",
        Api::AprResolve,
    ),
    (
        "sceKernelAprResolveFilepathsToIdsForEach",
        "eYAh2vlCY-U",
        Api::AprResolve,
    ),
    (
        "sceKernelAprResolveFilepathsWithPrefixToIds",
        "i3HWvW35jao",
        Api::AprResolve,
    ),
    (
        "sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes",
        "w5fcCG+t31g",
        Api::AprResolve,
    ),
    (
        "sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach",
        "C+Khtbbx2g8",
        Api::AprResolve,
    ),
    (
        "sceKernelAprResolveFilepathsWithPrefixToIdsForEach",
        "VB-BtuIW8Xc",
        Api::AprResolve,
    ),
    (
        "sceAmprAprCommandBufferReadFile",
        "mQ16-QdKv7k",
        Api::AprRead,
    ),
    (
        "sceAmprAprCommandBufferReadFileGather",
        "mZSbNJVJpV8",
        Api::AprRead,
    ),
    (
        "sceAmprAprCommandBufferReadFileScatter",
        "Jg-AgkdJHkk",
        Api::AprRead,
    ),
    (
        "sceAmprAprCommandBufferReadFileGatherScatter",
        "BVmR1H8l+XI",
        Api::AprRead,
    ),
    ("sceKernelAioSubmitReadCommands", "HgX7+AORI58", Api::Aio),
    (
        "sceKernelAioSubmitReadCommandsMultiple",
        "lXT0m3P-vs4",
        Api::Aio,
    ),
    ("sceKernelAioSubmitWriteCommands", "XQ8C8y+de+E", Api::Aio),
    (
        "sceKernelAioSubmitWriteCommandsMultiple",
        "xT3Cpz0yh6Y",
        Api::Aio,
    ),
    ("sceAvPlayerAddSource", "KMcEa+rHsIo", Api::Video),
    ("sceAvPlayerAddSourceEx", "x8uvuFOPZhU", Api::Video),
    ("sceKernelOpen", "1G3lF1Gg1k8", Api::Open),
    ("open", "wuCroIGjt2g", Api::Open),
    ("fopen", "xeYO4u7uyJ0", Api::Open),
    ("read", "AqBioC2vF3I", Api::Read),
    ("pread", "ezv-RSBNKqI", Api::Read),
    ("fread", "lbB+UlZqVG0", Api::Read),
    ("sceKernelRead", "Cg4srZ6TKbU", Api::Read),
    ("sceKernelPread", "+r3rMFwItV4", Api::Read),
    ("sceKernelGetdents", "j2AIqSqJP0w", Api::Directory),
    ("sceKernelGetdirentries", "taRWhTJFTgE", Api::Directory),
    ("getdirentries", "f09KvIPy-QY", Api::Directory),
    ("opendir", "ay3uROQAc5A", Api::Directory),
    ("sceKernelDlsym", "LwG8g3niqwA", Api::Dynamic),
    ("dlsym", "biY+kcVB5D4", Api::Dynamic),
    ("sceKernelLoadStartModule", "wzvqT4UqKX8", Api::Dynamic),
    ("sceKernelMmap", "PGhQHd-dzv8", Api::Map),
    ("mmap", "BPE9s9vQQXo", Api::Map),
];

#[derive(Clone, Copy)]
struct Import {
    api: Api,
    numeric_open_flags: bool,
    path_args: &'static [Register],
}

fn lookup(symbol: &str) -> Option<Import> {
    let name = symbol.split('#').next()?;
    let &(plain, _, api) = IO_APIS
        .iter()
        .find(|&&(plain, nid, _)| name == plain || name == nid)?;
    let path_args: &[_] = match api {
        Api::AprResolve if plain.contains("WithPrefix") => &[Register::RDI, Register::RSI],
        Api::AprResolve | Api::Open => &[Register::RDI],
        Api::Directory if plain == "opendir" => &[Register::RDI],
        Api::Video if plain == "sceAvPlayerAddSource" => &[Register::RSI],
        _ => &[],
    };
    Some(Import {
        api,
        numeric_open_flags: matches!(plain, "open" | "sceKernelOpen"),
        path_args,
    })
}

#[derive(Debug)]
pub(crate) struct Call<'a> {
    pub api: Api,
    pub rva: u64,
    pub paths: BTreeSet<&'a str>,
    pub flags: Option<u64>,
}

impl Call<'_> {
    pub fn is_directory_open(&self) -> bool {
        self.api == Api::Open && self.flags.is_some_and(|flags| flags & 0x2_0000 != 0)
    }
}

#[derive(Debug)]
pub(crate) struct PathReference<'a> {
    pub path: &'a str,
    pub rva: u64,
    // 0 means the function contains an API call. Positive distances count
    // direct inter-function calls or tail jumps. This is reachability evidence.
    pub distances: BTreeMap<Api, u8>,
}

pub(crate) struct IoEvidence<'a> {
    pub calls: Vec<Call<'a>>,
    pub references: Vec<PathReference<'a>>,
    /// Instructions whose destination was not resolved to a known import.
    /// These include ordinary callbacks and unknown imports; they do not prove I/O.
    pub unresolved_indirect_calls: Vec<u64>,
    pub unresolved_indirect_jumps: Vec<u64>,
}

const MAX_API_DISTANCE: u8 = 6;

pub(crate) fn inspect<'a>(image: &Image<'a>, is_path: impl Fn(&str) -> bool) -> IoEvidence<'a> {
    let imports: BTreeMap<_, _> = image
        .imports
        .iter()
        .filter_map(|(&slot, name)| Some((slot, lookup(name)?)))
        .collect();
    let mut stubs = BTreeMap::new();
    let mut joins = image.function_starts.clone();
    joins.extend(image.pointers.values().copied());
    for code in image.code() {
        for ins in Decoder::with_ip(64, code.data, code.address, DecoderOptions::NONE) {
            if ins.flow_control() == FlowControl::IndirectBranch && ins.is_ip_rel_memory_operand() {
                if let Some(&import) = imports.get(&ins.ip_rel_memory_address()) {
                    stubs.insert(ins.ip(), import);
                }
            }
            if let Some(target) = direct_target(&ins) {
                joins.push(target);
            }
        }
    }
    // A function consisting of an immediate tail jump to an already known
    // import stub preserves every argument. Resolve only this exact case; do
    // not infer argument flow through general wrappers, callbacks or vtables.
    for _ in 0..4 {
        let mut additions = Vec::new();
        for code in image.code() {
            for ins in Decoder::with_ip(64, code.data, code.address, DecoderOptions::NONE) {
                if image.function_starts.binary_search(&ins.ip()).is_ok()
                    && ins.flow_control() == FlowControl::UnconditionalBranch
                {
                    if let Some(import) = direct_target(&ins).and_then(|target| stubs.get(&target))
                    {
                        if !stubs.contains_key(&ins.ip()) {
                            additions.push((ins.ip(), *import));
                        }
                    }
                }
            }
        }
        if additions.is_empty() {
            break;
        }
        stubs.extend(additions);
    }
    joins.sort_unstable();
    joins.dedup();
    let mut calls = Vec::new();
    let mut references = Vec::new();
    let mut unresolved_indirect_calls = Vec::new();
    let mut unresolved_indirect_jumps = Vec::new();
    let mut callers = vec![Vec::new(); image.function_starts.len()];
    let mut api_roots = BTreeMap::<Api, BTreeSet<usize>>::new();
    let mut context = VecDeque::with_capacity(24);
    let mut factory = InstructionInfoFactory::new();
    for code in image.code() {
        context.clear();
        let mut next_join = joins.partition_point(|&rva| rva < code.address);
        let mut next_function = image
            .function_starts
            .partition_point(|&rva| rva < code.address);
        let mut function = None;
        for ins in Decoder::with_ip(64, code.data, code.address, DecoderOptions::NONE) {
            let rva = ins.ip();
            if joins.get(next_join).is_some_and(|&join| join <= rva) {
                context.clear();
                next_join += joins[next_join..].partition_point(|&join| join <= rva);
            }
            if image
                .function_starts
                .get(next_function)
                .is_some_and(|&start| start <= rva)
            {
                next_function +=
                    image.function_starts[next_function..].partition_point(|&start| start <= rva);
                function =
                    (image.function_starts[next_function - 1] == rva).then_some(next_function - 1);
            }

            let flow = ins.flow_control();
            let import = match flow {
                FlowControl::Call | FlowControl::UnconditionalBranch => direct_target(&ins)
                    .and_then(|target| {
                        if let Some(caller) = function {
                            if let Ok(callee) = image.function_starts.binary_search(&target) {
                                if caller != callee {
                                    callers[callee].push(caller);
                                }
                            }
                        }
                        stubs.get(&target)
                    }),
                FlowControl::IndirectCall if ins.is_ip_rel_memory_operand() => {
                    imports.get(&ins.ip_rel_memory_address())
                }
                _ => None,
            };
            match flow {
                FlowControl::IndirectCall if import.is_none() => {
                    unresolved_indirect_calls.push(rva)
                }
                FlowControl::IndirectBranch if !stubs.contains_key(&rva) => {
                    unresolved_indirect_jumps.push(rva);
                }
                _ => {}
            }
            if let Some(&import) = import {
                let regs = constants(&context, image, &mut factory);
                let mut paths = BTreeSet::new();
                // SysV x86-64. APR resolvers can receive a pointer to an array
                // of names, so try one statically relocated pointer as well.
                for addr in import.path_args.iter().filter_map(|reg| regs.get(reg)) {
                    for address in std::iter::once(*addr).chain(image.pointers.get(addr).copied()) {
                        if let Some(path) = image.text_at(address) {
                            paths.insert(path);
                        }
                    }
                }
                let call = Call {
                    api: import.api,
                    rva,
                    paths,
                    flags: import
                        .numeric_open_flags
                        .then(|| regs.get(&Register::RSI).copied())
                        .flatten(),
                };
                if let Some(function) = function {
                    let api = if call.is_directory_open() {
                        Api::Directory
                    } else {
                        call.api
                    };
                    api_roots.entry(api).or_default().insert(function);
                }
                calls.push(call);
            }

            if ins.is_ip_rel_memory_operand() {
                let address = ins.ip_rel_memory_address();
                for address in std::iter::once(address).chain(image.pointers.get(&address).copied())
                {
                    if let Some(path) = image.text_at(address).filter(|path| is_path(path)) {
                        references.push((path, rva, function));
                    }
                }
            }
            // A bounded straight-line analysis does not claim control flow
            // through indirect callbacks or across branches.
            if flow == FlowControl::Next && !ins.is_invalid() {
                if context.len() == 24 {
                    context.pop_front();
                }
                context.push_back(ins);
            } else {
                context.clear();
            }
        }
    }
    for callers in &mut callers {
        callers.sort_unstable();
        callers.dedup();
    }
    let distances: BTreeMap<_, _> = api_roots
        .into_iter()
        .map(|(api, roots)| (api, caller_distances(&callers, roots)))
        .collect();
    calls.sort_unstable_by_key(|call| (call.rva, call.api));
    references.sort_unstable();
    references.dedup();
    IoEvidence {
        calls,
        unresolved_indirect_calls,
        unresolved_indirect_jumps,
        references: references
            .into_iter()
            .map(|(path, rva, function)| PathReference {
                path,
                rva,
                distances: distances
                    .iter()
                    .filter_map(|(&api, steps)| {
                        let distance = steps[function?];
                        (distance <= MAX_API_DISTANCE).then_some((api, distance))
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn direct_target(ins: &Instruction) -> Option<u64> {
    matches!(
        ins.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| ins.near_branch_target())
}

fn caller_distances(callers: &[Vec<usize>], roots: BTreeSet<usize>) -> Vec<u8> {
    let mut distances = vec![u8::MAX; callers.len()];
    let mut queue = VecDeque::from_iter(roots);
    for &root in &queue {
        distances[root] = 0;
    }
    while let Some(callee) = queue.pop_front() {
        let next = distances[callee] + 1;
        if next > MAX_API_DISTANCE {
            continue;
        }
        for &caller in &callers[callee] {
            if distances[caller] == u8::MAX {
                distances[caller] = next;
                queue.push_back(caller);
            }
        }
    }
    distances
}

fn constants(
    context: &VecDeque<Instruction>,
    image: &Image<'_>,
    factory: &mut InstructionInfoFactory,
) -> BTreeMap<Register, u64> {
    let mut regs = BTreeMap::new();
    for ins in context {
        let dest = ins.op0_register().full_register();
        let value = if ins.op0_kind() != OpKind::Register {
            None
        } else {
            match (ins.mnemonic(), ins.op1_kind()) {
                (Mnemonic::Lea, OpKind::Memory) if ins.is_ip_rel_memory_operand() => {
                    Some(ins.ip_rel_memory_address())
                }
                (Mnemonic::Mov, OpKind::Register) => {
                    regs.get(&ins.op1_register().full_register()).copied()
                }
                (Mnemonic::Mov, OpKind::Memory) if ins.is_ip_rel_memory_operand() => {
                    image.pointers.get(&ins.ip_rel_memory_address()).copied()
                }
                (
                    Mnemonic::Mov,
                    OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64,
                ) => Some(ins.immediate(1)),
                (Mnemonic::Xor, OpKind::Register) if ins.op0_register() == ins.op1_register() => {
                    Some(0)
                }
                _ => None,
            }
        };
        for used in factory.info(ins).used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                regs.remove(&used.register().full_register());
            }
        }
        if let Some(value) = value {
            if ins.op0_register().size() >= 4 {
                regs.insert(
                    dest,
                    if ins.op0_register().size() == 4 {
                        value & u64::from(u32::MAX)
                    } else {
                        value
                    },
                );
            }
        }
    }
    regs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connects_literal_references_to_direct_calls_in_other_functions() {
        let data = executable();
        let mut image = Image::parse(&data).unwrap();
        image.imports.insert(0x300, "sceKernelOpen");
        let result = inspect(&image, |path| path == "assets/");

        assert_eq!(result.references.len(), 1);
        let reference = &result.references[0];
        assert_eq!(reference.path, "assets/");
        assert_eq!(reference.rva, 0x100);
        assert_eq!(reference.distances, BTreeMap::from([(Api::Open, 1)]));
        assert!(result.calls[0].paths.is_empty());
    }

    #[test]
    fn open_flags_require_a_reaching_assignment_and_a_numeric_argument() {
        let data = executable();
        let mut image = Image::parse(&data).unwrap();
        image.imports.insert(0x300, "sceKernelOpen");
        let result = inspect(&image, |_| false);
        let calls: BTreeMap<_, _> = result.calls.iter().map(|call| (call.rva, call)).collect();
        assert_eq!(calls[&0x13b].flags, None);
        assert!(calls[&0x155].is_directory_open());

        image.imports.insert(0x300, "fopen");
        let result = inspect(&image, |_| false);
        assert!(result.calls.iter().all(|call| call.flags.is_none()));
    }

    #[test]
    fn recognizes_only_argument_preserving_tail_jump_wrappers() {
        let mut data = executable();
        // Function 0x120 is a tail jump to the existing import stub at 0x140.
        data[0x120] = 0xe9;
        let mut image = Image::parse(&data).unwrap();
        image.imports.insert(0x300, "sceKernelOpen");
        let result = inspect(&image, |_| false);
        let call = result.calls.iter().find(|call| call.rva == 0x107).unwrap();
        assert_eq!(call.api, Api::Open);
        assert!(call.paths.contains("assets/"));

        // A wrapper with any prologue is not summarized: no propagation is
        // claimed without tracking the intervening argument modifications.
        data[0x120] = 0x90;
        data[0x121..0x126].copy_from_slice(&[0xe9, 0x1a, 0, 0, 0]);
        let mut image = Image::parse(&data).unwrap();
        image.imports.insert(0x300, "sceKernelOpen");
        let result = inspect(&image, |_| false);
        assert!(!result.calls.iter().any(|call| call.rva == 0x107));
    }

    #[test]
    fn reports_unresolved_indirection_without_claiming_it_is_io() {
        let mut data = executable();
        // call rax; jmp rax. The existing PLT jump is resolved separately.
        data[0x160..0x164].copy_from_slice(&[0xff, 0xd0, 0xff, 0xe0]);
        let mut image = Image::parse(&data).unwrap();
        image.imports.insert(0x300, "sceKernelOpen");
        let result = inspect(&image, |_| false);
        assert_eq!(result.unresolved_indirect_calls, vec![0x160]);
        assert_eq!(result.unresolved_indirect_jumps, vec![0x162]);
        assert!(!result.calls.iter().any(|call| call.rva == 0x160));
    }

    #[test]
    fn identifies_read_nids_without_inferring_a_path() {
        for name in [
            "AqBioC2vF3I",
            "ezv-RSBNKqI",
            "lbB+UlZqVG0",
            "Cg4srZ6TKbU",
            "+r3rMFwItV4",
        ] {
            let import = lookup(name).unwrap();
            assert_eq!(import.api, Api::Read);
            assert!(import.path_args.is_empty());
        }
    }

    fn executable() -> Vec<u8> {
        let mut data = vec![0; 0x400];
        data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        data[18..20].copy_from_slice(&62u16.to_le_bytes());
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&3u16.to_le_bytes());
        header(&mut data[64..120], 1, 5, 0x100, 0x80);
        header(&mut data[120..176], 1, 4, 0x200, 0x200);
        header(&mut data[176..232], 0x6474_e550, 4, 0x230, 44);

        data[0x100..0x180].fill(0x90);
        // lea rdi, [0x200]; call 0x120; ret
        data[0x100..0x10d]
            .copy_from_slice(&[0x48, 0x8d, 0x3d, 0xf9, 0, 0, 0, 0xe8, 0x14, 0, 0, 0, 0xc3]);
        // call 0x140; ret
        data[0x120..0x126].copy_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]);
        // xor esi, esi; jz 0x13b; mov esi, 0x20000
        data[0x130..0x139].copy_from_slice(&[0x31, 0xf6, 0x74, 7, 0xbe, 0, 0, 2, 0]);
        // call 0x140; jmp [0x300]
        data[0x13b..0x146].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0xff, 0x25, 0xba, 1, 0, 0]);
        // mov esi, 0x20000; call 0x140; ret
        data[0x150..0x15b].copy_from_slice(&[0xbe, 0, 0, 2, 0, 0xe8, 0xe6, 0xff, 0xff, 0xff, 0xc3]);

        data[0x200..0x208].copy_from_slice(b"assets/\0");
        data[0x230..0x234].copy_from_slice(&[1, 0x1b, 0x03, 0x3b]);
        data[0x238..0x23c].copy_from_slice(&4u32.to_le_bytes());
        for (row, start) in data[0x23c..0x25c]
            .chunks_exact_mut(8)
            .zip([0x100i32, 0x120, 0x130, 0x150])
        {
            row[..4].copy_from_slice(&(start - 0x230).to_le_bytes());
        }
        data
    }

    fn header(data: &mut [u8], kind: u32, flags: u32, address: u64, size: u64) {
        data[..4].copy_from_slice(&kind.to_le_bytes());
        data[4..8].copy_from_slice(&flags.to_le_bytes());
        data[8..16].copy_from_slice(&address.to_le_bytes());
        data[16..24].copy_from_slice(&address.to_le_bytes());
        data[32..40].copy_from_slice(&size.to_le_bytes());
    }
}
