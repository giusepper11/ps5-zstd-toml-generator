import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';

const BLOCK = 256 * 1024;
const RAW_LIMIT = 256 * 1024 * 1024;
const MAX_SELECTION = 32 * 1024 * 1024;
const MAX_JSON = 4 * 1024 * 1024;
const MAX_SAMPLES = 12_000;
const params = {
  [zlib.constants.ZSTD_c_compressionLevel]: 5,
  [zlib.constants.ZSTD_c_windowLog]: 18,
  [zlib.constants.ZSTD_c_checksumFlag]: 1,
  [zlib.constants.ZSTD_c_contentSizeFlag]: 1,
};

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function blockIndexes(size) {
  const count = Math.ceil(size / BLOCK);
  return count ? [...new Set([0, Math.floor((count - 1) / 2), count - 1])] : [];
}

function sampleFrame(data) {
  const encoded = zlib.zstdCompressSync(data, { params });
  assert(data.equals(zlib.zstdDecompressSync(encoded)), 'Zstd roundtrip mismatch');
  return {
    frameBytes: encoded.length,
    storedBytes: Math.min(encoded.length, data.length),
    rawSha256: sha256(data),
    frameSha256: sha256(encoded),
  };
}

function selfTest() {
  assert.deepEqual(blockIndexes(BLOCK * 2 + 1), [0, 1, 2]);
  assert.deepEqual(blockIndexes(BLOCK), [0]);
  assert.deepEqual(blockIndexes(0), []);
  assert.equal(sampleFrame(Buffer.alloc(1)).storedBytes, 1);
  assert(sampleFrame(Buffer.alloc(BLOCK)).storedBytes < BLOCK);
  console.log('self-test passed');
}

function within(base, target) {
  const relative = path.relative(base, target);
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function readSelection(filename) {
  const fd = fs.openSync(filename, 'r');
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_SELECTION) {
      throw Error('selection must be a file of at most 32 MiB');
    }
    const bytes = Buffer.alloc(stat.size);
    readExactly(fd, bytes, 0);
    if (fs.readSync(fd, Buffer.alloc(1), 0, 1, bytes.length) !== 0) {
      throw Error('selection changed while being read');
    }
    return bytes;
  } finally {
    fs.closeSync(fd);
  }
}

function groupCandidates(root, selectedText) {
  const seen = new Set();
  const groups = new Map();
  for (const relative of selectedText.split(/\r?\n/)) {
    if (relative === '') continue;
    const parts = relative.split('/');
    if (parts.some((part) => !part || part === '.' || part === '..') ||
        relative.includes('\\') || relative.includes(':') || /\p{Cc}/u.test(relative) ||
        seen.has(relative)) {
      throw Error('invalid or duplicate selected path');
    }
    seen.add(relative);
    const absolute = path.join(root, ...parts);
    const real = fs.realpathSync(absolute);
    if (!within(root, real) || real !== absolute) {
      throw Error(`link, path escape, or noncanonical path: ${relative}`);
    }
    const stat = fs.statSync(real, { bigint: true });
    if (!stat.isFile() || stat.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw Error(`invalid candidate: ${relative}`);
    }
    const extension = path.posix.extname(parts.at(-1));
    const key = JSON.stringify([parts.slice(0, -1).slice(0, 2).join('/'), extension]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ relative, absolute, stat, size: Number(stat.size) });
  }
  return groups;
}

function sameFile(before, after) {
  return after.isFile() && before.size === after.size && before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs && before.ino === after.ino && before.dev === after.dev;
}

function readExactly(fd, data, offset) {
  let read = 0;
  while (read < data.length) {
    const count = fs.readSync(fd, data, read, data.length - read, offset + read);
    if (count === 0) throw Error('short read');
    read += count;
  }
}

function readSample(file, offset, length) {
  const fd = fs.openSync(file.absolute, 'r');
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!sameFile(file.stat, before)) throw Error(`candidate changed before read: ${file.relative}`);
    const data = Buffer.alloc(length);
    readExactly(fd, data, offset);
    const after = fs.fstatSync(fd, { bigint: true });
    const current = fs.statSync(file.absolute, { bigint: true });
    if (!sameFile(before, after) || !sameFile(after, current)) {
      throw Error(`candidate changed during read: ${file.relative}`);
    }
    return {
      path: file.relative,
      offset,
      rawBytes: length,
      ...sampleFrame(data),
      sourceStat: {
        size: String(after.size),
        mtimeNs: String(after.mtimeNs),
        ctimeNs: String(after.ctimeNs),
        device: String(after.dev),
        inode: String(after.ino),
      },
    };
  } finally {
    fs.closeSync(fd);
  }
}

function measure(groups) {
  const result = { truncated: false, rawSampleBytes: 0, storedSampleBytes: 0, sampleCount: 0, groups: [] };
  for (const key of [...groups.keys()].sort()) {
    const files = groups.get(key).sort((a, b) => a.size - b.size ||
      (a.relative < b.relative ? -1 : a.relative > b.relative ? 1 : 0));
    const eligible = files.filter((file) => file.size > 0);
    const count = Math.min(16, eligible.length);
    const group = {
      stratum: JSON.parse(key),
      candidateFiles: files.length,
      candidateRawBytes: files.reduce((sum, file) => sum + file.size, 0),
      sampledFiles: 0,
      rawSampleBytes: 0,
      storedSampleBytes: 0,
      samples: [],
    };
    result.groups.push(group);
    for (let i = 0; i < count; i += 1) {
      const index = Math.floor(i * (eligible.length - 1) / Math.max(1, count - 1));
      const file = eligible[index];
      let sampled = false;
      for (const block of blockIndexes(file.size)) {
        const offset = block * BLOCK;
        const length = Math.min(BLOCK, file.size - offset);
        if (result.rawSampleBytes + length > RAW_LIMIT || result.sampleCount >= MAX_SAMPLES) {
          result.truncated = true;
          break;
        }
        const sample = readSample(file, offset, length);
        group.samples.push(sample);
        group.rawSampleBytes += length;
        group.storedSampleBytes += sample.storedBytes;
        result.rawSampleBytes += length;
        result.storedSampleBytes += sample.storedBytes;
        result.sampleCount += 1;
        sampled = true;
      }
      if (sampled) group.sampledFiles += 1;
      if (result.truncated) return result;
    }
  }
  return result;
}

function main(args) {
  if (typeof zlib.zstdCompressSync !== 'function') throw Error('use Node.js 24 or later');
  if (args.length === 1 && args[0] === '--self-test') {
    selfTest();
    return;
  }
  if (args.length !== 3) {
    throw Error('Usage: node scripts/sample-zstd.mjs <dump> <analysis-folder> <new-output.json>');
  }
  const [dumpArg, analysisArg, outArg] = args;
  const root = fs.realpathSync(dumpArg);
  if (!fs.statSync(root).isDirectory()) throw Error('dump must be a directory');
  const analysis = fs.realpathSync(analysisArg);
  const output = path.resolve(outArg);
  const parent = fs.realpathSync(path.dirname(output));
  const outputReal = path.join(parent, path.basename(output));
  if (within(root, outputReal)) throw Error('output must be outside dump');

  const selection = readSelection(path.join(analysis, 'candidates', 'selected.txt'));
  const selectedText = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(selection);
  const measurements = measure(groupCandidates(root, selectedText));
  const result = {
    schema: 'ps5-zstd-sample-v1',
    scope: 'sampled blocks only; not a pack-size prediction or gameplay/Forge compatibility validation',
    selectionSha256: sha256(selection),
    node: process.version,
    zstd: process.versions.zstd ?? 'unknown',
    parameters: { compressionLevel: 5, windowLog: 18, checksumFlag: 1, contentSizeFlag: 1, blockBytes: BLOCK },
    limits: { rawBytes: RAW_LIMIT, sampleCount: MAX_SAMPLES, outputBytesExclusive: MAX_JSON },
    grouping: 'first two parent path components and case-sensitive extension; files sorted size/path, 16 quantiles, first/middle/last aligned blocks',
    ...measurements,
  };
  const bytes = Buffer.from(`${JSON.stringify(result, null, 2)}\n`);
  if (bytes.length >= MAX_JSON) throw Error('output exceeds JSON size limit');
  fs.writeFileSync(outputReal, bytes, { flag: 'wx' });
  console.log(`Wrote ${result.sampleCount} samples, ${result.rawSampleBytes} raw bytes; truncated=${result.truncated}`);
}

try {
  main(process.argv.slice(2));
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exitCode = 1;
}
