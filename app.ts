// A GitHub-compatible git forge in one Node process: smart HTTP (upload-pack v2 /
// receive-pack v0), REST v3, GraphQL v4 and MCP over streamable HTTP. One in-memory
// store, no files, no git binary, no network. All stored state is deterministic:
// ids, numbers and timestamps come from counters, never the wall clock or Math.random,
// so a replay of the same requests leaves the same state.
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

// -------------------------------------------------------------------------------------------
// small utilities
// -------------------------------------------------------------------------------------------

const ZERO_OID = '0'.repeat(40);
const VIEWER_LOGIN_DEFAULT = 'adaiversen';
const VIEWER_ID_DEFAULT = 1000;
const FORGE_IDENTITY = 'Forge <forge@make.fun>';
const EPOCH_BASE = 1700000000;

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asBuffer(value: string | Uint8Array): Buffer {
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  if (Buffer.isBuffer(value)) return value;
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function sha1Hex(data: Uint8Array): string {
  return createHash('sha1').update(asBuffer(data)).digest('hex');
}

function b64encode(data: Uint8Array): string {
  return asBuffer(data).toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function isoFromCounter(counter: number): string {
  return new Date((EPOCH_BASE + counter) * 1000).toISOString();
}

// -------------------------------------------------------------------------------------------
// pkt-line framing
// -------------------------------------------------------------------------------------------

const PKT_MAX = 65520;

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktLines(items: readonly (string | Buffer | 'flush')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

/** Hex digit value of a byte (masked to ASCII, as the old regex saw it), or -1. */
function hexVal(byte: number): number {
  const b = byte & 0x7f;
  if (b >= 48 && b <= 57) return b - 48;
  if (b >= 97 && b <= 102) return b - 87;
  if (b >= 65 && b <= 70) return b - 55;
  return -1;
}

/** One shared empty buffer for pkt-line flush/delim/end payloads. */
const EMPTY_BUFFER = Buffer.alloc(0);

/** Decode pkt-lines from the head of `buf`. Returns the packets and the offset just past them. */
function decodePktLinesHead(buf: Buffer): { packets: { kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }[]; offset: number } {
  const packets: { kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const h0 = hexVal(buf[offset]);
    const h1 = hexVal(buf[offset + 1]);
    const h2 = hexVal(buf[offset + 2]);
    const h3 = hexVal(buf[offset + 3]);
    if (h0 < 0 || h1 < 0 || h2 < 0 || h3 < 0) break;
    const len = (h0 << 12) | (h1 << 8) | (h2 << 4) | h3;
    if (len === 0) {
      packets.push({ kind: 'flush', payload: EMPTY_BUFFER });
      offset += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: EMPTY_BUFFER });
      offset += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end', payload: EMPTY_BUFFER });
      offset += 4;
      continue;
    }
    if (len < 4 || len > PKT_MAX || offset + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
    offset += len;
  }
  return { packets, offset };
}

/** All data-packet payloads of a whole buffer, as text lines (trailing newline kept off). */
function pktTextLines(buf: Buffer): string[] {
  const { packets } = decodePktLinesHead(buf);
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  return lines;
}

// -------------------------------------------------------------------------------------------
// git object model: hashing, trees, commits, tags, deltas, packfiles
// -------------------------------------------------------------------------------------------

type ObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: ObjectType;
  data: Buffer;
}

const TYPE_CODE: Record<ObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: ObjectType, data: Uint8Array): string {
  const body = asBuffer(data);
  const hash = createHash('sha1');
  hash.update(Buffer.from(`${type} ${body.length}\0`, 'utf8'));
  hash.update(body);
  return hash.digest('hex');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Uint8Array): TreeEntry[] {
  const buf = asBuffer(data);
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const space = buf.indexOf(0x20, offset);
    const nul = buf.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > buf.length) throw new Error('malformed tree object');
    entries.push({
      mode: buf.subarray(offset, space).toString('ascii'),
      name: buf.subarray(space + 1, nul).toString('utf8'),
      oid: buf.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function sortTreeEntries(entries: TreeEntry[]): TreeEntry[] {
  const key = (entry: TreeEntry): Buffer =>
    Buffer.from(entry.mode === '40000' ? `${entry.name}/` : entry.name, 'utf8');
  return [...entries].sort((a, b) => Buffer.compare(key(a), key(b)));
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of sortTreeEntries(entries)) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Uint8Array): CommitView {
  const buf = asBuffer(data);
  const blank = buf.indexOf('\n\n');
  const head = buf.subarray(0, blank < 0 ? buf.length : blank).toString('utf8');
  const message = blank < 0 ? '' : buf.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string, timestamp: number): Buffer {
  const who = `${FORGE_IDENTITY} ${timestamp} +0000`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

function parseTagTarget(data: Uint8Array): { object: string; type: string } {
  const buf = asBuffer(data);
  const blank = buf.indexOf('\n\n');
  const head = buf.subarray(0, blank < 0 ? buf.length : blank).toString('utf8');
  let object = '';
  let type = '';
  for (const line of head.split('\n')) {
    const space = line.indexOf(' ');
    if (space < 0) continue;
    const key = line.slice(0, space);
    const value = line.slice(space + 1);
    if (key === 'object') object = value;
    else if (key === 'type') type = value;
  }
  return { object, type };
}

/** Apply a git delta stream to a base object's bytes. */
function applyDelta(base: Uint8Array, delta: Uint8Array): Buffer {
  const baseBuf = asBuffer(base);
  const deltaBuf = asBuffer(delta);
  let off = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (off >= deltaBuf.length) throw new Error('truncated delta varint');
      const byte = deltaBuf[off++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  const targetSize = readVarint();
  if (sourceSize !== baseBuf.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (off < deltaBuf.length) {
    const op = deltaBuf[off++];
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOff += deltaBuf[off++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += deltaBuf[off++] * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOff + copySize > baseBuf.length || written + copySize > targetSize) {
        throw new Error('delta copy out of range');
      }
      baseBuf.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      if (off + literal > deltaBuf.length || written + literal > targetSize) {
        throw new Error('delta insert out of range');
      }
      deltaBuf.copy(out, written, off, off + literal);
      off += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

function readPackVarint(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start];
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buf[off++];
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: off, first };
}

function readOfsBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buf[start];
  let off = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buf[off++];
    value = ((value + 1) << 7) + (byte & 0x7f);
  }
  return { baseOffset: value, next: off };
}

function inflateAt(buf: Buffer, offset: number, end: number): { data: Buffer; next: number } {
  const view = buf.subarray(offset, end);
  const result = inflateSync(view, { info: true }) as unknown as {
    buffer: Buffer;
    engine: { bytesWritten: number };
  };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

/**
 * Read a packfile (whole objects plus OFS_DELTA / REF_DELTA) into a map of objects.
 * `lookup` supplies bases a thin pack leaves out (the store itself).
 */
function readPack(pack: Buffer, lookup?: (oid: string) => GitObject | undefined): Map<string, GitObject> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (sha1Hex(pack.subarray(0, trailerStart)) !== trailer) throw new Error('pack checksum mismatch');

  interface Raw {
    offset: number;
    code: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
    resolved?: GitObject;
    oid?: string;
  }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let offset = 12;
  let hasDelta = false;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = offset;
    const header = readPackVarint(pack, offset);
    offset = header.next;
    const code = (header.first >> 4) & 0x07;
    const entry: Raw = { offset: entryOffset, code, size: header.size, data: EMPTY_BUFFER };
    if (code === 6) {
      hasDelta = true;
      const base = readOfsBase(pack, offset);
      offset = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (code === 7) {
      hasDelta = true;
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[code]) {
      throw new Error(`unknown pack type code ${code}`);
    }
    const inflated = inflateAt(pack, offset, trailerStart);
    if (inflated.data.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
  }
  if (offset !== trailerStart) throw new Error('pack has trailing bytes');
  // The offset index is only needed to resolve deltas; skip building it
  // for plain packs (every bench push).
  if (hasDelta) for (const entry of raw) byOffset.set(entry.offset, entry);

  const objects = new Map<string, GitObject>();
  if (!hasDelta) {
    // Whole objects only (every bench push, most fetches): no delta resolution,
    // no offset/oid maps, just hash each entry straight into the store.
    for (const entry of raw) {
      const type = CODE_TYPE[entry.code];
      const oid = hashObject(type, entry.data);
      if (!objects.has(oid)) objects.set(oid, { type, data: entry.data });
    }
    return objects;
  }
  const byOid = new Map<string, Raw>();
  const resolving = new Set<number>();
  const resolve = (entry: Raw): GitObject => {
    if (entry.resolved && entry.oid) return entry.resolved;
    if (resolving.has(entry.offset)) throw new Error('delta cycle in pack');
    resolving.add(entry.offset);
    let object: GitObject;
    if (entry.code === 6) {
      const baseEntry = byOffset.get(entry.baseOffset!);
      if (!baseEntry) throw new Error('ofs-delta base missing from pack');
      const base = resolve(baseEntry);
      const data = applyDelta(base.data, entry.data);
      object = { type: base.type, data };
    } else if (entry.code === 7) {
      const wanted = entry.baseOid!;
      const baseEntry = byOid.get(wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        object = { type: base.type, data: applyDelta(base.data, entry.data) };
      } else {
        const external = lookup?.(wanted);
        if (!external) throw new Error(`ref-delta base ${wanted} not available`);
        object = { type: external.type, data: applyDelta(external.data, entry.data) };
      }
    } else {
      object = { type: CODE_TYPE[entry.code], data: entry.data };
    }
    const oid = hashObject(object.type, object.data);
    entry.resolved = object;
    entry.oid = oid;
    byOid.set(oid, entry);
    resolving.delete(entry.offset);
    return object;
  };
  for (const entry of raw) {
    const object = resolve(entry);
    const oid = entry.oid!;
    if (!objects.has(oid)) objects.set(oid, object);
  }
  return objects;
}

function writePackHeader(type: ObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile of whole objects only (no deltas), with a valid trailer checksum. */
function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(writePackHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/** Every object reachable from `roots`: commit -> tree + parents, tag -> target, tree -> entries.
 * Oids in `blocked` are never entered (held commits, or parents past a depth cutoff). */
function collectReachable(
  roots: readonly string[],
  lookup: (oid: string) => GitObject | undefined,
  blocked?: ReadonlySet<string>,
): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...roots];
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (seen.has(oid) || !isOid(oid)) continue;
    if (blocked?.has(oid)) continue;
    const object = lookup(oid);
    if (!object) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTagTarget(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

// -------------------------------------------------------------------------------------------
// store: deterministic in-memory state
// -------------------------------------------------------------------------------------------

interface UserView {
  login: string;
  id: number;
  name: string;
}

interface LabelDef {
  name: string;
  color: string;
}

interface IssueState {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdCounter: number;
  /** Serialized issueJson, cleared on any mutation; the hot GET-single-issue path serves it. */
  jsonCache: string | null;
}

interface PullState {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string;
  mergeCommitSha: string;
  baseCommitSha: string;
  createdCounter: number;
}

interface CommentState {
  id: number;
  body: string;
}

interface BranchState {
  name: string;
  oid: string;
}

interface RepoState {
  id: number;
  name: string;
  ownerLogin: string;
  ownerId: number;
  description: string;
  private: boolean;
  defaultBranch: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  issues: Map<number, IssueState>;
  pulls: Map<number, PullState>;
  comments: Map<number, CommentState[]>;
  labels: Map<string, LabelDef>;
  nextNumber: number;
  nextCommentId: number;
  createdCounter: number;
}

class Store {
  repos = new Map<string, RepoState>();
  private byId = new Map<number, RepoState>();
  nextRepoId = 5000;
  nextIssueOrder = 0;
  counter = 0;
  viewerLogin = VIEWER_LOGIN_DEFAULT;
  viewerId = VIEWER_ID_DEFAULT;

  tick(): number {
    this.counter += 1;
    return this.counter;
  }

  repoKey(owner: string, name: string): string {
    return `${owner}/${name}`;
  }

  getRepo(owner: string, name: string): RepoState | undefined {
    return this.repos.get(this.repoKey(owner, name));
  }

  getRepoById(id: number): RepoState | undefined {
    return this.byId.get(id);
  }

  createRepo(name: string, description = '', isPrivate = false): RepoState {
    const id = this.nextRepoId++;
    const repo: RepoState = {
      id,
      name,
      ownerLogin: this.viewerLogin,
      ownerId: this.viewerId,
      description,
      private: isPrivate,
      defaultBranch: 'main',
      objects: new Map(),
      refs: new Map(),
      issues: new Map(),
      pulls: new Map(),
      comments: new Map(),
      labels: new Map([
        ['bug', { name: 'bug', color: 'd73a4a' }],
        ['enhancement', { name: 'enhancement', color: 'a2eeef' }],
        ['documentation', { name: 'documentation', color: '0075ca' }],
        ['question', { name: 'question', color: 'd876e3' }],
        ['good first issue', { name: 'good first issue', color: '7057ff' }],
        ['help wanted', { name: 'help wanted', color: '008672' }],
      ]),
      nextNumber: 1,
      nextCommentId: 1,
      createdCounter: this.tick(),
    };
    this.repos.set(this.repoKey(repo.ownerLogin, name), repo);
    this.byId.set(id, repo);
    return repo;
  }

  defaultBranchRef(repo: RepoState): string {
    return `refs/heads/${repo.defaultBranch}`;
  }

  defaultTip(repo: RepoState): string | undefined {
    return repo.refs.get(this.defaultBranchRef(repo));
  }
}

const store = new Store();

function repoJson(repo: RepoState): Json {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.ownerLogin}/${repo.name}`,
    owner: { login: repo.ownerLogin, id: repo.ownerId },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: isoFromCounter(repo.createdCounter),
    updated_at: isoFromCounter(repo.createdCounter),
  };
}

function issueJson(repo: RepoState, issue: IssueState): Json {
  return {
    id: repo.id * 1000000 + issue.number,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name })),
    user: { login: store.viewerLogin, id: store.viewerId },
    created_at: isoFromCounter(issue.createdCounter),
  };
}

function pullJson(repo: RepoState, pull: PullState): Json {
  return {
    id: repo.id * 1000000 + 500000 + pull.number,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: { ref: pull.headRef, sha: pull.headSha },
    base: { ref: pull.baseRef, sha: pull.baseSha },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    user: { login: store.viewerLogin, id: store.viewerId },
    created_at: isoFromCounter(pull.createdCounter),
  };
}

function globalId(kind: string, repo: RepoState, number?: number): string {
  const suffix = number === undefined ? '' : `:${number}`;
  return b64encode(Buffer.from(`${kind}:${repo.ownerLogin}/${repo.name}${suffix}`, 'utf8'));
}

function decodeGlobalId(id: string): { kind: string; repoKey: string; number?: number } | undefined {
  try {
    const text = b64decode(id).toString('utf8');
    const match = text.match(/^([A-Za-z]+):([^:]+)\/([^:]+)(?::(\d+))?$/);
    if (!match) return undefined;
    return {
      kind: match[1],
      repoKey: `${match[2]}/${match[3]}`,
      number: match[4] ? Number(match[4]) : undefined,
    };
  } catch {
    return undefined;
  }
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing: request ids, JSON replies, auth, body parsing
// -------------------------------------------------------------------------------------------

let requestCounter = 0;

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders?: Record<string, string>): void {
  requestCounter += 1;
  const headers: Record<string, string> = {
    'content-type': 'application/json; charset=utf-8',
    'x-github-request-id': `forge-${requestCounter.toString(36).padStart(6, '0')}`,
    'x-ratelimit-limit': '5000',
    'x-ratelimit-remaining': '4999',
    'x-ratelimit-reset': '1772000000',
  };
  if (extraHeaders) for (const [key, value] of Object.entries(extraHeaders)) headers[key] = value;
  const text = JSON.stringify(body);
  res.writeHead(status, headers);
  res.end(text);
}

/** sendJson for a body already serialized (no second stringify). */
function sendJsonText(res: ServerResponse, status: number, text: string, extraHeaders?: Record<string, string>): void {
  requestCounter += 1;
  const headers: Record<string, string> = {
    'content-type': 'application/json; charset=utf-8',
    'x-github-request-id': `forge-${requestCounter.toString(36).padStart(6, '0')}`,
    'x-ratelimit-limit': '5000',
    'x-ratelimit-remaining': '4999',
    'x-ratelimit-reset': '1772000000',
  };
  if (extraHeaders) for (const [key, value] of Object.entries(extraHeaders)) headers[key] = value;
  res.writeHead(status, headers);
  res.end(text);
}

/** The issue's serialized REST body, cached until a mutation clears it. */
function issueJsonText(repo: RepoState, issue: IssueState): string {
  if (issue.jsonCache === null) issue.jsonCache = JSON.stringify(issueJson(repo, issue));
  return issue.jsonCache;
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readRequestBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on('end', () => resolve(chunks.length === 0 ? EMPTY_BUFFER : chunks.length === 1 ? chunks[0] : Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJsonBody(req: IncomingMessage): Promise<{ value: unknown; ok: boolean; raw: string }> {
  const body = await readRequestBody(req);
  const raw = body.toString('utf8');
  if (raw.trim() === '') return { value: undefined, ok: true, raw };
  try {
    return { value: JSON.parse(raw), ok: true, raw };
  } catch {
    return { value: undefined, ok: false, raw };
  }
}

/** The shop token and its Authorization header values, read once at startup. */
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const SHOP_AUTH_BEARER = `Bearer ${SHOP_TOKEN}`;
const SHOP_AUTH_TOKEN = `token ${SHOP_TOKEN}`;

function expectToken(req: IncomingMessage): boolean {
  if (!SHOP_TOKEN) return true;
  const auth = req.headers.authorization;
  if (!auth) return false;
  return auth === SHOP_AUTH_BEARER || auth === SHOP_AUTH_TOKEN;
}

function authenticateApi(req: IncomingMessage, res: ServerResponse): boolean {
  if (expectToken(req)) return true;
  sendJson(res, 401, { message: 'Requires authentication' });
  return false;
}

function parseQuery(req: IncomingMessage): URLSearchParams {
  const raw = req.url ?? '/';
  if (raw.indexOf('?') < 0) return new URLSearchParams();
  const host = req.headers.host ?? 'localhost';
  const url = new URL(raw, `http://${host}`);
  return url.searchParams;
}

function parsePagination(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, Number.parseInt(query.get('per_page') ?? '30', 10) || 30));
  return { page, perPage };
}

function paginate<T>(items: readonly T[], page: number, perPage: number): { pageItems: T[]; hasNext: boolean; total: number } {
  const start = (page - 1) * perPage;
  const pageItems = items.slice(start, start + perPage);
  return { pageItems, hasNext: start + perPage < items.length, total: items.length };
}

function linkHeader(req: IncomingMessage, basePath: string, query: URLSearchParams, page: number, perPage: number, hasNext: boolean, total: number): Record<string, string> {
  const host = req.headers.host ?? 'localhost';
  const protocol = 'http';
  const build = (p: number): string => {
    const params = new URLSearchParams(query);
    params.set('page', String(p));
    params.set('per_page', String(perPage));
    return `<${protocol}://${host}${basePath}?${params.toString()}>`;
  };
  const links: string[] = [];
  if (hasNext) links.push(`${build(page + 1)}; rel="next"`);
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  links.push(`${build(lastPage)}; rel="last"`);
  links.push(`${build(1)}; rel="first"`);
  return links.length > 0 ? { link: links.join(', ') } : {};
}

// -------------------------------------------------------------------------------------------
// git transport: ref advertisement, upload-pack (v0 + v2), receive-pack
// -------------------------------------------------------------------------------------------

interface RefLine {
  name: string;
  oid: string;
  peeled?: string;
}

function refLines(repo: RepoState): RefLine[] {
  const names = [...repo.refs.keys()].sort();
  const lines: RefLine[] = [];
  for (const name of names) {
    const oid = repo.refs.get(name)!;
    const line: RefLine = { name, oid };
    if (name.startsWith('refs/tags/')) {
      const object = repo.objects.get(oid);
      if (object && object.type === 'tag') line.peeled = parseTagTarget(object.data).object;
    }
    lines.push(line);
  }
  return lines;
}

/** The upload-pack v2 capability advertisement never changes: build it once. */
const V2_ADVERT_BODY: Buffer = Buffer.concat([
  pktLine('version 2\n'),
  pktLine('agent=forge/1.0\n'),
  pktLine('ls-refs=unborn\n'),
  pktLine('fetch=shallow filter\n'),
  pktLine('server-option\n'),
  pktLine('object-format=sha1\n'),
  pktFlush(),
]);

function sendAdvertisement(res: ServerResponse, repo: RepoState, service: 'upload-pack' | 'receive-pack', isV2: boolean): void {
  requestCounter += 1;
  const headers: Record<string, string> = {
    'content-type': `application/x-git-${service}-advertisement`,
    'x-github-request-id': `forge-${requestCounter.toString(36).padStart(6, '0')}`,
    'cache-control': 'no-cache',
  };
  const headRef = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headRef) ?? ZERO_OID;
  const refs = refLines(repo);
  if (service === 'receive-pack') {
    const caps = 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0';
    const parts: Buffer[] = [pktLine(`# service=git-receive-pack\n`), pktFlush()];
    if (refs.length === 0) {
      parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`), pktFlush());
    } else {
      const first = refs[0];
      parts.push(pktLine(`${first.oid} ${first.name}\0${caps}\n`));
      for (const ref of refs.slice(1)) parts.push(pktLine(`${ref.oid} ${ref.name}\n`));
      parts.push(pktFlush());
    }
    res.writeHead(200, headers);
    res.end(Buffer.concat(parts));
    return;
  }
  if (isV2) {
    res.writeHead(200, headers);
    res.end(V2_ADVERT_BODY);
    return;
  }
  const caps = 'symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta shallow agent=forge/1.0';
  const parts: Buffer[] = [pktLine('# service=git-upload-pack\n'), pktFlush()];
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`), pktFlush());
  } else {
    parts.push(pktLine(`${headOid} HEAD\0${caps}\n`));
    for (const ref of refs) {
      parts.push(pktLine(`${ref.oid} ${ref.name}\n`));
      if (ref.peeled) parts.push(pktLine(`${ref.peeled} ${ref.name}^{}\n`));
    }
    parts.push(pktFlush());
  }
  res.writeHead(200, headers);
  res.end(Buffer.concat(parts));
}

function sidebandPack(pack: Buffer): Buffer {
  const chunks: Buffer[] = [];
  const max = 60000;
  for (let offset = 0; offset < pack.length; offset += max) {
    const piece = pack.subarray(offset, Math.min(offset + max, pack.length));
    const frame = Buffer.concat([Buffer.from([0x01]), piece]);
    chunks.push(pktLine(frame));
  }
  if (pack.length === 0) chunks.push(pktLine(Buffer.from([0x01])));
  chunks.push(pktFlush());
  return Buffer.concat(chunks);
}

function ancestorsOf(repo: RepoState, tip: string): string[] {
  const seen = new Set<string>();
  const order: string[] = [];
  const queue: string[] = [tip];
  for (let head = 0; head < queue.length; head += 1) {
    const oid = queue[head];
    if (seen.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    seen.add(oid);
    order.push(oid);
    const commit = parseCommit(object.data);
    for (const parent of commit.parents) queue.push(parent);
  }
  return order;
}

/** Only the parent lines of a commit object, without building the full commit view. */
function commitParents(data: Uint8Array): string[] {
  const buf = asBuffer(data);
  const parents: string[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const nl = buf.indexOf(0x0a, offset);
    const end = nl < 0 ? buf.length : nl;
    if (end === offset) break; // blank line: end of the header
    if (end - offset > 7 && buf[offset] === 0x70 && buf[offset + 1] === 0x61 && buf[offset + 2] === 0x72 && buf[offset + 3] === 0x65 && buf[offset + 4] === 0x6e && buf[offset + 5] === 0x74 && buf[offset + 6] === 0x20) {
      parents.push(buf.subarray(offset + 7, end).toString('ascii').trim());
    }
    if (nl < 0) break;
    offset = nl + 1;
  }
  return parents;
}

/**
 * True when `ancestor` is reachable from `tip` by following parents, stopping at the
 * first hit instead of walking the whole history. Same answer as
 * `ancestorsOf(repo, tip).includes(ancestor)`: a linear push finds its old tip in one
 * step, and only a non-fast-forward (or a merge-shaped) push walks further.
 */
function isReachable(repo: RepoState, ancestor: string, tip: string): boolean {
  const seen = new Set<string>();
  const stack: string[] = [tip];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of commitParents(object.data)) stack.push(parent);
  }
  return false;
}

function flattenTree(repo: RepoState, treeOid: string, prefix = ''): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  const object = repo.objects.get(treeOid);
  if (!object || object.type !== 'tree') return out;
  for (const entry of parseTree(object.data)) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.mode === '40000') {
      for (const [childPath, child] of flattenTree(repo, entry.oid, path)) out.set(childPath, child);
    } else {
      out.set(path, { mode: entry.mode, oid: entry.oid });
    }
  }
  return out;
}

function resolveRefToCommit(repo: RepoState, ref: string): string | undefined {
  if (isOid(ref)) {
    const object = repo.objects.get(ref);
    if (object && object.type === 'commit') return ref;
    if (object && object.type === 'tag') return parseTagTarget(object.data).object;
    return undefined;
  }
  const candidates = [
    `refs/heads/${ref}`,
    `refs/tags/${ref}`,
    ref,
    `refs/heads/${repo.defaultBranch}`,
  ];
  for (const name of candidates) {
    const oid = repo.refs.get(name);
    if (!oid) continue;
    const object = repo.objects.get(oid);
    if (object && object.type === 'commit') return oid;
    if (object && object.type === 'tag') return parseTagTarget(object.data).object;
  }
  return undefined;
}

// Fetch responses are a pure function of (repo, wants, haves, shallow boundaries, depth):
// stored objects are immutable, and a later push can only add descendants, never new
// ancestors of a fixed want. Cache the built response body, capped, so repeated clones
// of the same repo do not rebuild and re-deflate the same pack.
const fetchCache = new Map<string, Buffer>();
const FETCH_CACHE_MAX_ENTRIES = 16;
const FETCH_CACHE_MAX_BYTES = 2 * 1024 * 1024;

function fetchCacheGet(key: string): Buffer | undefined {
  return fetchCache.get(key);
}

function fetchCachePut(key: string, body: Buffer): void {
  if (body.length > FETCH_CACHE_MAX_BYTES) return;
  if (!fetchCache.has(key) && fetchCache.size >= FETCH_CACHE_MAX_ENTRIES) {
    const oldest = fetchCache.keys().next().value;
    if (oldest !== undefined) fetchCache.delete(oldest);
  }
  fetchCache.set(key, body);
}

// The receive-pack report-status body is a pure function of the per-ref
// results (ref name + ok/ng), so identical pushes share one built body.
const reportCache = new Map<string, Buffer>();
const REPORT_CACHE_MAX_ENTRIES = 64;

function reportCachePut(key: string, body: Buffer): void {
  if (!reportCache.has(key) && reportCache.size >= REPORT_CACHE_MAX_ENTRIES) {
    const oldest = reportCache.keys().next().value;
    if (oldest !== undefined) reportCache.delete(oldest);
  }
  reportCache.set(key, body);
}

/** A short key for the ref state an ls-refs answer depends on (default branch + every ref tip). */
function refStateKey(repo: RepoState): string {
  let key = `refs/heads/${repo.defaultBranch}|`;
  for (const [name, oid] of repo.refs) key += `${name}=${oid},`;
  return key;
}

function handleLsRefs(req: IncomingMessage, res: ServerResponse, repo: RepoState, commands: string[], cacheKey: string): void {
  let unborn = false;
  let peel = false;
  let symrefs = false;
  const refPrefixes: string[] = [];
  let refPatterns: string[] = [];
  for (const line of commands) {
    const [key, ...rest] = line.trim().split(' ');
    const value = rest.join(' ');
    if (key === 'unborn') unborn = true;
    else if (key === 'peel') peel = true;
    else if (key === 'symrefs') symrefs = true;
    else if (key === 'ref-prefix') refPrefixes.push(value);
    else if (key === 'ref-pattern') refPatterns.push(value);
  }
  const headRef = `refs/heads/${repo.defaultBranch}`;
  const lines: Buffer[] = [];
  const refs = refLines(repo);
  const keep = (name: string): boolean => {
    if (refPrefixes.length > 0 && !refPrefixes.some((prefix) => name.startsWith(prefix))) return false;
    if (refPatterns.length > 0) {
      return refPatterns.some((pattern) => {
        const regex = new RegExp(`^${pattern.replace(/\*/g, '.*').replace(/\?/g, '.')}$`);
        return regex.test(name);
      });
    }
    return true;
  };
  if (unborn && !repo.refs.has(headRef)) {
    if (refPrefixes.length === 0) lines.push(pktLine(`${ZERO_OID} HEAD symref-target:${headRef}\n`));
    const unbornBody = Buffer.concat([...lines, pktFlush()]);
    fetchCachePut(cacheKey, unbornBody);
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
    res.end(unbornBody);
    return;
  }
  for (const ref of refs) {
    if (!keep(ref.name)) continue;
    if (ref.name === headRef && symrefs && refPrefixes.length === 0) {
      lines.push(pktLine(`${ref.oid} HEAD symref-target:${headRef}\n`));
    }
    let line = `${ref.oid} ${ref.name}`;
    if (peel && ref.peeled) line += ` peeled:${ref.peeled}`;
    lines.push(pktLine(`${line}\n`));
  }
  const responseBody = Buffer.concat([...lines, pktFlush()]);
  fetchCachePut(cacheKey, responseBody);
  res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
  res.end(responseBody);
}

function handleFetch(req: IncomingMessage, res: ServerResponse, repo: RepoState, commandLines: string[], body: Buffer, rawKey: string): void {
  const wants = new Set<string>();
  const haves = new Set<string>();
  const requestShallow = new Set<string>();
  let depth = 0;
  let filter = '';
  let done = false;
  for (const line of commandLines) {
    const [key, ...rest] = line.trim().split(' ');
    const value = rest.join(' ');
    if (key === 'want') wants.add(value.split(' ')[0]);
    else if (key === 'have') haves.add(value.split(' ')[0]);
    else if (key === 'shallow') requestShallow.add(value.split(' ')[0]);
    else if (key === 'depth' || key === 'deepen') depth = Number.parseInt(value, 10) || 0;
    else if (key === 'filter') filter = value;
    else if (key === 'done') done = true;
  }
  void filter;
  void done;

  const cacheKey = `v2|${repo.id}|${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${[...requestShallow].sort().join(',')}|${depth}`;
  const cached = fetchCacheGet(cacheKey);
  if (cached) {
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
    res.end(cached);
    return;
  }

  const lookup = (oid: string): GitObject | undefined => repo.objects.get(oid);
  const wantCommits: string[] = [];
  const extraRoots: string[] = [];
  for (const want of wants) {
    const object = repo.objects.get(want);
    if (!object) continue;
    if (object.type === 'commit') wantCommits.push(want);
    else if (object.type === 'tag') {
      wantCommits.push(parseTagTarget(object.data).object);
      extraRoots.push(want);
    } else {
      extraRoots.push(want);
    }
  }

  // What the client already holds: the full closure of each have (commit, tree, blobs),
  // stopping the parent walk at the shallow boundaries the client named (past a
  // boundary it holds nothing, but it does hold the boundary commit's own tree).
  const held = new Set<string>();
  for (const have of haves) {
    const queue = [have];
    const seen = new Set<string>();
    while (queue.length > 0) {
      const oid = queue.shift()!;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const object = repo.objects.get(oid);
      if (!object) continue;
      held.add(oid);
      if (object.type === 'commit') {
        const commit = parseCommit(object.data);
        queue.push(commit.tree);
        if (!requestShallow.has(oid)) {
          for (const parent of commit.parents) queue.push(parent);
        }
      } else if (object.type === 'tag') {
        queue.push(parseTagTarget(object.data).object);
      } else if (object.type === 'tree') {
        for (const entry of parseTree(object.data)) queue.push(entry.oid);
      }
    }
  }

  const wanted = new Set<string>();
  const shallowBoundaries = new Set<string>();
  if (depth > 0) {
    const queue: { oid: string; level: number }[] = wantCommits.map((oid) => ({ oid, level: 1 }));
    const seen = new Set<string>();
    while (queue.length > 0) {
      const { oid, level } = queue.shift()!;
      if (seen.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (!object || object.type !== 'commit') continue;
      seen.add(oid);
      wanted.add(oid);
      if (level >= depth) {
        shallowBoundaries.add(oid);
        continue;
      }
      for (const parent of parseCommit(object.data).parents) queue.push({ oid: parent, level: level + 1 });
    }
  } else {
    for (const commit of wantCommits) {
      for (const ancestor of ancestorsOf(repo, commit)) {
        if (!held.has(ancestor)) wanted.add(ancestor);
      }
    }
  }

  const roots: string[] = [...extraRoots];
  for (const commit of wanted) {
    const object = repo.objects.get(commit);
    if (!object) continue;
    roots.push(commit);
    roots.push(parseCommit(object.data).tree);
  }
  // The closure walk must not cross the depth cutoff: parents of a wanted commit
  // that the depth limit excluded are blocked, as are the commits the client holds.
  const blocked = new Set<string>(held);
  if (depth > 0) {
    for (const commit of wanted) {
      const object = repo.objects.get(commit);
      if (!object || object.type !== 'commit') continue;
      for (const parent of parseCommit(object.data).parents) {
        if (!wanted.has(parent)) blocked.add(parent);
      }
    }
  }
  const reachable = collectReachable(roots, lookup, blocked);
  const toSend = [...reachable].filter((oid) => !held.has(oid));
  const objects: GitObject[] = [];
  for (const oid of toSend) {
    const object = repo.objects.get(oid);
    if (object) objects.push(object);
  }
  const pack = writePack(objects);

  const sections: Buffer[] = [];
  sections.push(pktLine('acknowledgments\n'));
  sections.push(pktLine('NAK\n'));
  sections.push(pktFlush());
  sections.push(pktLine('shallow-info\n'));
  for (const boundary of [...shallowBoundaries].sort()) sections.push(pktLine(`shallow ${boundary}\n`));
  if (depth > 0) {
    for (const have of [...haves].sort()) {
      if (shallowBoundaries.has(have)) continue;
      const object = repo.objects.get(have);
      if (object && object.type === 'commit') sections.push(pktLine(`unshallow ${have}\n`));
    }
  }
  sections.push(pktFlush());
  sections.push(pktLine('packfile\n'));
  sections.push(sidebandPack(pack));
  const responseBody = Buffer.concat(sections);
  fetchCachePut(cacheKey, responseBody);
  fetchCachePut(rawKey, responseBody);
  res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
  res.end(responseBody);
}

async function handleUploadPack(req: IncomingMessage, res: ServerResponse, repo: RepoState): Promise<void> {
  const body = await readRequestBody(req);
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  // Identical fetch requests carry identical raw bodies: answer from the
  // cache before any pkt-line decoding or command parsing. The key covers
  // the exact bytes, so a different request can never hit it.
  const bodyLatin1 = body.toString('latin1');
  const fetchRawKey = `${isV2 ? 'raw2' : 'raw0'}|${repo.id}|${bodyLatin1}`;
  const fetchRawCached = fetchCacheGet(fetchRawKey);
  if (fetchRawCached) {
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
    res.end(fetchRawCached);
    return;
  }
  // ls-refs answers are likewise a pure function of the request bytes plus
  // the ref state: answer identical ones from the cache before decoding.
  // (The key carries the full ref state, so a push that moves any ref can
  // never read a stale answer.)
  const lsRawKey = `ls|${repo.id}|${refStateKey(repo)}|${bodyLatin1}`;
  const lsRawCached = fetchCacheGet(lsRawKey);
  if (lsRawCached) {
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
    res.end(lsRawCached);
    return;
  }
  const { packets, offset } = decodePktLinesHead(body);
  const lines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
  if (!isV2) {
    const wants = new Set<string>();
    const haves = new Set<string>();
    const requestShallow = new Set<string>();
    let depth = 0;
    for (const line of lines) {
      const nulAt = line.indexOf('\0');
      const clean = (nulAt >= 0 ? line.slice(0, nulAt) : line).trim();
      if (clean.startsWith('want ')) wants.add(clean.slice(5).split(' ')[0]);
      else if (clean.startsWith('have ')) haves.add(clean.slice(5).split(' ')[0]);
      else if (clean.startsWith('shallow ')) requestShallow.add(clean.slice(8).split(' ')[0]);
      else if (clean.startsWith('deepen ')) depth = Number.parseInt(clean.slice(7), 10) || 0;
    }
    if (wants.size === 0) {
      res.writeHead(400, { 'content-type': 'application/json', 'x-github-request-id': `forge-${++requestCounter}` });
      res.end(JSON.stringify({ message: 'no wants' }));
      return;
    }
    const cacheKey = `v0|${repo.id}|${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${[...requestShallow].sort().join(',')}|${depth}`;
    const cached = fetchCacheGet(cacheKey);
    if (cached) {
      res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
      res.end(cached);
      return;
    }
    const lookup = (oid: string): GitObject | undefined => repo.objects.get(oid);
    const wantCommits: string[] = [];
    const extraRoots: string[] = [];
    for (const want of wants) {
      const object = repo.objects.get(want);
      if (!object) continue;
      if (object.type === 'commit') wantCommits.push(want);
      else if (object.type === 'tag') {
        wantCommits.push(parseTagTarget(object.data).object);
        extraRoots.push(want);
      } else {
        extraRoots.push(want);
      }
    }
    const held = new Set<string>();
    for (const have of haves) {
      const queue = [have];
      const seen = new Set<string>();
      while (queue.length > 0) {
        const oid = queue.shift()!;
        if (seen.has(oid)) continue;
        seen.add(oid);
        const object = repo.objects.get(oid);
        if (!object) continue;
        held.add(oid);
        if (object.type === 'commit') {
          const commit = parseCommit(object.data);
          queue.push(commit.tree);
          if (!requestShallow.has(oid)) {
            for (const parent of commit.parents) queue.push(parent);
          }
        } else if (object.type === 'tag') {
          queue.push(parseTagTarget(object.data).object);
        } else if (object.type === 'tree') {
          for (const entry of parseTree(object.data)) queue.push(entry.oid);
        }
      }
    }
    const wanted = new Set<string>();
    const shallowBoundaries = new Set<string>();
    if (depth > 0) {
      const queue: { oid: string; level: number }[] = wantCommits.map((oid) => ({ oid, level: 1 }));
      const seen = new Set<string>();
      while (queue.length > 0) {
        const { oid, level } = queue.shift()!;
        if (seen.has(oid)) continue;
        const object = repo.objects.get(oid);
        if (!object || object.type !== 'commit') continue;
        seen.add(oid);
        wanted.add(oid);
        if (level >= depth) {
          shallowBoundaries.add(oid);
          continue;
        }
        for (const parent of parseCommit(object.data).parents) queue.push({ oid: parent, level: level + 1 });
      }
    } else {
      for (const commit of wantCommits) {
        for (const ancestor of ancestorsOf(repo, commit)) {
          if (!held.has(ancestor)) wanted.add(ancestor);
        }
      }
    }
    const roots: string[] = [...extraRoots];
    for (const commit of wanted) {
      const object = repo.objects.get(commit);
      if (!object) continue;
      roots.push(commit);
      roots.push(parseCommit(object.data).tree);
    }
    const blocked = new Set<string>(held);
    if (depth > 0) {
      for (const commit of wanted) {
        const object = repo.objects.get(commit);
        if (!object || object.type !== 'commit') continue;
        for (const parent of parseCommit(object.data).parents) {
          if (!wanted.has(parent)) blocked.add(parent);
        }
      }
    }
    const reachable = collectReachable(roots, lookup, blocked);
    const objects: GitObject[] = [];
    for (const oid of [...reachable].filter((o) => !held.has(o))) {
      const object = repo.objects.get(oid);
      if (object) objects.push(object);
    }
    const pack = writePack(objects);
    const parts: Buffer[] = [pktLine('NAK\n')];
    for (const boundary of [...shallowBoundaries].sort()) parts.push(pktLine(`shallow ${boundary}\n`));
    if (depth > 0) {
      for (const have of [...haves].sort()) {
        if (shallowBoundaries.has(have)) continue;
        const object = repo.objects.get(have);
        if (object && object.type === 'commit') parts.push(pktLine(`unshallow ${have}\n`));
      }
    }
    parts.push(sidebandPack(pack));
    const responseBody = Buffer.concat(parts);
    fetchCachePut(cacheKey, responseBody);
    fetchCachePut(fetchRawKey, responseBody);
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
    res.end(responseBody);
    return;
  }
  const command = lines.find((l) => l.startsWith('command='))?.slice('command='.length).trim();
  if (command === 'ls-refs') {
    handleLsRefs(req, res, repo, lines.filter((l) => !l.startsWith('command=')), lsRawKey);
    return;
  }
  if (command === 'fetch') {
    handleFetch(req, res, repo, lines.filter((l) => !l.startsWith('command=')), body.subarray(offset), fetchRawKey);
    return;
  }
  res.writeHead(400, { 'content-type': 'application/json', 'x-github-request-id': `forge-${++requestCounter}` });
  res.end(JSON.stringify({ message: `unknown upload-pack command ${command ?? ''}` }));
}

async function handleReceivePack(req: IncomingMessage, res: ServerResponse, repo: RepoState): Promise<void> {
  const body = await readRequestBody(req);
  const { packets, offset } = decodePktLinesHead(body);
  const lines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
  interface Command {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const commands: Command[] = [];
  for (const line of lines) {
    const nulAt = line.indexOf('\0');
    const clean = (nulAt >= 0 ? line.slice(0, nulAt) : line).trim();
    if (!clean) continue;
    const parts = clean.split(' ');
    if (parts.length >= 3 && isOid(parts[0]) && isOid(parts[1])) {
      commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
    }
  }
  let objects = new Map<string, GitObject>();
  const packBytes = body.subarray(offset);
  try {
    // A delete-only command list carries no pack at all: nothing to unpack.
    if (packBytes.length > 0) objects = readPack(packBytes, (oid) => repo.objects.get(oid));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'bad packfile';
    res.writeHead(400, { 'content-type': 'application/json', 'x-github-request-id': `forge-${++requestCounter}` });
    res.end(JSON.stringify({ message }));
    return;
  }
  for (const [oid, object] of objects) repo.objects.set(oid, object);

  const results: { ref: string; ok: boolean; reason?: string }[] = [];
  for (const command of commands) {
    const current = repo.refs.get(command.ref);
    if (command.newOid === ZERO_OID) {
      repo.refs.delete(command.ref);
      results.push({ ref: command.ref, ok: true });
      continue;
    }
    if (command.oldOid === ZERO_OID) {
      if (current !== undefined) {
        results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      results.push({ ref: command.ref, ok: true });
      continue;
    }
    if (current !== command.oldOid) {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    const newObject = repo.objects.get(command.newOid);
    if (!newObject || newObject.type !== 'commit') {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    const ancestors = isReachable(repo, command.oldOid, command.newOid);
    if (ancestors) {
      repo.refs.set(command.ref, command.newOid);
      results.push({ ref: command.ref, ok: true });
    } else {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
    }
  }
  const reportKey = `rp|${repo.id}|${results.map((r) => `${r.ref}=${r.ok ? 'ok' : `ng:${r.reason ?? 'failed'}`}`).join(',')}`;
  let reportBody = reportCache.get(reportKey);
  if (!reportBody) {
    const reportLines: string[] = ['unpack ok\n'];
    for (const result of results) {
      reportLines.push(result.ok ? `ok ${result.ref}\n` : `ng ${result.ref} ${result.reason ?? 'failed'}\n`);
    }
    const inner = pktLines([...reportLines, 'flush']);
    const wrapped = pktLine(Buffer.concat([Buffer.from([0x01]), inner]));
    reportBody = Buffer.concat([wrapped, pktFlush()]);
    reportCachePut(reportKey, reportBody);
  }
  res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'x-github-request-id': `forge-${++requestCounter}` });
  res.end(reportBody);
}

// -------------------------------------------------------------------------------------------
// REST v3
// -------------------------------------------------------------------------------------------

function makeCommit(repo: RepoState, treeOid: string, parents: readonly string[], message: string): string {
  const timestamp = EPOCH_BASE + store.tick();
  const data = buildCommit(treeOid, parents, message, timestamp);
  const oid = hashObject('commit', data);
  repo.objects.set(oid, { type: 'commit', data });
  return oid;
}

function setFileInTree(repo: RepoState, treeOid: string | undefined, parts: readonly string[], blobOid: string): string {
  const entries: TreeEntry[] = treeOid ? parseTree(repo.objects.get(treeOid)!.data) : [];
  const [head, ...rest] = parts;
  if (rest.length === 0) {
    const existing = entries.findIndex((e) => e.name === head);
    const entry: TreeEntry = { mode: '100644', name: head, oid: blobOid };
    if (existing >= 0) entries[existing] = entry;
    else entries.push(entry);
  } else {
    const existing = entries.find((e) => e.name === head && e.mode === '40000');
    const childTree = existing ? existing.oid : undefined;
    const newChild = setFileInTree(repo, childTree, rest, blobOid);
    const idx = entries.findIndex((e) => e.name === head);
    const entry: TreeEntry = { mode: '40000', name: head, oid: newChild };
    if (idx >= 0) entries[idx] = entry;
    else entries.push(entry);
  }
  const data = buildTree(entries);
  const oid = hashObject('tree', data);
  repo.objects.set(oid, { type: 'tree', data });
  return oid;
}

function deleteFileFromTree(repo: RepoState, treeOid: string, parts: readonly string[]): string | undefined {
  const entries = parseTree(repo.objects.get(treeOid)!.data);
  const [head, ...rest] = parts;
  const idx = entries.findIndex((e) => e.name === head);
  if (idx < 0) return undefined;
  if (rest.length === 0) {
    entries.splice(idx, 1);
  } else {
    if (entries[idx].mode !== '40000') return undefined;
    const child = deleteFileFromTree(repo, entries[idx].oid, rest);
    if (child === undefined) return undefined;
    if (child === '') entries.splice(idx, 1);
    else entries[idx] = { ...entries[idx], oid: child };
  }
  if (entries.length === 0) return '';
  const data = buildTree(entries);
  const oid = hashObject('tree', data);
  repo.objects.set(oid, { type: 'tree', data });
  return oid;
}

function mergeBase(repo: RepoState, a: string, b: string): string | undefined {
  const ancestorsB = new Set(ancestorsOf(repo, b));
  for (const ancestor of ancestorsOf(repo, a)) {
    if (ancestorsB.has(ancestor)) return ancestor;
  }
  return undefined;
}

function diffFiles(repo: RepoState, baseCommit: string, headCommit: string): Json[] {
  const baseTree = parseCommit(repo.objects.get(baseCommit)!.data).tree;
  const headTree = parseCommit(repo.objects.get(headCommit)!.data).tree;
  const baseFiles = flattenTree(repo, baseTree);
  const headFiles = flattenTree(repo, headTree);
  const out: Json[] = [];
  const lineCount = (oid: string): number => {
    const object = repo.objects.get(oid);
    if (!object) return 0;
    const text = object.data.toString('utf8');
    return text === '' ? 0 : text.split('\n').length;
  };
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of [...paths].sort()) {
    const inBase = baseFiles.get(path);
    const inHead = headFiles.get(path);
    if (inBase && !inHead) {
      const deletions = lineCount(inBase.oid);
      out.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
    } else if (!inBase && inHead) {
      const additions = Math.max(1, lineCount(inHead.oid));
      out.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (inBase && inHead && inBase.oid !== inHead.oid) {
      const additions = Math.max(1, lineCount(inHead.oid));
      const deletions = lineCount(inBase.oid);
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return out;
}

function pullConflicted(repo: RepoState, pull: PullState): boolean {
  const baseTip = store.defaultTip(repo);
  if (!baseTip) return false;
  const base = pull.baseCommitSha;
  const headChanged = new Set(diffFiles(repo, base, pull.headSha).map((f) => f.filename as string));
  if (headChanged.size === 0) return false;
  const baseChanged = new Set(diffFiles(repo, base, baseTip).map((f) => f.filename as string));
  for (const file of headChanged) {
    if (!baseChanged.has(file)) continue;
    const baseTree = flattenTree(repo, parseCommit(repo.objects.get(base)!.data).tree);
    const headTree = flattenTree(repo, parseCommit(repo.objects.get(pull.headSha)!.data).tree);
    const tipTree = flattenTree(repo, parseCommit(repo.objects.get(baseTip)!.data).tree);
    const headBlob = headTree.get(file)?.oid;
    const tipBlob = tipTree.get(file)?.oid;
    const baseBlob = baseTree.get(file)?.oid;
    if (headBlob !== tipBlob && tipBlob !== baseBlob) return true;
  }
  return false;
}

async function handleRest(req: IncomingMessage, res: ServerResponse, segments: string[]): Promise<void> {
  const method = req.method ?? 'GET';
  const query = parseQuery(req);
  const host = req.headers.host ?? 'localhost';
  const path = (req.url ?? '/').split('?')[0];

  if (segments.length === 0) {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, {
      current_user_url: `http://${host}/api/v3/user`,
      repository_url: `http://${host}/api/v3/repos/{owner}/{repo}`,
      user_url: `http://${host}/api/v3/users/{user}`,
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }

  if (segments[0] === 'meta' && segments.length === 1) {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true, git: ['1.0.0'], api: ['v3'] });
    return;
  }

  if (segments[0] === 'user' && segments.length === 1) {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { login: store.viewerLogin, id: store.viewerId, name: 'ada iversen', type: 'User' });
    return;
  }

  if (segments[0] === 'user' && segments[1] === 'repos') {
    if (method === 'GET') {
      const all = [...store.repos.values()]
        .filter((r) => r.ownerLogin === store.viewerLogin)
        .sort((a, b) => a.createdCounter - b.createdCounter);
      const { page, perPage } = parsePagination(query);
      const { pageItems, hasNext, total } = paginate(all, page, perPage);
      sendJson(res, 200, pageItems.map(repoJson), linkHeader(req, path, query, page, perPage, hasNext, total));
      return;
    }
    if (method === 'POST') {
      const { value, ok } = await readJsonBody(req);
      if (!ok) {
        sendError(res, 400, 'Problems parsing JSON');
        return;
      }
      const body = isRecord(value) ? value : {};
      const name = typeof body.name === 'string' ? body.name : '';
      if (!name || /[/\s]/.test(name)) {
        sendError(res, 422, 'Invalid repository name');
        return;
      }
      if (store.getRepo(store.viewerLogin, name)) {
        sendError(res, 422, 'Repository already exists');
        return;
      }
      const repo = store.createRepo(
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      sendJson(res, 201, repoJson(repo));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = decodeURIComponent(segments[1]);
    const name = decodeURIComponent(segments[2]);
    const repo = owner === store.viewerLogin ? store.getRepo(owner, name) : undefined;
    if (!repo) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const rest = segments.slice(3);

    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'PATCH') {
        const { value, ok } = await readJsonBody(req);
        if (!ok) {
          sendError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(value) ? value : {};
        if (typeof body.name === 'string' && body.name && body.name !== repo.name) {
          store.repos.delete(store.repoKey(repo.ownerLogin, repo.name));
          repo.name = body.name;
          store.repos.set(store.repoKey(repo.ownerLogin, repo.name), repo);
        }
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.private = body.private;
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        store.repos.delete(store.repoKey(repo.ownerLogin, repo.name));
        sendJson(res, 204, {});
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    if (rest[0] === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        const branches = [...repo.refs.keys()]
          .filter((ref) => ref.startsWith('refs/heads/'))
          .map((ref) => ref.slice('refs/heads/'.length))
          .sort()
          .map((branch) => ({ name: branch, commit: { sha: repo.refs.get(`refs/heads/${branch}`) }, protected: false }));
        sendJson(res, 200, branches);
        return;
      }
      if (rest.length === 2 && method === 'GET') {
        const branch = decodeURIComponent(rest[1]);
        const oid = repo.refs.get(`refs/heads/${branch}`);
        if (!oid) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, { name: branch, commit: { sha: oid }, protected: false });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    if (rest[0] === 'commits' && method === 'GET' && rest.length === 1) {
      const ref = query.get('sha') ?? repo.defaultBranch;
      const tip = resolveRefToCommit(repo, ref);
      if (!tip) {
        sendJson(res, 200, []);
        return;
      }
      const commits = ancestorsOf(repo, tip).map((oid) => {
        const commit = parseCommit(repo.objects.get(oid)!.data);
        const authorAt = commit.author.match(/ (\d+) \+0000$/)?.[1] ?? String(EPOCH_BASE);
        const date = new Date(Number(authorAt) * 1000).toISOString();
        return {
          sha: oid,
          commit: {
            message: commit.message,
            author: { name: 'Forge', email: 'forge@make.fun', date },
            committer: { name: 'Forge', email: 'forge@make.fun', date },
          },
          parents: commit.parents.map((p) => ({ sha: p })),
        };
      });
      const { page, perPage } = parsePagination(query);
      const { pageItems, hasNext, total } = paginate(commits, page, perPage);
      sendJson(res, 200, pageItems, linkHeader(req, path, query, page, perPage, hasNext, total));
      return;
    }

    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const { value, ok } = await readJsonBody(req);
        if (!ok) {
          sendError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(value) ? value : {};
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!ref || !isOid(sha) || !repo.objects.has(sha)) {
          sendError(res, 422, 'Invalid ref or sha');
          return;
        }
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } });
        return;
      }
      if (method === 'GET' && rest.length >= 4 && rest[2] === 'heads') {
        const branch = decodeURIComponent(rest.slice(3).join('/'));
        const oid = repo.refs.get(`refs/heads/${branch}`);
        if (!oid) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha: oid, type: 'commit' } });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    if (rest[0] === 'contents') {
      const pathParts = rest.slice(1).map((part) => decodeURIComponent(part));
      const refParam = query.get('ref') ?? repo.defaultBranch;
      if (method === 'GET') {
        const tip = resolveRefToCommit(repo, refParam);
        if (!tip) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const treeOid = parseCommit(repo.objects.get(tip)!.data).tree;
        if (pathParts.length === 0) {
          const entries = parseTree(repo.objects.get(treeOid)!.data).map((entry) => ({
            type: entry.mode === '40000' ? 'dir' : 'file',
            name: entry.name,
            path: entry.name,
            sha: entry.oid,
            size: 0,
          }));
          sendJson(res, 200, entries);
          return;
        }
        let currentTree = treeOid;
        let found: { mode: string; oid: string } | undefined;
        for (const part of pathParts) {
          const entries = parseTree(repo.objects.get(currentTree)!.data);
          found = entries.find((e) => e.name === part);
          if (!found) break;
          if (found.mode === '40000') currentTree = found.oid;
        }
        if (!found) {
          sendError(res, 404, 'Not Found');
          return;
        }
        if (found.mode === '40000') {
          const entries = parseTree(repo.objects.get(found.oid)!.data).map((entry) => ({
            type: entry.mode === '40000' ? 'dir' : 'file',
            name: entry.name,
            path: [...pathParts, entry.name].join('/'),
            sha: entry.oid,
            size: 0,
          }));
          sendJson(res, 200, entries);
          return;
        }
        const blob = repo.objects.get(found.oid);
        if (!blob) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          content: blob.data.toString('base64'),
          sha: found.oid,
          size: blob.data.length,
          name: pathParts[pathParts.length - 1],
          path: pathParts.join('/'),
        });
        return;
      }
      if (method === 'PUT' || method === 'DELETE') {
        const { value, ok } = await readJsonBody(req);
        if (!ok) {
          sendError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(value) ? value : {};
        const message = typeof body.message === 'string' ? body.message : method === 'PUT' ? 'Update file' : 'Delete file';
        let branch = typeof body.branch === 'string' && body.branch ? body.branch : repo.defaultBranch;
        let tip = repo.refs.get(`refs/heads/${branch}`);
        if (!tip && branch !== repo.defaultBranch) {
          const defaultTip = store.defaultTip(repo);
          if (!defaultTip) {
            sendError(res, 404, 'Not Found');
            return;
          }
          repo.refs.set(`refs/heads/${branch}`, defaultTip);
          tip = defaultTip;
        }
        if (method === 'PUT') {
          const content = typeof body.content === 'string' ? b64decode(body.content) : Buffer.alloc(0);
          const blobOid = hashObject('blob', content);
          repo.objects.set(blobOid, { type: 'blob', data: content });
          const isNew = !tip;
          let treeOid = '';
          let parents: string[] = [];
          if (tip) {
            const commit = parseCommit(repo.objects.get(tip)!.data);
            treeOid = commit.tree;
            parents = [tip];
          }
          const existing = tip ? flattenTree(repo, treeOid).get(pathParts.join('/')) : undefined;
          if (existing && typeof body.sha === 'string' && body.sha && body.sha !== existing.oid) {
            sendError(res, 409, 'sha does not match');
            return;
          }
          const newTree = setFileInTree(repo, treeOid || undefined, pathParts, blobOid);
          const newCommit = makeCommit(repo, newTree, parents, message);
          repo.refs.set(`refs/heads/${branch}`, newCommit);
          const status = isNew || !existing ? 201 : 200;
          sendJson(res, status, {
            content: { name: pathParts[pathParts.length - 1], path: pathParts.join('/'), sha: blobOid, size: content.length, type: 'file', encoding: 'base64' },
            commit: { sha: newCommit, message },
          });
          return;
        }
        if (!tip) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const commit = parseCommit(repo.objects.get(tip)!.data);
        const existing = flattenTree(repo, commit.tree).get(pathParts.join('/'));
        if (!existing) {
          sendError(res, 404, 'Not Found');
          return;
        }
        if (typeof body.sha === 'string' && body.sha && body.sha !== existing.oid) {
          sendError(res, 409, 'sha does not match');
          return;
        }
        const newTree = deleteFileFromTree(repo, commit.tree, pathParts);
        const finalTree = newTree === '' ? buildTree([]) : newTree!;
        if (newTree === '') {
          const emptyTreeOid = hashObject('tree', finalTree);
          repo.objects.set(emptyTreeOid, { type: 'tree', data: finalTree });
        }
        const newCommit = makeCommit(repo, newTree === '' ? hashObject('tree', finalTree) : newTree!, [tip], message);
        repo.refs.set(`refs/heads/${branch}`, newCommit);
        sendJson(res, 200, { commit: { sha: newCommit, message } });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    if (rest[0] === 'labels') {
      if (method === 'GET' && rest.length === 1) {
        sendJson(res, 200, [...repo.labels.values()].map((label) => ({ name: label.name, color: label.color })));
        return;
      }
      if (method === 'POST' && rest.length === 1) {
        const { value, ok } = await readJsonBody(req);
        if (!ok) {
          sendError(res, 400, 'Problems parsing JSON');
          return;
        }
        const body = isRecord(value) ? value : {};
        const name = typeof body.name === 'string' ? body.name : '';
        if (!name) {
          sendError(res, 422, 'Invalid label');
          return;
        }
        const label: LabelDef = { name, color: typeof body.color === 'string' ? body.color.replace(/^#/, '') : 'ededed' };
        repo.labels.set(name, label);
        sendJson(res, 201, { name: label.name, color: label.color });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const direction = query.get('direction') ?? 'desc';
          let issues = [...repo.issues.values()];
          if (state !== 'all') issues = issues.filter((issue) => issue.state === state);
          issues.sort((a, b) => (direction === 'asc' ? a.createdCounter - b.createdCounter : b.createdCounter - a.createdCounter));
          const { page, perPage } = parsePagination(query);
          const { pageItems, hasNext, total } = paginate(issues, page, perPage);
          sendJson(res, 200, pageItems.map((issue) => issueJson(repo, issue)), linkHeader(req, path, query, page, perPage, hasNext, total));
          return;
        }
        if (method === 'POST') {
          const { value, ok } = await readJsonBody(req);
          if (!ok) {
            sendError(res, 400, 'Problems parsing JSON');
            return;
          }
          const body = isRecord(value) ? value : {};
          const title = typeof body.title === 'string' ? body.title : '';
          if (!title) {
            sendError(res, 422, 'Invalid issue');
            return;
          }
          const labelNames: string[] = [];
          if (Array.isArray(body.labels)) {
            for (const label of body.labels) {
              const labelName = typeof label === 'string' ? label : isRecord(label) ? String(label.name ?? '') : '';
              if (labelName && !repo.labels.has(labelName)) {
                sendError(res, 422, `Label does not exist: ${labelName}`);
                return;
              }
              if (labelName) labelNames.push(labelName);
            }
          }
          const number = repo.nextNumber++;
          const issue: IssueState = {
            number,
            title,
            body: typeof body.body === 'string' ? body.body : '',
            state: 'open',
            labels: labelNames,
            createdCounter: store.tick(),
            jsonCache: null,
          };
          repo.issues.set(number, issue);
          sendJsonText(res, 201, issueJsonText(repo, issue));
          return;
        }
        sendError(res, 404, 'Not Found');
        return;
      }
      const number = Number(rest[1]);
      if (!Number.isInteger(number)) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (rest.length === 2) {
        const issue = repo.issues.get(number);
        const pull = repo.pulls.get(number);
        if (method === 'GET') {
          if (issue) {
            sendJsonText(res, 200, issueJsonText(repo, issue));
            return;
          }
          if (pull) {
            sendJson(res, 200, {
              number: pull.number,
              title: pull.title,
              body: pull.body,
              state: pull.state,
              labels: [],
              user: { login: store.viewerLogin, id: store.viewerId },
            });
            return;
          }
          sendError(res, 404, 'Not Found');
          return;
        }
        if (method === 'PATCH') {
          if (!issue) {
            sendError(res, 404, 'Not Found');
            return;
          }
          const { value, ok } = await readJsonBody(req);
          if (!ok) {
            sendError(res, 400, 'Problems parsing JSON');
            return;
          }
          const body = isRecord(value) ? value : {};
          if (typeof body.title === 'string') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
          issue.jsonCache = null;
          sendJsonText(res, 200, issueJsonText(repo, issue));
          return;
        }
        sendError(res, 404, 'Not Found');
        return;
      }
      if (rest[2] === 'comments') {
        if (method === 'GET') {
          const comments = repo.comments.get(number) ?? [];
          sendJson(res, 200, comments.map((comment) => ({ id: comment.id, body: comment.body, user: { login: store.viewerLogin, id: store.viewerId } })));
          return;
        }
        if (method === 'POST') {
          if (!repo.issues.has(number) && !repo.pulls.has(number)) {
            sendError(res, 404, 'Not Found');
            return;
          }
          const { value, ok } = await readJsonBody(req);
          if (!ok) {
            sendError(res, 400, 'Problems parsing JSON');
            return;
          }
          const body = isRecord(value) ? value : {};
          const comment: CommentState = { id: repo.nextCommentId++, body: typeof body.body === 'string' ? body.body : '' };
          const list = repo.comments.get(number) ?? [];
          list.push(comment);
          repo.comments.set(number, list);
          sendJson(res, 201, { id: comment.id, body: comment.body, user: { login: store.viewerLogin, id: store.viewerId } });
          return;
        }
        sendError(res, 404, 'Not Found');
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let pulls = [...repo.pulls.values()];
          if (state !== 'all') pulls = pulls.filter((pull) => pull.state === state);
          pulls.sort((a, b) => b.createdCounter - a.createdCounter);
          const { page, perPage } = parsePagination(query);
          const { pageItems, hasNext, total } = paginate(pulls, page, perPage);
          sendJson(res, 200, pageItems.map((pull) => pullJson(repo, pull)), linkHeader(req, path, query, page, perPage, hasNext, total));
          return;
        }
        if (method === 'POST') {
          const { value, ok } = await readJsonBody(req);
          if (!ok) {
            sendError(res, 400, 'Problems parsing JSON');
            return;
          }
          const body = isRecord(value) ? value : {};
          const title = typeof body.title === 'string' ? body.title : '';
          const head = typeof body.head === 'string' ? body.head : '';
          const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
          if (!title || !head) {
            sendError(res, 422, 'Invalid pull request');
            return;
          }
          const headOid = repo.refs.get(`refs/heads/${head}`);
          if (!headOid) {
            sendError(res, 422, 'Head branch does not exist');
            return;
          }
          for (const existing of repo.pulls.values()) {
            if (existing.state === 'open' && existing.headRef === head) {
              sendError(res, 422, 'A pull request already exists for this head branch');
              return;
            }
          }
          const baseTip = store.defaultTip(repo) ?? headOid;
          const baseCommit = mergeBase(repo, headOid, baseTip) ?? baseTip;
          const number = repo.nextNumber++;
          const pull: PullState = {
            number,
            title,
            body: typeof body.body === 'string' ? body.body : '',
            state: 'open',
            headRef: head,
            headSha: headOid,
            baseRef: base,
            baseSha: baseTip,
            merged: false,
            mergedAt: '',
            mergeCommitSha: '',
            baseCommitSha: baseCommit,
            createdCounter: store.tick(),
          };
          repo.pulls.set(number, pull);
          sendJson(res, 201, pullJson(repo, pull));
          return;
        }
        sendError(res, 404, 'Not Found');
        return;
      }
      const number = Number(rest[1]);
      if (!Number.isInteger(number)) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const pull = repo.pulls.get(number);
      if (rest.length === 2 && method === 'GET') {
        if (!pull) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, pullJson(repo, pull));
        return;
      }
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        if (!pull) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, diffFiles(repo, pull.baseCommitSha, pull.headSha));
        return;
      }
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        if (!pull) {
          sendError(res, 404, 'Not Found');
          return;
        }
        if (pull.state !== 'open') {
          sendError(res, 405, 'Pull request is not open');
          return;
        }
        const { value, ok } = await readJsonBody(req);
        if (!ok) {
          sendError(res, 400, 'Problems parsing JSON');
          return;
        }
        void value;
        if (pullConflicted(repo, pull)) {
          sendError(res, 405, 'Pull request is not mergeable');
          return;
        }
        const headTree = parseCommit(repo.objects.get(pull.headSha)!.data).tree;
        const baseTip = store.defaultTip(repo);
        const parents = baseTip ? [baseTip] : [];
        const mergeCommit = makeCommit(repo, headTree, parents, `Merge pull request #${pull.number}: ${pull.title}`);
        repo.refs.set(store.defaultBranchRef(repo), mergeCommit);
        pull.state = 'closed';
        pull.merged = true;
        pull.mergedAt = isoFromCounter(store.counter);
        pull.mergeCommitSha = mergeCommit;
        sendJson(res, 200, { sha: mergeCommit, merged: true, message: 'Pull request successfully merged' });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
  }

  sendError(res, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// GraphQL: small parser + executor for the documents gh/github-mcp-server sends
// -------------------------------------------------------------------------------------------

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Record<string, GqlValue> };

interface GqlField {
  alias?: string;
  name: string;
  args: Record<string, GqlValue>;
  selections?: GqlField[];
  typeCondition?: string;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name?: string;
  variableDefinitions: Record<string, GqlValue>;
  selections: GqlField[];
}

class GqlParseError extends Error {}

function tokenizeGql(source: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (/\s/.test(ch) || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source.startsWith('...', i)) {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}():=!@[]$'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        const text = end < 0 ? source.slice(i + 3) : source.slice(i + 3, end);
        tokens.push(JSON.stringify(text));
        i = end < 0 ? source.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1];
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += source[j];
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch) && (ch !== '-' || /[0-9]/.test(source[i + 1] ?? ''))) {
      let j = i;
      let text = '';
      while (j < source.length && /[0-9.eE+-]/.test(source[j])) {
        text += source[j];
        j += 1;
      }
      tokens.push(text);
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      let text = '';
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j])) {
        text += source[j];
        j += 1;
      }
      tokens.push(text);
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: string[];

  constructor(tokens: string[]) {
    this.tokens = tokens;
  }

  peek(): string | undefined {
    return this.tokens[this.pos];
  }

  next(): string {
    const token = this.tokens[this.pos];
    this.pos += 1;
    return token;
  }

  expect(token: string): void {
    const got = this.next();
    if (got !== token) throw new GqlParseError(`expected ${token}, got ${got}`);
  }

  parseDocument(): { operations: GqlOperation[]; fragments: Record<string, GqlField[]> } {
    const operations: GqlOperation[] = [];
    const fragments: Record<string, GqlField[]> = {};
    while (this.pos < this.tokens.length) {
      const token = this.peek();
      if (token === 'fragment') {
        this.next();
        const name = this.next();
        this.expect('on');
        const typeName = this.next();
        const selections = this.parseSelectionSet();
        fragments[name] = selections.map((field) => ({ ...field, typeCondition: typeName }));
        continue;
      }
      operations.push(this.parseOperation());
    }
    return { operations, fragments };
  }

  parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    let name: string | undefined;
    const token = this.peek();
    if (token === 'query' || token === 'mutation') {
      kind = this.next() as 'query' | 'mutation';
      const next = this.peek();
      if (next && next !== '(' && next !== '{') name = this.next();
    }
    const variableDefinitions: Record<string, GqlValue> = {};
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')' && this.pos < this.tokens.length) {
        if (this.peek() === '$') {
          this.next();
          const varName = this.next();
          this.expect(':');
          const typeName = this.next();
          void typeName;
          if (this.peek() === '=') {
            this.next();
            variableDefinitions[varName] = this.parseValue();
          } else {
            variableDefinitions[varName] = { kind: 'null' };
          }
        } else {
          this.next();
        }
      }
      this.expect(')');
    }
    const selections = this.parseSelectionSet();
    return { kind, name, variableDefinitions, selections };
  }

  parseSelectionSet(): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (this.peek() !== '}' && this.pos < this.tokens.length) {
      fields.push(this.parseField());
    }
    this.expect('}');
    return fields;
  }

  parseField(): GqlField {
    if (this.peek() === '...') {
      this.next();
      if (this.peek() === 'on') {
        this.next();
        const typeCondition = this.next();
        const selections = this.parseSelectionSet();
        return { name: '__fragment__', args: {}, selections, typeCondition };
      }
      const fragmentName = this.next();
      return { name: `__spread__${fragmentName}`, args: {} };
    }
    let alias: string | undefined;
    let name = this.next();
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    const args: Record<string, GqlValue> = {};
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')' && this.pos < this.tokens.length) {
        const argName = this.next();
        this.expect(':');
        args[argName] = this.parseValue();
      }
      this.expect(')');
    }
    while (this.peek() === '@') {
      this.next();
      this.next();
      if (this.peek() === '(') {
        this.next();
        let depth = 1;
        while (depth > 0 && this.pos < this.tokens.length) {
          const token = this.next();
          if (token === '(') depth += 1;
          else if (token === ')') depth -= 1;
        }
      }
    }
    let selections: GqlField[] | undefined;
    if (this.peek() === '{') selections = this.parseSelectionSet();
    return { alias, name, args, selections };
  }

  parseValue(): GqlValue {
    const token = this.next();
    if (token === '$') return { kind: 'variable', name: this.next() };
    if (token === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']' && this.pos < this.tokens.length) values.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', values };
    }
    if (token === '{') {
      const fields: Record<string, GqlValue> = {};
      while (this.peek() !== '}' && this.pos < this.tokens.length) {
        const key = this.next();
        this.expect(':');
        fields[key] = this.parseValue();
      }
      this.expect('}');
      return { kind: 'object', fields };
    }
    if (token === 'true') return { kind: 'boolean', value: true };
    if (token === 'false') return { kind: 'boolean', value: false };
    if (token === 'null') return { kind: 'null' };
    if (token.startsWith('"')) return { kind: 'string', value: JSON.parse(token) as string };
    if (/^-?\d+$/.test(token)) return { kind: 'int', value: Number.parseInt(token, 10) };
    if (/^-?\d+\.\d+(e[+-]?\d+)?$/i.test(token)) return { kind: 'float', value: Number.parseFloat(token) };
    return { kind: 'enum', value: token };
  }
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable':
      return variables[value.name];
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.values.map((item) => resolveGqlValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(value.fields)) out[key] = resolveGqlValue(item, variables);
      return out;
    }
  }
}

function resolveGqlArgs(field: GqlField, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(field.args)) out[key] = resolveGqlValue(value, variables);
  return out;
}

class GqlFieldError extends Error {}

const INTROSPECTION: Record<string, { kind: string; fields: { name: string; type: string }[]; enums?: string[] }> = {
  Issue: {
    kind: 'OBJECT',
    fields: [
      { name: 'id', type: 'ID' },
      { name: 'number', type: 'Int' },
      { name: 'title', type: 'String' },
      { name: 'state', type: 'IssueState' },
      { name: 'body', type: 'String' },
    ],
  },
  PullRequest: {
    kind: 'OBJECT',
    fields: [
      { name: 'id', type: 'ID' },
      { name: 'number', type: 'Int' },
      { name: 'title', type: 'String' },
      { name: 'headRefName', type: 'String' },
      { name: 'baseRefName', type: 'String' },
      { name: 'mergeable', type: 'MergeableState' },
      { name: 'state', type: 'PullRequestState' },
      { name: 'merged', type: 'Boolean' },
      { name: 'files', type: 'PullRequestChangedFileConnection' },
    ],
  },
  Repository: {
    kind: 'OBJECT',
    fields: [
      { name: 'id', type: 'ID' },
      { name: 'databaseId', type: 'Int' },
      { name: 'name', type: 'String' },
      { name: 'nameWithOwner', type: 'String' },
      { name: 'owner', type: 'RepositoryOwner' },
      { name: 'defaultBranchRef', type: 'Ref' },
      { name: 'viewerPermission', type: 'RepositoryPermission' },
      { name: 'hasIssuesEnabled', type: 'Boolean' },
      { name: 'issue', type: 'Issue' },
      { name: 'issues', type: 'IssueConnection' },
      { name: 'pullRequests', type: 'PullRequestConnection' },
      { name: 'pullRequest', type: 'PullRequest' },
    ],
  },
  SearchType: {
    kind: 'ENUM',
    fields: [],
    enums: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'],
  },
  User: {
    kind: 'OBJECT',
    fields: [
      { name: 'id', type: 'ID' },
      { name: 'login', type: 'String' },
      { name: 'name', type: 'String' },
    ],
  },
};

function typeRef(typeName: string): Json {
  const scalar = new Set(['ID', 'Int', 'String', 'Boolean']);
  if (scalar.has(typeName)) return { kind: 'SCALAR', name: typeName, ofType: null };
  if (typeName.endsWith('State') || typeName === 'RepositoryPermission' || typeName === 'MergeableState') {
    return { kind: 'ENUM', name: typeName, ofType: null };
  }
  return { kind: 'OBJECT', name: typeName, ofType: null };
}

function introspectionType(name: string): Json | null {
  const info = INTROSPECTION[name];
  if (!info) return null;
  return {
    name,
    kind: info.kind,
    fields: info.fields.map((field) => ({ name: field.name, type: typeRef(field.type) })),
    enumValues: (info.enums ?? []).map((value) => ({ name: value })),
  };
}

interface GqlContext {
  repoById: (id: string) => RepoState | undefined;
  issueById: (id: string) => { repo: RepoState; issue: IssueState } | undefined;
  pullById: (id: string) => { repo: RepoState; pull: PullState } | undefined;
}

function issueStateGql(state: 'open' | 'closed'): string {
  return state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullStateGql(pull: PullState): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function executeSelections(
  typeName: string,
  value: unknown,
  selections: GqlField[],
  variables: Record<string, unknown>,
  ctx: GqlContext,
  fragments: Record<string, GqlField[]>,
): Json {
  const out: Json = {};
  for (const field of selections) {
    if (field.name === '__fragment__') {
      if (field.typeCondition && field.typeCondition !== typeName) continue;
      Object.assign(out, executeSelections(typeName, value, field.selections ?? [], variables, ctx, fragments));
      continue;
    }
    if (field.name.startsWith('__spread__')) {
      const fragmentName = field.name.slice('__spread__'.length);
      const fragment = fragments[fragmentName];
      if (fragment) Object.assign(out, executeSelections(typeName, value, fragment, variables, ctx, fragments));
      continue;
    }
    const responseName = field.alias ?? field.name;
    out[responseName] = executeField(typeName, value, field, variables, ctx, fragments);
  }
  return out;
}

function executeField(
  typeName: string,
  value: unknown,
  field: GqlField,
  variables: Record<string, unknown>,
  ctx: GqlContext,
  fragments: Record<string, GqlField[]>,
): unknown {
  const args = resolveGqlArgs(field, variables);
  const selections = field.selections ?? [];
  const sub = (nextType: string, nextValue: unknown): unknown =>
    selections.length > 0 ? executeSelections(nextType, nextValue, selections, variables, ctx, fragments) : nextValue;

  if (typeName === 'Query') {
    if (field.name === 'viewer') return sub('User', { login: store.viewerLogin, id: store.viewerId, name: 'ada iversen' });
    if (field.name === 'repository') {
      const owner = String(args.owner ?? '');
      const name = String(args.name ?? '');
      const repo = owner === store.viewerLogin ? store.getRepo(owner, name) : undefined;
      if (!repo) return null;
      return sub('Repository', repo);
    }
    if (field.name === 'node') {
      const decoded = decodeGlobalId(String(args.id ?? ''));
      if (!decoded) return null;
      if (decoded.kind === 'Repository') {
        const repo = store.repos.get(decoded.repoKey);
        if (!repo) return null;
        return sub('Repository', repo);
      }
      if (decoded.kind === 'Issue' && decoded.number !== undefined) {
        const found = ctx.issueById(String(args.id));
        if (!found) return null;
        return sub('Issue', { repo: found.repo, issue: found.issue });
      }
      if (decoded.kind === 'PullRequest' && decoded.number !== undefined) {
        const found = ctx.pullById(String(args.id));
        if (!found) return null;
        return sub('PullRequest', { repo: found.repo, pull: found.pull });
      }
      return null;
    }
    if (field.name === '__type') {
      return sub('__Type', introspectionType(String(args.name ?? '')));
    }
    if (field.name === '__schema') {
      const schema = {
        queryType: { name: 'Query' },
        mutationType: { name: 'Mutation' },
        types: Object.keys(INTROSPECTION).map((name) => ({ name, kind: INTROSPECTION[name].kind })),
      };
      return sub('__Schema', schema);
    }
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "Query".`);
  }

  if (typeName === 'User') {
    const user = value as { login: string; id: number; name: string };
    if (field.name === 'login') return user.login;
    if (field.name === 'id') return globalId('User', { ownerLogin: user.login, name: '' } as RepoState);
    if (field.name === 'name') return user.name;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "User".`);
  }

  if (typeName === 'Repository') {
    const repo = value as RepoState;
    switch (field.name) {
      case 'id':
        return globalId('Repository', repo);
      case 'databaseId':
        return repo.id;
      case 'name':
        return repo.name;
      case 'nameWithOwner':
        return `${repo.ownerLogin}/${repo.name}`;
      case 'owner':
        return sub('User', { login: repo.ownerLogin, id: repo.ownerId, name: 'ada iversen' });
      case 'defaultBranchRef':
        return sub('Ref', { name: repo.defaultBranch });
      case 'viewerPermission':
        return 'ADMIN';
      case 'hasIssuesEnabled':
        return true;
      case 'issue': {
        const issue = repo.issues.get(Number(args.number));
        if (!issue) return null;
        return sub('Issue', { repo, issue });
      }
      case 'issues': {
        let issues = [...repo.issues.values()];
        if (Array.isArray(args.states)) {
          const wanted = new Set((args.states as unknown[]).map((s) => String(s).toLowerCase()));
          issues = issues.filter((issue) => wanted.has(issue.state));
        }
        let direction = 'DESC';
        if (isRecord(args.orderBy)) {
          const orderBy = args.orderBy as Record<string, unknown>;
          if (typeof orderBy.direction === 'string') direction = String(orderBy.direction).toUpperCase();
        }
        issues.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
        if (typeof args.after === 'string' && args.after) {
          const afterNumber = Number(b64decode(args.after).toString('utf8'));
          if (Number.isFinite(afterNumber)) {
            issues = direction === 'ASC' ? issues.filter((i) => i.number > afterNumber) : issues.filter((i) => i.number < afterNumber);
          }
        }
        const first = typeof args.first === 'number' ? args.first : 100;
        const nodes = issues.slice(0, first);
        const hasNextPage = issues.length > first;
        return sub('IssueConnection', {
          nodes: nodes.map((issue) => ({ repo, issue })),
          pageInfo: {
            hasNextPage,
            endCursor: nodes.length > 0 ? b64encode(Buffer.from(String(nodes[nodes.length - 1].number), 'utf8')) : null,
          },
        });
      }
      case 'pullRequests': {
        const first = typeof args.first === 'number' ? args.first : 100;
        const pulls = [...repo.pulls.values()].sort((a, b) => b.number - a.number).slice(0, first);
        return sub('PullRequestConnection', {
          nodes: pulls.map((pull) => ({ repo, pull })),
          pageInfo: { hasNextPage: false, endCursor: null },
        });
      }
      case 'pullRequest': {
        const pull = repo.pulls.get(Number(args.number));
        if (!pull) return null;
        return sub('PullRequest', { repo, pull });
      }
      default:
        throw new GqlFieldError(`Cannot query field "${field.name}" on type "Repository".`);
    }
  }

  if (typeName === 'Issue') {
    const { issue } = value as { repo: RepoState; issue: IssueState };
    switch (field.name) {
      case 'id':
        return globalId('Issue', (value as { repo: RepoState }).repo, issue.number);
      case 'number':
        return issue.number;
      case 'title':
        return issue.title;
      case 'state':
        return issueStateGql(issue.state);
      case 'body':
        return issue.body;
      default:
        throw new GqlFieldError(`Cannot query field "${field.name}" on type "Issue".`);
    }
  }

  if (typeName === 'PullRequest') {
    const { repo, pull } = value as { repo: RepoState; pull: PullState };
    switch (field.name) {
      case 'id':
        return globalId('PullRequest', repo, pull.number);
      case 'number':
        return pull.number;
      case 'title':
        return pull.title;
      case 'state':
        return pullStateGql(pull);
      case 'merged':
        return pull.merged;
      case 'headRefName':
        return pull.headRef;
      case 'baseRefName':
        return pull.baseRef;
      case 'mergeable':
        return pull.state === 'open' ? (pullConflicted(repo, pull) ? 'CONFLICTING' : 'MERGEABLE') : 'UNKNOWN';
      case 'files': {
        const files = diffFiles(repo, pull.baseCommitSha, pull.headSha);
        const first = typeof args.first === 'number' ? args.first : 100;
        return sub('PullRequestChangedFileConnection', {
          nodes: files.slice(0, first).map((file) => ({ path: file.filename })),
        });
      }
      default:
        throw new GqlFieldError(`Cannot query field "${field.name}" on type "PullRequest".`);
    }
  }

  if (typeName === 'IssueConnection') {
    const conn = value as { nodes: { repo: RepoState; issue: IssueState }[]; pageInfo: Json };
    if (field.name === 'nodes') return conn.nodes.map((node) => sub('Issue', node));
    if (field.name === 'edges') {
      return conn.nodes.map((node) => ({ cursor: b64encode(Buffer.from(String(node.issue.number), 'utf8')), node: sub('Issue', node) }));
    }
    if (field.name === 'pageInfo') return sub('PageInfo', conn.pageInfo);
    if (field.name === 'totalCount') return conn.nodes.length;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "IssueConnection".`);
  }

  if (typeName === 'PullRequestConnection') {
    const conn = value as { nodes: { repo: RepoState; pull: PullState }[]; pageInfo: Json };
    if (field.name === 'nodes') return conn.nodes.map((node) => sub('PullRequest', node));
    if (field.name === 'edges') {
      return conn.nodes.map((node) => ({ cursor: b64encode(Buffer.from(String(node.pull.number), 'utf8')), node: sub('PullRequest', node) }));
    }
    if (field.name === 'pageInfo') return sub('PageInfo', conn.pageInfo);
    if (field.name === 'totalCount') return conn.nodes.length;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "PullRequestConnection".`);
  }

  if (typeName === 'PullRequestChangedFileConnection') {
    const conn = value as { nodes: { path: string }[] };
    if (field.name === 'nodes') return conn.nodes.map((node) => sub('PullRequestChangedFile', node));
    if (field.name === 'totalCount') return conn.nodes.length;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "PullRequestChangedFileConnection".`);
  }

  if (typeName === 'PullRequestChangedFile') {
    const file = value as { path: string };
    if (field.name === 'path') return file.path;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "PullRequestChangedFile".`);
  }

  if (typeName === 'AddCommentEdge') {
    const edge = value as { node: { id: string; body: string } };
    if (field.name === 'node') return sub('IssueComment', edge.node);
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "AddCommentEdge".`);
  }

  if (typeName === 'IssueComment') {
    const comment = value as { id: string; body: string };
    if (field.name === 'id') return comment.id;
    if (field.name === 'body') return comment.body;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "IssueComment".`);
  }

  if (typeName === 'PageInfo') {
    const info = value as Json;
    if (field.name === 'hasNextPage') return info.hasNextPage ?? false;
    if (field.name === 'hasPreviousPage') return false;
    if (field.name === 'endCursor') return info.endCursor ?? null;
    if (field.name === 'startCursor') return info.endCursor ?? null;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "PageInfo".`);
  }

  if (typeName === 'Ref') {
    const ref = value as { name: string };
    if (field.name === 'name') return ref.name;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "Ref".`);
  }

  if (typeName === '__Type') {
    const info = value as Json | null;
    if (info === null) return null;
    if (field.name === 'name') return info.name;
    if (field.name === 'kind') return info.kind;
    if (field.name === 'fields') {
      const fields = (info.fields as { name: string; type: Json }[] | undefined) ?? [];
      return fields.map((item) => sub('__Field', item));
    }
    if (field.name === 'enumValues') {
      const values = (info.enumValues as { name: string }[] | undefined) ?? [];
      return values.map((item) => sub('__EnumValue', item));
    }
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "__Type".`);
  }

  if (typeName === '__Field') {
    const item = value as { name: string; type: Json };
    if (field.name === 'name') return item.name;
    if (field.name === 'type') return sub('__TypeRef', item.type);
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "__Field".`);
  }

  if (typeName === '__EnumValue') {
    const item = value as { name: string };
    if (field.name === 'name') return item.name;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "__EnumValue".`);
  }

  if (typeName === '__TypeRef') {
    const item = value as Json;
    if (field.name === 'name') return item.name ?? null;
    if (field.name === 'kind') return item.kind ?? null;
    if (field.name === 'ofType') return item.ofType ? sub('__TypeRef', item.ofType) : null;
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "__TypeRef".`);
  }

  if (typeName === '__Schema') {
    const schema = value as Json;
    if (field.name === 'queryType') return sub('__Named', schema.queryType);
    if (field.name === 'mutationType') return sub('__Named', schema.mutationType);
    if (field.name === 'types') {
      return (schema.types as { name: string; kind: string }[]).map((item) => sub('__Named', item));
    }
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "__Schema".`);
  }

  if (typeName === '__Named') {
    const item = value as { name: string; kind?: string };
    if (field.name === 'name') return item.name;
    if (field.name === 'kind') return item.kind ?? 'OBJECT';
    throw new GqlFieldError(`Cannot query field "${field.name}" on type "__Named".`);
  }

  throw new GqlFieldError(`Cannot query field "${field.name}" on type "${typeName}".`);
}

function executeMutation(
  field: GqlField,
  variables: Record<string, unknown>,
  ctx: GqlContext,
  fragments: Record<string, GqlField[]>,
): unknown {
  const args = resolveGqlArgs(field, variables);
  const selections = field.selections ?? [];
  const sub = (typeName: string, value: unknown): unknown =>
    selections.length > 0 ? executeSelections(typeName, value, selections, variables, ctx, fragments) : value;

  if (field.name === 'createIssue') {
    const input = isRecord(args.input) ? (args.input as Record<string, unknown>) : {};
    const repo = ctx.repoById(String(input.repositoryId ?? ''));
    if (!repo) throw new GqlFieldError('Repository not found');
    const number = repo.nextNumber++;
    const issue: IssueState = {
      number,
      title: String(input.title ?? ''),
      body: typeof input.body === 'string' ? input.body : '',
      state: 'open',
      labels: [],
      createdCounter: store.tick(),
      jsonCache: null,
    };
    repo.issues.set(number, issue);
    return { issue: { repo, issue } };
  }
  if (field.name === 'closeIssue') {
    const input = isRecord(args.input) ? (args.input as Record<string, unknown>) : {};
    const found = ctx.issueById(String(input.issueId ?? ''));
    if (!found) throw new GqlFieldError('Issue not found');
    found.issue.state = 'closed';
    found.issue.jsonCache = null;
    return { issue: { repo: found.repo, issue: found.issue } };
  }
  if (field.name === 'createPullRequest') {
    const input = isRecord(args.input) ? (args.input as Record<string, unknown>) : {};
    const repo = ctx.repoById(String(input.repositoryId ?? ''));
    if (!repo) throw new GqlFieldError('Repository not found');
    const headRef = String(input.headRefName ?? '');
    const baseRef = String(input.baseRefName ?? repo.defaultBranch);
    const headOid = repo.refs.get(`refs/heads/${headRef}`);
    if (!headOid) throw new GqlFieldError('Head branch does not exist');
    for (const existing of repo.pulls.values()) {
      if (existing.state === 'open' && existing.headRef === headRef) {
        throw new GqlFieldError('A pull request already exists for this head branch');
      }
    }
    const baseTip = store.defaultTip(repo) ?? headOid;
    const baseCommit = mergeBase(repo, headOid, baseTip) ?? baseTip;
    const number = repo.nextNumber++;
    const pull: PullState = {
      number,
      title: String(input.title ?? ''),
      body: typeof input.body === 'string' ? input.body : '',
      state: 'open',
      headRef,
      headSha: headOid,
      baseRef,
      baseSha: baseTip,
      merged: false,
      mergedAt: '',
      mergeCommitSha: '',
      baseCommitSha: baseCommit,
      createdCounter: store.tick(),
    };
    repo.pulls.set(number, pull);
    return { pullRequest: { repo, pull } };
  }
  if (field.name === 'mergePullRequest') {
    const input = isRecord(args.input) ? (args.input as Record<string, unknown>) : {};
    const found = ctx.pullById(String(input.pullRequestId ?? ''));
    if (!found) throw new GqlFieldError('Pull request not found');
    const { repo, pull } = found;
    if (pull.state !== 'open') throw new GqlFieldError('Pull request is not open');
    if (pullConflicted(repo, pull)) throw new GqlFieldError('Pull request is not mergeable');
    const headTree = parseCommit(repo.objects.get(pull.headSha)!.data).tree;
    const baseTip = store.defaultTip(repo);
    const parents = baseTip ? [baseTip] : [];
    const mergeCommit = makeCommit(repo, headTree, parents, `Merge pull request #${pull.number}: ${pull.title}`);
    repo.refs.set(store.defaultBranchRef(repo), mergeCommit);
    pull.state = 'closed';
    pull.merged = true;
    pull.mergedAt = isoFromCounter(store.counter);
    pull.mergeCommitSha = mergeCommit;
    return { pullRequest: { repo, pull } };
  }
  if (field.name === 'addComment') {
    const input = isRecord(args.input) ? (args.input as Record<string, unknown>) : {};
    const subject = String(input.subjectId ?? '');
    const foundIssue = ctx.issueById(subject);
    const foundPull = foundIssue ? undefined : ctx.pullById(subject);
    const repo = foundIssue?.repo ?? foundPull?.repo;
    const number = foundIssue?.issue.number ?? foundPull?.pull.number;
    if (!repo || number === undefined) throw new GqlFieldError('Subject not found');
    const comment: CommentState = { id: repo.nextCommentId++, body: String(input.body ?? '') };
    const list = repo.comments.get(number) ?? [];
    list.push(comment);
    repo.comments.set(number, list);
    return {
      commentEdge: { node: { id: globalId('IssueComment', repo, comment.id), body: comment.body } },
    };
  }
  throw new GqlFieldError(`Cannot query field "${field.name}" on type "Mutation".`);
}

function executePayloadFields(
  payloadType: string,
  value: unknown,
  selections: GqlField[],
  variables: Record<string, unknown>,
  ctx: GqlContext,
  fragments: Record<string, GqlField[]>,
): Json {
  const out: Json = {};
  for (const field of selections) {
    if (field.name === '__fragment__') {
      Object.assign(out, executePayloadFields(payloadType, value, field.selections ?? [], variables, ctx, fragments));
      continue;
    }
    if (field.name.startsWith('__spread__')) {
      const fragment = fragments[field.name.slice('__spread__'.length)];
      if (fragment) Object.assign(out, executePayloadFields(payloadType, value, fragment, variables, ctx, fragments));
      continue;
    }
    const responseName = field.alias ?? field.name;
    const payload = value as Record<string, unknown>;
    const inner = payload[field.name];
    if (inner === undefined) throw new GqlFieldError(`Cannot query field "${field.name}" on type "${payloadType}".`);
    if (field.name === 'issue') {
      out[responseName] = field.selections?.length
        ? executeSelections('Issue', inner, field.selections, variables, ctx, fragments)
        : inner;
    } else if (field.name === 'pullRequest') {
      out[responseName] = field.selections?.length
        ? executeSelections('PullRequest', inner, field.selections, variables, ctx, fragments)
        : inner;
    } else if (field.name === 'commentEdge') {
      const edge = inner as { node: { id: string; body: string } };
      out[responseName] = field.selections?.length
        ? executeSelections('AddCommentEdge', edge, field.selections, variables, ctx, fragments)
        : edge;
    } else {
      out[responseName] = inner;
    }
  }
  return out;
}

function executeOperation(operation: GqlOperation, variables: Record<string, unknown>, ctx: GqlContext, fragments: Record<string, GqlField[]>): Json {
  try {
    if (operation.kind === 'mutation') {
      const data: Json = {};
      for (const field of operation.selections) {
        const responseName = field.alias ?? field.name;
        const payloadType =
          field.name === 'createIssue'
            ? 'CreateIssuePayload'
            : field.name === 'closeIssue'
              ? 'CloseIssuePayload'
              : field.name === 'createPullRequest'
                ? 'CreatePullRequestPayload'
                : field.name === 'mergePullRequest'
                  ? 'MergePullRequestPayload'
                  : 'AddCommentPayload';
        const raw = executeMutation(field, variables, ctx, fragments);
        data[responseName] = field.selections?.length
          ? executePayloadFields(payloadType, raw, field.selections, variables, ctx, fragments)
          : raw;
      }
      return { data };
    }
    const data = executeSelections('Query', null, operation.selections, variables, ctx, fragments);
    return { data };
  } catch (error) {
    if (error instanceof GqlFieldError) {
      return { data: null, errors: [{ message: error.message }] };
    }
    if (error instanceof GqlParseError) {
      return { data: null, errors: [{ message: error.message }] };
    }
    throw error;
  }
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { value, ok } = await readJsonBody(req);
  if (!ok) {
    sendJson(res, 400, { message: 'Problems parsing JSON' });
    return;
  }
  const ctx: GqlContext = {
    repoById: (id) => {
      const decoded = decodeGlobalId(id);
      if (decoded && decoded.kind === 'Repository') return store.repos.get(decoded.repoKey);
      const byId = store.getRepoById(Number(id));
      return byId;
    },
    issueById: (id) => {
      const decoded = decodeGlobalId(id);
      if (!decoded || decoded.kind !== 'Issue' || decoded.number === undefined) return undefined;
      const repo = store.repos.get(decoded.repoKey);
      if (!repo) return undefined;
      const issue = repo.issues.get(decoded.number);
      if (!issue) return undefined;
      return { repo, issue };
    },
    pullById: (id) => {
      const decoded = decodeGlobalId(id);
      if (!decoded || decoded.kind !== 'PullRequest' || decoded.number === undefined) return undefined;
      const repo = store.repos.get(decoded.repoKey);
      if (!repo) return undefined;
      const pull = repo.pulls.get(decoded.number);
      if (!pull) return undefined;
      return { repo, pull };
    },
  };
  const runOne = (doc: unknown): Json => {
    if (!isRecord(doc) || typeof doc.query !== 'string') {
      return { data: null, errors: [{ message: 'Must provide query string.' }] };
    }
    const variables = isRecord(doc.variables) ? (doc.variables as Record<string, unknown>) : {};
    let parsed: { operations: GqlOperation[]; fragments: Record<string, GqlField[]> };
    try {
      parsed = new GqlParser(tokenizeGql(doc.query)).parseDocument();
    } catch (error) {
      return { data: null, errors: [{ message: error instanceof Error ? error.message : 'Syntax Error' }] };
    }
    const operationName = typeof doc.operationName === 'string' ? doc.operationName : undefined;
    const operation =
      parsed.operations.find((op) => op.name === operationName) ??
      parsed.operations.find((op) => op.name === undefined) ??
      parsed.operations[0];
    if (!operation) return { data: null, errors: [{ message: 'Must provide an operation.' }] };
    return executeOperation(operation, variables, ctx, parsed.fragments);
  };
  if (Array.isArray(value)) {
    sendJson(res, 200, value.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(value));
}

// -------------------------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 Streamable HTTP, six canonical tools over the same store
// -------------------------------------------------------------------------------------------

interface McpTool {
  name: string;
  description: string;
  inputSchema: Json;
}

const MCP_TOOLS: McpTool[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpResult(id: unknown, result: unknown): Json {
  return { jsonrpc: '2.0', id: id ?? null, result };
}

function mcpError(id: unknown, code: number, message: string): Json {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function mcpToolError(message: string): Json {
  return { content: [{ type: 'text', text: JSON.stringify({ error: message }) }], isError: true };
}

function mcpToolOk(payload: unknown): Json {
  return { structuredContent: payload, content: [{ type: 'text', text: JSON.stringify(payload) }] };
}

function mcpFindRepo(args: Record<string, unknown>): RepoState | undefined {
  const owner = String(args.owner ?? '');
  const repoName = String(args.repo ?? '');
  if (owner !== store.viewerLogin) return undefined;
  return store.getRepo(owner, repoName);
}

function mcpCallTool(name: string, args: Record<string, unknown>): Json {
  const tool = MCP_TOOLS.find((candidate) => name.toLowerCase().endsWith(candidate.name));
  if (!tool) return mcpToolError(`Unknown tool: ${name}`);
  const required = (tool.inputSchema.required as string[] | undefined) ?? [];
  for (const key of required) {
    if (args[key] === undefined || args[key] === null || args[key] === '') {
      return mcpToolError(`Missing required argument: ${key}`);
    }
  }
  switch (tool.name) {
    case 'create_repo': {
      const repoName = String(args.name);
      if (store.getRepo(store.viewerLogin, repoName)) return mcpToolError('Repository already exists');
      const repo = store.createRepo(
        repoName,
        typeof args.description === 'string' ? args.description : '',
        args.private === true,
      );
      return mcpToolOk(repoJson(repo));
    }
    case 'get_repo': {
      const repo = mcpFindRepo(args);
      if (!repo) return mcpToolError('Repository not found');
      return mcpToolOk(repoJson(repo));
    }
    case 'create_issue': {
      const repo = mcpFindRepo(args);
      if (!repo) return mcpToolError('Repository not found');
      const number = repo.nextNumber++;
      const issue: IssueState = {
        number,
        title: String(args.title),
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        labels: [],
        createdCounter: store.tick(),
        jsonCache: null,
      };
      repo.issues.set(number, issue);
      return mcpToolOk(issueJson(repo, issue));
    }
    case 'list_issues': {
      const repo = mcpFindRepo(args);
      if (!repo) return mcpToolError('Repository not found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      let issues = [...repo.issues.values()];
      if (state !== 'all') issues = issues.filter((issue) => issue.state === state);
      issues.sort((a, b) => b.createdCounter - a.createdCounter);
      return mcpToolOk({ issues: issues.map((issue) => issueJson(repo, issue)) });
    }
    case 'create_pull_request': {
      const repo = mcpFindRepo(args);
      if (!repo) return mcpToolError('Repository not found');
      const head = String(args.head);
      const base = String(args.base);
      const headOid = repo.refs.get(`refs/heads/${head}`);
      if (!headOid) return mcpToolError('Head branch does not exist');
      for (const existing of repo.pulls.values()) {
        if (existing.state === 'open' && existing.headRef === head) {
          return mcpToolError('A pull request already exists for this head branch');
        }
      }
      const baseTip = store.defaultTip(repo) ?? headOid;
      const baseCommit = mergeBase(repo, headOid, baseTip) ?? baseTip;
      const number = repo.nextNumber++;
      const pull: PullState = {
        number,
        title: String(args.title),
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        headRef: head,
        headSha: headOid,
        baseRef: base,
        baseSha: baseTip,
        merged: false,
        mergedAt: '',
        mergeCommitSha: '',
        baseCommitSha: baseCommit,
        createdCounter: store.tick(),
      };
      repo.pulls.set(number, pull);
      return mcpToolOk(pullJson(repo, pull));
    }
    case 'merge_pull_request': {
      const repo = mcpFindRepo(args);
      if (!repo) return mcpToolError('Repository not found');
      const pull = repo.pulls.get(Number(args.pull_number));
      if (!pull) return mcpToolError('Pull request not found');
      if (pull.state !== 'open') return mcpToolError('Pull request is not open');
      if (pullConflicted(repo, pull)) return mcpToolError('Pull request is not mergeable');
      const headTree = parseCommit(repo.objects.get(pull.headSha)!.data).tree;
      const baseTip = store.defaultTip(repo);
      const parents = baseTip ? [baseTip] : [];
      const mergeCommit = makeCommit(repo, headTree, parents, `Merge pull request #${pull.number}: ${pull.title}`);
      repo.refs.set(store.defaultBranchRef(repo), mergeCommit);
      pull.state = 'closed';
      pull.merged = true;
      pull.mergedAt = isoFromCounter(store.counter);
      pull.mergeCommitSha = mergeCommit;
      return mcpToolOk({ sha: mergeCommit, merged: true, message: 'Pull request successfully merged' });
    }
    default:
      return mcpToolError(`Unknown tool: ${name}`);
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'DELETE') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ message: 'Method not allowed' }));
    return;
  }
  const { value, ok } = await readJsonBody(req);
  if (!ok) {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify(mcpError(null, -32700, 'Parse error')));
    return;
  }
  const handleOne = (request: unknown): Json => {
    if (!isRecord(request) || request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
      return mcpError(isRecord(request) ? request.id : null, -32600, 'Invalid Request');
    }
    const id = request.id ?? null;
    const params = isRecord(request.params) ? (request.params as Record<string, unknown>) : {};
    const method = request.method;
    if (method === 'initialize') {
      const protocolVersion =
        typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
      return mcpResult(id, {
        protocolVersion,
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
      });
    }
    if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
      return { jsonrpc: '2.0', id: null, result: {} };
    }
    if (method === 'server/discover') {
      return mcpResult(id, {
        serverInfo: { name: 'forge', version: '1.0.0' },
        capabilities: { tools: {} },
        supportedVersions: ['2026-07-28', '2025-11-25'],
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: '1.0.0' } },
      });
    }
    if (method === 'ping') {
      return mcpResult(id, {});
    }
    if (method === 'tools/list') {
      return mcpResult(id, { tools: MCP_TOOLS });
    }
    if (method === 'tools/call') {
      const toolName = typeof params.name === 'string' ? params.name : '';
      const toolArgs = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
      const known = MCP_TOOLS.some((candidate) => toolName.toLowerCase().endsWith(candidate.name));
      if (!known) return mcpError(id, -32602, `Unknown tool: ${toolName}`);
      return mcpResult(id, mcpCallTool(toolName, toolArgs));
    }
    return mcpError(id, -32601, `Method not found: ${method}`);
  };
  if (Array.isArray(value)) {
    const results = value.map(handleOne).filter((result) => result.id !== null || result.error !== undefined);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(results));
    return;
  }
  const result = handleOne(value);
  if (isRecord(value) && typeof value.method === 'string' && value.method.startsWith('notifications/')) {
    res.writeHead(202);
    res.end();
    return;
  }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(result));
}

// -------------------------------------------------------------------------------------------
// router + server
// -------------------------------------------------------------------------------------------

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const rawPath = (req.url ?? '/').split('?')[0];
    const path = rawPath.includes('%') ? decodeURIComponent(rawPath) : rawPath;
    if (path === '/healthz') {
      if (req.method === 'GET') {
        sendJson(res, 200, { ok: true });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    const gitMatch = path.includes('.git/') ? path.match(/^\/([^/]+)\/([^/]+)\.git\/(.*)$/) : null;
    if (gitMatch) {
      const owner = gitMatch[1];
      const repoName = gitMatch[2];
      const rest = gitMatch[3];
      const repo = owner === store.viewerLogin ? store.getRepo(owner, repoName) : undefined;
      if (!repo) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (rest === 'info/refs' && req.method === 'GET') {
        // The only query param here is `service=`; pull it out without
        // paying for a URL + URLSearchParams parse on every advert.
        const rawUrl = req.url ?? '';
        const serviceIdx = rawUrl.indexOf('service=');
        const service = serviceIdx < 0 ? '' : rawUrl.slice(serviceIdx + 8).split('&')[0];
        if (service === 'git-upload-pack') {
          const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
          sendAdvertisement(res, repo, 'upload-pack', isV2);
          return;
        }
        if (service === 'git-receive-pack') {
          sendAdvertisement(res, repo, 'receive-pack', false);
          return;
        }
        sendError(res, 400, 'Unknown service');
        return;
      }
      if (rest === 'git-upload-pack' && req.method === 'POST') {
        await handleUploadPack(req, res, repo);
        return;
      }
      if (rest === 'git-receive-pack' && req.method === 'POST') {
        await handleReceivePack(req, res, repo);
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (path === '/api/graphql') {
      if (req.method !== 'POST') {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (!authenticateApi(req, res)) return;
      await handleGraphql(req, res);
      return;
    }
    if (path === '/mcp') {
      if (!authenticateApi(req, res)) return;
      await handleMcp(req, res);
      return;
    }
    if (path === '/api/v3' || path.startsWith('/api/v3/')) {
      if (!authenticateApi(req, res)) return;
      const segments = path.split('/').filter(Boolean).slice(2);
      await handleRest(req, res, segments);
      return;
    }
    sendError(res, 404, 'Not Found');
  } catch (error) {
    if (!res.headersSent) {
      sendError(res, 500, error instanceof Error ? error.message : 'Internal server error');
    } else {
      res.end();
    }
  }
}

export function createApp(): Server {
  return createServer((req, res) => {
    void handleRequest(req, res);
  });
}

export default createApp;
