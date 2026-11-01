// Decompression: a gzip (RFC 1952), zlib (RFC 1950), or raw DEFLATE (RFC 1951)
// stream, fed in pieces, with a limit on the output of each call, so that a
// program bounds what a stream from outside can make it hold. The decoder
// keeps the stream's last 32 KB for its matches and up to 64 bits of input;
// everything else goes to the caller's output as it's decoded.
namespace compress;

import std;
import .checksum;

// What decode returns beside the bytes of input it used.
let DECODE_MORE = 0;    // every byte was used, and the stream goes on
let DECODE_FULL = 1;    // the call's output limit was reached: call again with input[used..], even an empty one
let DECODE_DONE = 2;    // the stream has ended, at input[used]
let DECODE_ERROR = -1;  // the stream is corrupt, or one the decoder refuses: Decoder.error says why

// A symbol's code is looked up in a table of its first ROOT bits; a longer one
// is decoded a bit at a time from its lengths' counts.
let ROOT = 10;
let ROOT_MASK: u64 = 1023;

// The most of a gzip header's file name or comment the decoder takes.
let GZIP_TEXT_MAX = 4096;

// Where a decoder is in its stream.
let D_HEADER = 0;
let D_BLOCK = 1;
let D_STORED_LEN = 2;
let D_STORED = 3;
let D_TABLES = 4;
let D_CLEN = 5;
let D_LENGTHS = 6;
let D_CODES = 7;
let D_DISTANCE = 8;
let D_COPY = 9;
let D_TRAILER = 10;
let D_DONE = 11;
let D_FAILED = 12;

let LENGTH_BASE: u16[29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
                            67, 83, 99, 115, 131, 163, 195, 227, 258];
let LENGTH_EXTRA: u8[29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5,
                            5, 5, 5, 0];
let DIST_BASE: u16[30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
                          769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
let DIST_EXTRA: u8[30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
                          11, 11, 12, 12, 13, 13];
// The order a dynamic block sends its code length code's lengths in.
let CLEN_ORDER: u8[19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// A Huffman code's decoding: a table of its first ROOT bits, each entry the
// symbol << 4 | its length, 0 for a longer code; and for those, the count of
// each length and the symbols in canonical order.
struct Code {
    table: u16[1 << ROOT] = [0; 1 << ROOT],
    counts: u16[16] = [0; 16],
    symbols: u16[320] = [0; 320],
}

// A stream being decompressed.
struct Decoder {
    format: i64 = GZIP,
    state: i64 = D_HEADER,
    // Why decode returned DECODE_ERROR.
    error: const u8[:] = "",
    // Input taken but not used yet, its first bit the low one.
    bits: u64 = 0,
    nbits: i64 = 0,
    // The block being read is the stream's last; and lit and dist hold the
    // fixed codes, which a run of fixed blocks then needn't build again.
    last: bool = false,
    fixed: bool = false,
    stored_left: i64 = 0,
    lit: Code = Code { .. },
    dist: Code = Code { .. },
    // A dynamic block's header: its counts of codes, and the lengths read so
    // far, of the code length code's first.
    hlit: i64 = 0,
    hdist: i64 = 0,
    hclen: i64 = 0,
    have: i64 = 0,
    lens: u8[320] = [0; 320],
    // A match not yet whole: its length left and distance.
    copy_len: i64 = 0,
    copy_dist: i64 = 0,
    // The last 32 KB the stream made, and how many bytes it has made, of its
    // member for gzip, and their CRC-32 or Adler-32.
    window: u8[WSIZE] = [0; WSIZE],
    total: i64 = 0,
    check: u32 = 0,
    // A gzip header: its flags, where it is in the header, what's left of
    // the field it's in, and the header's CRC so far.
    flags: u8 = 0,
    header_at: i64 = 0,
    field_left: i64 = 0,
    header_crc: u32 = 0,
}

fn decoder(format: i64 = GZIP) -> Decoder {
    assert(format == GZIP || format == ZLIB || format == RAW);
    return Decoder { format: format, check: if format == ZLIB { 1 } else { 0 },
                     state: if format == RAW { D_BLOCK } else { D_HEADER }, .. };
}

// Starts d over as a new stream of format, in place: a Decoder holds 37 KB,
// which building one copies.
fn reset(d: Decoder&, format: i64 = GZIP) {
    assert(format == GZIP || format == ZLIB || format == RAW);
    d.format = format;
    d.error = "";
    d.bits = 0;
    d.nbits = 0;
    start_member(d);
}

// Starts the stream's next gzip member, or its only part, keeping the input
// held.
fn start_member(d: Decoder&) {
    d.state = if d.format == RAW { D_BLOCK } else { D_HEADER };
    d.last = false;
    d.copy_len = 0;
    d.total = 0;
    d.check = if d.format == ZLIB { 1 } else { 0 };
    d.header_at = 0;
    d.field_left = 0;
    d.header_crc = 0;
}

var ONE_SHOT_DECODER: Decoder[>..] = [];

// Decompresses the stream whole and appends it to out: true once it has
// ended, with nothing after it, in at most most bytes (-1: no limit).
fn decompress(data: const u8[:], out: u8[>..]&, format: i64 = GZIP, most: i64 = -1) -> bool {
    if ONE_SHOT_DECODER.len == 0 { ONE_SHOT_DECODER.push(decoder()); }
    let d .= ONE_SHOT_DECODER[0];
    reset(d, format);
    let used, status = decode(d, data, out, most);
    return status == DECODE_DONE && used == data.len;
}

// Decodes what input holds of the stream, appending what it makes to out, up
// to most bytes this call (-1: no limit). Returns how many bytes of input it
// used and DECODE_MORE, DECODE_FULL, DECODE_DONE, or DECODE_ERROR. The
// input may be split anywhere across calls, and the output is the same. A
// gzip stream may hold several members: a member that begins where one
// ends, in this call or the next, goes on the stream, and other bytes after
// a member are DECODE_ERROR. After a zlib or raw stream, they're the
// caller's: DECODE_DONE says where they start.
fn decode(d: Decoder&, input: const u8[:], out: u8[>..]&, most: i64 = -1) -> i64, i64 {
    let start = out.len;
    var checked = out.len;
    var at = 0;
    if d.state == D_DONE && input.len > 0 {
        guard d.format == GZIP && input[0] == 0x1f else { return 0, fail(d, "bytes after the stream"); }
        start_member(d);
    }
    loop {
        let room = if most < 0 { -1 } else { most - (out.len - start) };
        let progressed, status = step(d, input, at, out, room);
        if d.format != RAW && out.len > checked {
            d.check = if d.format == GZIP { crc32(d.check, out[checked..]) } else { adler32(d.check, out[checked..]) };
            checked = out.len;
        }
        if status == DECODE_DONE && d.format == GZIP && at < input.len && input[at] == 0x1f {
            start_member(d);
            continue;
        }
        if status == DECODE_FULL {
            // The whole bytes taken this call and not used yet go back to
            // input, so that used ends where the stream does: what follows
            // a zlib or raw stream stays the caller's.
            let back = min(d.nbits / 8, at);
            if back > 0 {
                at -= back;
                d.nbits -= 8 * back;
                d.bits &= ((1 as u64) << (d.nbits as u64)) - 1;
            }
        }
        if status != DECODE_MORE || !progressed { return at, status; }
    }
}

// Takes input's bytes into d.bits until it holds at least 57 bits, or input
// has no more.
fn fill(d: Decoder&, input: const u8[:], at: i64&) {
    while d.nbits <= 56 && at < input.len {
        d.bits |= (input[at] as u64) << (d.nbits as u64);
        d.nbits += 8;
        at++;
    }
}

fn take_bits(d: Decoder&, n: i64) -> u64 {
    let v = d.bits & (((1 as u64) << (n as u64)) - 1);
    d.bits >>= n as u64;
    d.nbits -= n;
    return v;
}

fn fail(d: Decoder&, why: const u8[:]) -> i64 {
    d.state = D_FAILED;
    d.error = why;
    return DECODE_ERROR;
}

// One step of the stream: whether it made progress, and DECODE_MORE to go
// on, or the status to return.
fn step(d: Decoder&, input: const u8[:], at: i64&, out: u8[>..]&, room: i64) -> bool, i64 {
    fill(d, input, at);
    let s = d.state;
    if s == D_FAILED { return false, DECODE_ERROR; }
    if s == D_DONE { return false, DECODE_DONE; }
    if s == D_HEADER { return header_step(d); }
    if s == D_BLOCK {
        if d.last {
            d.state = if d.format == RAW { D_DONE } else { D_TRAILER };
            if d.format == RAW { return true, end_stream(d, input, at); }
            return true, DECODE_MORE;
        }
        guard d.nbits >= 3 else { return false, DECODE_MORE; }
        d.last = take_bits(d, 1) == 1;
        let kind = take_bits(d, 2);
        if kind == 0 {
            take_bits(d, d.nbits % 8);
            d.state = D_STORED_LEN;
        } else if kind == 1 {
            fixed_codes(d);
            d.state = D_CODES;
        } else if kind == 2 {
            d.state = D_TABLES;
        } else {
            return true, fail(d, "a block of the reserved type");
        }
        return true, DECODE_MORE;
    }
    if s == D_STORED_LEN {
        guard d.nbits >= 32 else { return false, DECODE_MORE; }
        let len = take_bits(d, 16);
        let nlen = take_bits(d, 16);
        guard len == (~nlen & 0xffff) else { return true, fail(d, "a stored block's length and its complement differ"); }
        d.stored_left = len as i64;
        d.state = D_STORED;
        return true, DECODE_MORE;
    }
    if s == D_STORED { return stored_step(d, input, at, out, room); }
    if s == D_TABLES {
        guard d.nbits >= 14 else { return false, DECODE_MORE; }
        d.hlit = take_bits(d, 5) as i64 + 257;
        d.hdist = take_bits(d, 5) as i64 + 1;
        d.hclen = take_bits(d, 4) as i64 + 4;
        guard d.hlit <= 286 && d.hdist <= 30 else { return true, fail(d, "a dynamic block with too many codes"); }
        for i in 19 { d.lens[i] = 0; }
        d.have = 0;
        d.state = D_CLEN;
        return true, DECODE_MORE;
    }
    if s == D_CLEN {
        var progressed = false;
        while d.have < d.hclen {
            guard d.nbits >= 3 else { return progressed, DECODE_MORE; }
            d.lens[CLEN_ORDER[d.have]] = take_bits(d, 3) as! u8;
            d.have++;
            progressed = true;
        }
        d.fixed = false;
        let left = build(d.lit, d.lens[..19]);
        guard left >= 0 else { return true, fail(d, "a code length code that's over-subscribed"); }
        guard left == 0 else { return true, fail(d, "a code length code that isn't complete"); }
        d.have = 0;
        d.state = D_LENGTHS;
        return true, DECODE_MORE;
    }
    if s == D_LENGTHS { return lengths_step(d); }
    if s == D_COPY { return copy_step(d, out, room); }
    if s == D_CODES || s == D_DISTANCE { return codes_step(d, out, room); }
    if s == D_TRAILER {
        // The last block is over: what's left of its last byte isn't the
        // stream's. A gzip trailer's 64 bits are more than fill holds before
        // the alignment.
        take_bits(d, d.nbits % 8);
        fill(d, input, at);
        guard d.nbits >= (if d.format == GZIP { 64 } else { 32 }) else { return false, DECODE_MORE; }
        if d.format == GZIP {
            let crc = take_bits(d, 32) as! u32;
            let size = take_bits(d, 32) as! u32;
            guard crc == d.check else { return true, fail(d, "a gzip CRC that doesn't match"); }
            guard size == (d.total as! u32) else { return true, fail(d, "a gzip length that doesn't match"); }
        } else {
            var adler: u32 = 0;
            for i in 4 { adler = adler << 8 | take_bits(d, 8) as! u32; }
            guard adler == d.check else { return true, fail(d, "a zlib Adler-32 that doesn't match"); }
        }
        d.state = D_DONE;
        return true, end_stream(d, input, at);
    }
    return false, fail(d, "a state the decoder doesn't know");
}

// At the stream's end, gives back to input the whole bytes taken past it, as
// far as this call took them, so the call's used ends at the stream's end.
// Bytes taken in an earlier call stay held, as what follows the stream: the
// start of a gzip member, or DECODE_ERROR.
fn end_stream(d: Decoder&, input: const u8[:], at: i64&) -> i64 {
    take_bits(d, d.nbits % 8);
    let held = d.nbits / 8;
    if held <= at {
        at -= held;
        d.bits = 0;
        d.nbits = 0;
        return DECODE_DONE;
    }
    guard d.format == GZIP && (d.bits & 0xff) == 0x1f else { return fail(d, "bytes after the stream"); }
    start_member(d);
    return DECODE_MORE;
}

// A stored block's bytes: those in d.bits first, then input's, up to room.
fn stored_step(d: Decoder&, input: const u8[:], at: i64&, out: u8[>..]&, room: i64) -> bool, i64 {
    if d.stored_left == 0 {
        d.state = D_BLOCK;
        return true, DECODE_MORE;
    }
    guard room != 0 else { return false, DECODE_FULL; }
    let most = if room < 0 { d.stored_left } else { min(d.stored_left, room) };
    var made = 0;
    while made < most && d.nbits >= 8 {
        emit(d, out, take_bits(d, 8) as! u8);
        made++;
    }
    let n = min(most - made, input.len - at);
    for b in input[at..at + n] { emit(d, out, b); }
    at += n;
    made += n;
    d.stored_left -= made;
    if d.stored_left > 0 && made == room { return true, DECODE_FULL; }
    return made > 0, DECODE_MORE;
}

// Appends b to out and to the window.
fn emit(d: Decoder&, out: u8[>..]&, b: u8) {
    out.push(b);
    d.window[d.total & (WSIZE - 1)] = b;
    d.total++;
}

// The gzip or zlib header, a byte at a time for gzip's.
fn header_step(d: Decoder&) -> bool, i64 {
    if d.format == ZLIB {
        guard d.nbits >= 16 else { return false, DECODE_MORE; }
        let cmf = take_bits(d, 8);
        let flg = take_bits(d, 8);
        guard (cmf & 15) == 8 && (cmf >> 4) <= 7 else { return true, fail(d, "a zlib stream not of DEFLATE"); }
        guard (cmf * 256 + flg) % 31 == 0 else { return true, fail(d, "a zlib header whose check fails"); }
        guard (flg & 0x20) == 0 else { return true, fail(d, "a zlib stream that needs a preset dictionary"); }
        d.state = D_BLOCK;
        return true, DECODE_MORE;
    }
    // ID1 ID2 CM FLG MTIME(4) XFL OS, then FEXTRA, FNAME, FCOMMENT, and FHCRC
    // as FLG names them: header_at is 0 to 9 in the fixed part, 10 and 11 in
    // FEXTRA's length, 20 in its bytes, 12 and 13 in the texts, 14 at FHCRC.
    let i = d.header_at;
    if i == 14 {
        if (d.flags & 2) != 0 {
            guard d.nbits >= 16 else { return false, DECODE_MORE; }
            let crc = take_bits(d, 16) as! u32;
            guard crc == (d.header_crc & 0xffff) else { return true, fail(d, "a gzip header whose CRC fails"); }
        }
        d.state = D_BLOCK;
        return true, DECODE_MORE;
    }
    if (i == 12 && (d.flags & 8) == 0) || (i == 13 && (d.flags & 16) == 0) || (i == 20 && d.field_left == 0) {
        d.header_at = if i == 20 { 12 } else { i + 1 };
        d.field_left = 0;
        return true, DECODE_MORE;
    }
    guard d.nbits >= 8 else { return false, DECODE_MORE; }
    let b = take_bits(d, 8) as! u8;
    let one: u8[1] = [b];
    d.header_crc = crc32(d.header_crc, one);
    if i < 10 {
        if i == 0 && b != 0x1f || i == 1 && b != 0x8b { return true, fail(d, "not a gzip stream"); }
        if i == 2 && b != 8 { return true, fail(d, "a gzip stream not of DEFLATE"); }
        if i == 3 {
            guard (b & 0xe0) == 0 else { return true, fail(d, "gzip flags reserved for later"); }
            d.flags = b;
        }
        d.header_at = if i < 9 { i + 1 } else if (d.flags & 4) != 0 { 10 } else { 12 };
    } else if i == 10 {
        d.field_left = b;
        d.header_at = 11;
    } else if i == 11 {
        d.field_left |= (b as i64) << 8;
        d.header_at = 20;
    } else if i == 20 {
        d.field_left--;
    } else {
        d.field_left++;
        guard d.field_left <= GZIP_TEXT_MAX else { return true, fail(d, "a gzip file name or comment too long"); }
        if b == 0 {
            d.header_at = i + 1;
            d.field_left = 0;
        }
    }
    return true, DECODE_MORE;
}

// Builds code c from lengths, one per symbol: 0 if the code is complete, more
// if it's incomplete, less if it's over-subscribed.
fn build(c: Code&, lengths: const u8[:]) -> i64 {
    for i in 16 { c.counts[i] = 0; }
    for l in lengths { c.counts[l]++; }
    c.counts[0] = 0;
    var left: i64 = 1;
    for len in 15 {
        left = left * 2 - c.counts[len + 1];
        if left < 0 { return left; }
    }
    var offs: u16[16] = [0; 16];
    for len in 14 { offs[len + 2] = offs[len + 1] + c.counts[len + 1]; }
    for l, sym in lengths {
        if l != 0 {
            c.symbols[offs[l]] = sym as! u16;
            offs[l]++;
        }
    }
    for i in 1 << ROOT { c.table[i] = 0; }
    var code: u64 = 0;
    var index = 0;
    for len1 in ROOT {
        let len = len1 + 1;
        for k in c.counts[len] as i64 {
            let sym = c.symbols[index + k];
            var rev: u64 = 0;
            for b in len { rev |= ((code >> (b as u64)) & 1) << ((len - 1 - b) as u64); }
            let entry = sym << 4 | len as! u16;
            for f in 1 << (ROOT - len) { c.table[rev | (f as u64) << (len as u64)] = entry; }
            code++;
        }
        index += c.counts[len];
        code <<= 1;
    }
    return left;
}

// The next symbol of code c, and how many bits it takes, without taking
// them: 0 bits while d.bits doesn't hold all of it yet, -1 for bits that
// aren't one of c's codes.
fn peek(d: const Decoder&, c: const Code&) -> i64, i64 {
    let e = c.table[d.bits & ROOT_MASK];
    if e != 0 {
        let len = (e & 15) as i64;
        let sym: i64 = e >> 4;
        return sym, if len <= d.nbits { len } else { 0 };
    }
    var code = 0;
    var first = 0;
    var index = 0;
    var b = d.bits;
    for i in 15 {
        let len = i + 1;
        guard len <= d.nbits else { return 0, 0; }
        code |= (b & 1) as i64;
        b >>= 1;
        let count = c.counts[len] as i64;
        if code - count < first {
            let sym: i64 = c.symbols[index + code - first];
            return sym, len;
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return 0, -1;
}

fn fixed_codes(d: Decoder&) {
    guard !d.fixed else { return; }
    d.fixed = true;
    var lengths: u8[288] = [0; 288];
    for i in 288 { lengths[i] = if i < 144 { 8 } else if i < 256 { 9 } else if i < 280 { 7 } else { 8 }; }
    build(d.lit, lengths);
    let dl: u8[30] = [5; 30];
    build(d.dist, dl);
}

// The literal/length and distance codes' lengths, by the code length code in
// d.lit, then the two codes.
fn lengths_step(d: Decoder&) -> bool, i64 {
    let total = d.hlit + d.hdist;
    var progressed = false;
    while d.have < total {
        let sym, len = peek(d, d.lit);
        guard len >= 0 else { return true, fail(d, "a code length that isn't one of the code's"); }
        guard len > 0 else { return progressed, DECODE_MORE; }
        if sym < 16 {
            take_bits(d, len);
            d.lens[d.have] = sym as! u8;
            d.have++;
        } else {
            let extra = if sym == 16 { 2 } else if sym == 17 { 3 } else { 7 };
            guard d.nbits >= len + extra else { return progressed, DECODE_MORE; }
            take_bits(d, len);
            let base = if sym == 18 { 11 } else { 3 };
            let n = take_bits(d, extra) as i64 + base;
            guard sym != 16 || d.have > 0 else { return true, fail(d, "a repeat with no length before it"); }
            guard d.have + n <= total else { return true, fail(d, "lengths past the codes' count"); }
            let v: u8 = if sym == 16 { d.lens[d.have - 1] } else { 0 };
            for k in n { d.lens[d.have + k] = v; }
            d.have += n;
        }
        progressed = true;
    }
    guard d.lens[256] != 0 else { return true, fail(d, "a block with no end-of-block code"); }
    let lit_left = build(d.lit, d.lens[..d.hlit]);
    guard lit_left == 0 || lit_left > 0 && single(d.lit) else {
        return true, fail(d, "a literal/length code that isn't complete");
    }
    let dist_left = build(d.dist, d.lens[d.hlit..total]);
    guard dist_left == 0 || dist_left > 0 && single(d.dist) else {
        return true, fail(d, "a distance code that isn't complete");
    }
    d.state = D_CODES;
    return true, DECODE_MORE;
}

// Whether c is the one kind of incomplete code a stream may send: a single
// code of one bit, or none.
fn single(c: const Code&) -> bool {
    var used = 0;
    for len in 15 { used += c.counts[len + 1]; }
    let ones: i64 = c.counts[1];
    return used <= 1 && ones == used;
}

// A block's literals and matches, until its end or the call's room.
fn codes_step(d: Decoder&, out: u8[>..]&, room: i64) -> bool, i64 {
    let begin = out.len;
    // Whether this call has taken bits or made bytes.
    var moved = false;
    loop {
        let made = out.len - begin;
        if d.state == D_CODES {
            // The block's end makes nothing, so it's taken with no room left,
            // and a stream that fills the room exactly ends in this call.
            let sym, len = peek(d, d.lit);
            guard len >= 0 else { return true, fail(d, "a literal/length that isn't one of the code's"); }
            guard len > 0 else { return moved, DECODE_MORE; }
            guard sym == 256 || room < 0 || made < room else { return moved, DECODE_FULL; }
            if sym < 256 {
                take_bits(d, len);
                emit(d, out, sym as! u8);
                moved = true;
                continue;
            }
            if sym == 256 {
                take_bits(d, len);
                d.state = D_BLOCK;
                return true, DECODE_MORE;
            }
            guard sym <= 285 else { return true, fail(d, "a length code past 285"); }
            let extra = LENGTH_EXTRA[sym - 257] as i64;
            guard d.nbits >= len + extra else { return moved, DECODE_MORE; }
            take_bits(d, len);
            let base: i64 = LENGTH_BASE[sym - 257];
            d.copy_len = base + take_bits(d, extra) as i64;
            d.state = D_DISTANCE;
            moved = true;
        }
        let sym, len = peek(d, d.dist);
        guard len >= 0 else { return true, fail(d, "a distance that isn't one of the code's"); }
        guard len > 0 else { return moved, DECODE_MORE; }
        guard sym <= 29 else { return true, fail(d, "a distance code past 29"); }
        let extra = DIST_EXTRA[sym] as i64;
        guard d.nbits >= len + extra else { return moved, DECODE_MORE; }
        take_bits(d, len);
        let base: i64 = DIST_BASE[sym];
        d.copy_dist = base + take_bits(d, extra) as i64;
        guard d.copy_dist <= min(d.total, WSIZE) else { return true, fail(d, "a distance back past the stream's start"); }
        d.state = D_COPY;
        let progressed, s = copy_step(d, out, if room < 0 { -1 } else { room - (out.len - begin) });
        guard s == DECODE_MORE else { return true, s; }
    }
}

// The match d holds, up to room.
fn copy_step(d: Decoder&, out: u8[>..]&, room: i64) -> bool, i64 {
    var n = d.copy_len;
    if room >= 0 { n = min(n, room); }
    for k in n { emit(d, out, d.window[(d.total - d.copy_dist) & (WSIZE - 1)]); }
    d.copy_len -= n;
    if d.copy_len > 0 { return n > 0, DECODE_FULL; }
    d.state = D_CODES;
    return true, DECODE_MORE;
}
