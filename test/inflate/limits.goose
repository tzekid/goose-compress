// The decoder (inflate.goose) at a call's output limit and across streams:
// a stream whose output fills the limit exactly, which ends in that call;
// bytes after a raw and a zlib stream decoded a few bytes a call, which stay
// the caller's; a stream whose end the last full call holds, which the next
// call ends with no input; a gzip file name after a stream cut inside its
// extra field; and a megabyte of empty fixed blocks, whose codes aren't built
// again for each block.
import std;
import os;
import compress from "../../";
import check from "../";

// "hello world", as zlib and as raw DEFLATE.
let HELLO_ZLIB: u8[19] = [
    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x01, 0x00,
    0x1a, 0x0b, 0x04, 0x5d];
let HELLO_RAW: u8[13] = [
    0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x01, 0x00];
// 40,000 'a', as zlib.
let AS_ZLIB: u8[62] = [
    0x78, 0x9c, 0xed, 0xc1, 0x31, 0x01, 0x00, 0x00, 0x00, 0xc2, 0xa0, 0xac, 0xeb, 0x5f, 0xc2,
    0xcb, 0x16, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x53, 0xd1,
    0x37, 0xb6];
// A gzip header cut short inside its extra field, and a gzip with the file
// name "file.txt" holding "hello world".
let CUT_EXTRA: u8[12] = [0x1f, 0x8b, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0xff];
let NAMED: u8[40] = [
    0x1f, 0x8b, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x66, 0x69, 0x6c, 0x65, 0x2e,
    0x74, 0x78, 0x74, 0x00, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49,
    0x01, 0x00, 0x85, 0x11, 0x4a, 0x0d, 0x0b, 0x00, 0x00, 0x00];

// Decodes data a call at a time, each call making at most most bytes and
// called again after DECODE_FULL whatever input is left: the last status,
// how much input was used, and how many calls it took.
fn in_calls(d: compress::Decoder&, data: const u8[:], out: u8[>..]&, most: i64) -> i64, i64, i64 {
    var at = 0;
    var calls = 0;
    loop {
        let used, status = compress::decode(d, data[at..], out, most);
        at += used;
        calls++;
        if status != compress::DECODE_FULL { return status, at, calls; }
    }
}

fn main() {
    var out: u8[>..] = [];
    check::that("zlib's 11 bytes in a limit of 11", compress::decompress(HELLO_ZLIB, out, compress::ZLIB, 11)
                && out == "hello world");
    var r = compress::decoder(compress::RAW);
    out.clear();
    let ru, rs = compress::decode(r, HELLO_RAW, out, 11);
    check::that(str("raw's 11 bytes in a call of 11: done, used ", ru), rs == compress::DECODE_DONE && ru == 13);

    var tail: u8[>..] = [];
    tail.append(HELLO_RAW);
    tail.append("xyz");
    var t = compress::decoder(compress::RAW);
    out.clear();
    let ts, tu, tc = in_calls(t, tail, out, 4);
    check::that(str("after a raw stream, 4 bytes a call: done, used ", tu, " of ", tail.len),
                ts == compress::DECODE_DONE && tu == 13 && out == "hello world");
    tail.clear();
    tail.append(HELLO_ZLIB);
    tail.append("xyz");
    var z = compress::decoder(compress::ZLIB);
    out.clear();
    let zs, zu, zc = in_calls(z, tail, out, 1);
    check::that(str("after a zlib stream, 1 byte a call: done, used ", zu, " of ", tail.len),
                zs == compress::DECODE_DONE && zu == 19 && out == "hello world");

    var a = compress::decoder(compress::ZLIB);
    out.clear();
    let fs, fu, fc = in_calls(a, AS_ZLIB, out, 10000);
    check::that(str("40,000 bytes, 10,000 a call: done in ", fc, " calls, used ", fu),
                fs == compress::DECODE_DONE && fu == AS_ZLIB.len && out.len == 40000 && fc == 4);

    out.clear();
    let cut = compress::decompress(CUT_EXTRA, out, compress::GZIP);
    out.clear();
    let named = compress::decompress(NAMED, out, compress::GZIP);
    check::that("a file name after a stream cut in its extra field", !cut && named && out == "hello world");

    // Empty fixed blocks: each is 10 bits, the only 1 its type's low bit,
    // and the last one's final bit too.
    let blocks = 838860;
    var empty: u8[>..] = [];
    empty.resize((10 * blocks + 7) / 8, 0);
    for k in blocks { empty[(10 * k + 1) / 8] = empty[(10 * k + 1) / 8] | (1 << ((10 * k + 1) % 8)) as! u8; }
    empty[(10 * (blocks - 1)) / 8] = empty[(10 * (blocks - 1)) / 8] | (1 << ((10 * (blocks - 1)) % 8)) as! u8;
    var e = compress::decoder(compress::RAW);
    out.clear();
    let began = clock();
    let eu, es = compress::decode(e, empty, out);
    let took = clock() - began;
    check::that(str("1 MB of empty fixed blocks: done, nothing made, in under a second"),
                es == compress::DECODE_DONE && out.len == 0 && took < 1.0);
}
