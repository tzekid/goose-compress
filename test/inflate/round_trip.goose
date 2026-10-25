// The decoder (inflate.goose) on the package's own streams, gzip, zlib, and
// raw, at levels 0, 1, 6, and 9, of inputs that take each kind of block:
// none, random bytes, which are stored, text, zeros, and a 32 KB block
// repeated, whose matches reach as far as a window does. Each is decoded
// whole, fed 7 bytes at a time, and 1,000 bytes of output a call; and a
// short one a byte at a time with 1 byte a call.
import std;
import compress from "../../";
import check from "../";

fn random(n: i64, seed: u64) -> u8[>..] {
    var out: u8[>..] = [];
    var x = seed;
    for i in n {
        x = x * 6364136223846793005 + 1442695040888963407;
        out.push((x >> 56) as! u8);
    }
    return out;
}

fn text(n: i64) -> u8[>..] {
    let words = ["the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog, ", "and ", "then ",
                 "it ", "rests. ", "Again: "];
    var out: u8[>..] = [];
    var x: u64 = 7;
    while out.len < n {
        x = x * 6364136223846793005 + 1442695040888963407;
        out.append(words[((x >> 33) % words.len as u64) as! i64]);
    }
    out.resize(n);
    return out;
}

fn run(format: i64, data: const u8[:], piece: i64, most: i64) -> u8[>..], bool {
    var d = compress::decoder(format);
    var out: u8[>..] = [];
    var at = 0;
    loop {
        let end = if piece < 0 { data.len } else { min(at + piece, data.len) };
        let used, status = compress::decode(d, data[at..end], out, most);
        at += used;
        if status == compress::DECODE_ERROR { return out, false; }
        if status == compress::DECODE_DONE && at == data.len { return out, true; }
        if status == compress::DECODE_MORE && at == data.len { return out, false; }
    }
}

fn each_way(name: const u8[:], input: const u8[:]) {
    let formats = [compress::GZIP, compress::ZLIB, compress::RAW];
    let format_names = ["gzip", "zlib", "raw"];
    var all = true;
    for format, f in formats {
        for level in [0, 1, 6, 9] {
            var z: u8[>..] = [];
            compress::compress(input, z, format, level);
            let whole, w = run(format, z, -1, -1);
            let pieces, p = run(format, z, 7, -1);
            let limited, l = run(format, z, -1, 1000);
            if !(w && whole == input && p && pieces == input && l && limited == input) {
                print("  ", format_names[f], " level ", level, " differs");
                all = false;
            }
        }
    }
    check::that(str(name, ": every format and level, whole, in 7-byte pieces, and 1,000 bytes a call"), all);
}

fn main() {
    each_way("none", "");
    each_way("300 KB random", random(300000, 2));
    each_way("200 KB text", text(200000));
    var zeros: u8[>..] = [];
    zeros.resize(100000, 0);
    each_way("100 KB zeros", zeros);
    var far = random(32768, 5);
    let half = copy(far);
    far.append(half);
    each_way("32 KB twice", far);
    let formats = [compress::GZIP, compress::ZLIB, compress::RAW];
    let short = text(3000);
    var tiny = true;
    for format in formats {
        var z: u8[>..] = [];
        compress::compress(short, z, format, 6);
        let out, ok = run(format, z, 1, 1);
        if !ok || out != short { tiny = false; }
    }
    check::that("3,000 bytes of text, a byte in and a byte out each call", tiny);
}
