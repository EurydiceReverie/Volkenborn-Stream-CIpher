use std::env;
use std::io::{self, Read, Write};
use volkenborn2::{open, open_auto_stream, openp_stream, seal, seal_auto_stream, sealp_stream, Volkenborn2, IV_BYTES, KEY_BYTES};

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 { return None; }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn usage(program: &str) {
    eprintln!("usage:");
    eprintln!("  {program} enc    <64-hex-key> <32-hex-iv> < input > ciphertext");
    eprintln!("  {program} dec    <64-hex-key> <32-hex-iv> < ciphertext > plaintext");
    eprintln!("  {program} seal   <64-hex-key> <32-hex-iv> < plaintext > ciphertext_plus_32_byte_tag");
    eprintln!("  {program} open   <64-hex-key> <32-hex-iv> < ciphertext_plus_32_byte_tag > plaintext");
    eprintln!("  {program} sealp  <64-hex-key> <32-hex-nonce> < plaintext > ciphertext_plus_32_byte_poly1305_tag");
    eprintln!("  {program} openp  <64-hex-key> <32-hex-nonce> < ciphertext_plus_32_byte_poly1305_tag > plaintext");
    eprintln!("  {program} seal-auto <64-hex-key> < plaintext > nonce_plus_ciphertext_plus_32_byte_poly1305_tag");
    eprintln!("  {program} open-auto <64-hex-key> < nonce_plus_ciphertext_plus_32_byte_poly1305_tag > plaintext");
    eprintln!("  {program} stream <64-hex-key> <32-hex-iv> <bytes> > keystream");
    eprintln!("warning: experimental unaudited research cipher; not for production secrets.");
}

fn stream_crypt(mode: &str, key: &[u8; KEY_BYTES], iv: &[u8; IV_BYTES]) -> io::Result<()> {
    let mut cipher = Volkenborn2::new(key, iv);
    let mut input = [0u8; 4096];
    let mut output = [0u8; 4096];
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    loop {
        let n = stdin.read(&mut input)?;
        if n == 0 { break; }
        if mode == "enc" { cipher.encrypt(&input[..n], &mut output[..n]); }
        else { cipher.decrypt(&input[..n], &mut output[..n]); }
        stdout.write_all(&output[..n])?;
    }
    stdout.flush()
}

fn write_stream(key: &[u8; KEY_BYTES], iv: &[u8; IV_BYTES], mut len: usize) -> io::Result<()> {
    let mut cipher = Volkenborn2::new(key, iv);
    let mut stdout = io::stdout().lock();
    while len != 0 {
        let block = cipher.keystream_block();
        let take = len.min(32);
        stdout.write_all(&block[..take])?;
        len -= take;
    }
    stdout.flush()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage(args.first().map(String::as_str).unwrap_or("v2tool"));
        std::process::exit(2);
    }
    let mode = args[1].as_str();
    let key = match parse_hex::<KEY_BYTES>(&args[2]) {
        Some(k) => k,
        None => { usage(&args[0]); std::process::exit(2); }
    };
    let iv = if mode == "seal-auto" || mode == "open-auto" {
        [0u8; IV_BYTES]
    } else {
        if args.len() < 4 { usage(&args[0]); std::process::exit(2); }
        match parse_hex::<IV_BYTES>(&args[3]) {
            Some(v) => v,
            None => { usage(&args[0]); std::process::exit(2); }
        }
    };

    match mode {
        "enc" | "dec" if args.len() == 4 => stream_crypt(mode, &key, &iv),
        "stream" if args.len() == 5 => {
            let len = match args[4].parse::<usize>() {
                Ok(n) => n,
                Err(_) => { usage(&args[0]); std::process::exit(2); }
            };
            write_stream(&key, &iv, len)
        }
        "seal" if args.len() == 4 => {
            let mut plain = Vec::new();
            io::stdin().lock().read_to_end(&mut plain)?;
            let (ciphertext, tag) = seal(&key, &iv, &plain);
            let mut stdout = io::stdout().lock();
            stdout.write_all(&ciphertext)?;
            stdout.write_all(&tag)?;
            stdout.flush()
        }
        "open" if args.len() == 4 => {
            let mut input = Vec::new();
            io::stdin().lock().read_to_end(&mut input)?;
            if input.len() < TAG_BYTES { std::process::exit(3); }
            let clen = input.len() - TAG_BYTES;
            let mut tag = [0u8; TAG_BYTES];
            tag.copy_from_slice(&input[clen..]);
            match open(&key, &iv, &input[..clen], &tag) {
                Some(plain) => {
                    let mut stdout = io::stdout().lock();
                    stdout.write_all(&plain)?;
                    stdout.flush()
                }
                None => std::process::exit(3),
            }
        }
        "sealp" if args.len() == 4 => {
            let mut input = io::stdin().lock();
            let mut output = io::stdout().lock();
            sealp_stream(&key, &iv, &mut input, &mut output)?;
            output.flush()
        }
        "openp" if args.len() == 4 => {
            let mut input = io::stdin().lock();
            let mut output = io::stdout().lock();
            if !openp_stream(&key, &iv, &mut input, &mut output)? {
                std::process::exit(3);
            }
            output.flush()
        }
        "seal-auto" if args.len() == 3 => {
            let mut input = io::stdin().lock();
            let mut output = io::stdout().lock();
            seal_auto_stream(&key, &mut input, &mut output)?;
            output.flush()
        }
        "open-auto" if args.len() == 3 => {
            let mut input = io::stdin().lock();
            let mut output = io::stdout().lock();
            if !open_auto_stream(&key, &mut input, &mut output)? {
                std::process::exit(3);
            }
            output.flush()
        }
        _ => { usage(&args[0]); std::process::exit(2); }
    }
}
