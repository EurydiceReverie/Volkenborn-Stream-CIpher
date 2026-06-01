$ErrorActionPreference = 'Stop'

Write-Host '== C Address/Undefined/Leak sanitizer build =='
$cc = if (Get-Command clang -ErrorAction SilentlyContinue) { 'clang' } else { 'cc' }
& $cc -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -Ivolkenborn2-c/include volkenborn2-c/src/volkenborn2.c volkenborn2-c/tests/test_vectors.c -o tmp_rovodev_c_sanitize.exe
& .\tmp_rovodev_c_sanitize.exe

Write-Host '== Rust sanitizer guidance =='
Write-Host 'For nightly Rust ASan on supported targets:'
Write-Host '  rustup toolchain install nightly'
Write-Host '  $env:RUSTFLAGS="-Zsanitizer=address"; cargo +nightly test --manifest-path volkenborn2-rust/Cargo.toml -Zbuild-std --target x86_64-pc-windows-msvc'
Write-Host 'Stable Rust tests:'
cargo test --manifest-path volkenborn2-rust/Cargo.toml

Remove-Item tmp_rovodev_c_sanitize.exe -ErrorAction SilentlyContinue
