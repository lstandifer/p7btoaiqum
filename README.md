# p7btoaiqum

A small Rust command-line tool that converts a PKCS#7 **`.p7b`** certificate
bundle into a **PEM** chain that NetApp **Active IQ Unified Manager (AIQUM)**
accepts for its HTTPS certificate import.

Certificate authorities frequently return a `.p7b` bundle in which the
certificates are in arbitrary order and may be DER- or PEM-armored. AIQUM wants a
single PEM file with the chain ordered **leaf → intermediate → root**. This tool
does that reordering for you.

Everything runs in pure Rust — **no `openssl` or other host utilities are
required** at runtime. The compiled `.exe` is self-contained.

## Features

- Reads both **DER** and **PEM** (`-----BEGIN PKCS7-----`) encoded `.p7b` files,
  including **BER / indefinite-length** encodings produced by Windows and many
  enterprise CA tools (a strict DER parser rejects these — this tool falls back
  to a lenient BER parser automatically).
- Extracts every certificate and orders the chain **leaf → intermediate → root**,
  regardless of the order inside the bundle.
- Optionally includes or omits the root CA in the output.
- Standard RFC 7468 PEM with LF line endings (matches the Linux-based AIQUM appliance).

## Build

```sh
cargo build --release
```

The binary lands at `target/release/p7btoaiqum` (`.exe` on Windows).

## Usage

```sh
p7btoaiqum <input.p7b> [output.pem] [--no-root]
```

- `output.pem` defaults to the input path with a `.pem` extension.
- `--no-root` omits the root CA from the output chain.
- `-h` / `--help` prints usage.

Paths may be passed with surrounding quotes (e.g. Windows "Copy as path") — the
quotes are stripped automatically.

Run with no arguments to see the usage message.

Example:

```sh
$ p7btoaiqum cert.p7b aiqum.pem
Wrote 3 certificate(s) to aiqum.pem:
  [leaf ] aiqum.example.com  (issuer: Test Intermediate CA)  valid 2025-01-01 0:00:00 … 2026-01-01 0:00:00
  [inter] Test Intermediate CA  (issuer: Test Root CA)  valid 2024-01-01 0:00:00 … 2034-01-01 0:00:00
  [root ] Test Root CA  (issuer: Test Root CA)  valid 2020-01-01 0:00:00 … 2040-01-01 0:00:00
```

Each certificate is listed with a role tag (`leaf`, `inter`, `root`), its subject
common name, issuer common name, and validity window. With `--no-root`, the root
CA is still listed but not written to the output file.

## Installing the certificate in AIQUM

1. Convert your `.p7b` to a `.pem` with this tool.
2. In AIQUM, go to **General → HTTPS Certificate**.
3. Choose **Install HTTPS Certificate** (this must correspond to the same private
   key and CSR that produced the certificate).
4. Paste the contents of the generated `.pem` — the leaf certificate first,
   followed by the intermediate CA(s) and root CA.
5. Restart AIQUM services if prompted and re-verify the certificate in the browser.

> The private key is **not** part of a `.p7b` and is not handled by this tool.
> AIQUM already holds the private key it generated when you created the CSR.

## Tests

```sh
cargo test
```

The unit tests in `src/cert.rs` run against a real 3-certificate chain fixture
(with the certificates deliberately scrambled inside the bundle) and assert that:

- the output is ordered leaf → intermediate → root,
- PEM-armored `.p7b` input parses,
- BER / indefinite-length input parses (via the lenient fallback parser) even
  though the strict DER parser rejects it,
- `--no-root` drops the self-signed root, and
- garbage input is rejected with an error.

## License

Provided as-is for internal certificate conversion use.
