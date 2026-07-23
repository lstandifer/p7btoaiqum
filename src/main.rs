mod cert;

use std::fs;
use std::io;
use std::path::Path;

use cert::convert_p7b;

fn clean_path(raw: &str) -> String {
    raw.trim().trim_matches('"').trim().to_string()
}

fn derive_output(input: &str) -> String {
    Path::new(input)
        .with_extension("pem")
        .to_string_lossy()
        .to_string()
}

fn print_usage() {
    println!(
        "Usage: p7btoaiqum <input.p7b> [output.pem] [--no-root]\n\n\
         Converts a PKCS#7 (.p7b) certificate bundle into a PEM chain\n\
         ordered leaf → intermediate → root, compatible with\n\
         NetApp Active IQ Unified Manager.\n\n\
         --no-root   omit the root CA from the output chain\n\
         Output defaults to the input path with a .pem extension."
    );
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        return Ok(());
    }

    let include_root = !args.iter().any(|a| a == "--no-root");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let input = match positional.first() {
        Some(p) => clean_path(p),
        None => {
            eprintln!("error: no input file given");
            std::process::exit(2);
        }
    };
    let output = positional
        .get(1)
        .map(|p| clean_path(p))
        .unwrap_or_else(|| derive_output(&input));

    let data = fs::read(&input).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{input}': {e}");
        std::process::exit(1);
    });
    let result = convert_p7b(&data, include_root).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    fs::write(&output, result.pem_output.as_bytes())?;

    let written = result
        .certs
        .iter()
        .filter(|c| !(c.is_root && !include_root))
        .count();
    println!("Wrote {written} certificate(s) to {output}:");
    for c in &result.certs {
        if c.is_root && !include_root {
            continue;
        }
        let role = if c.is_leaf {
            "leaf "
        } else if c.is_root {
            "root "
        } else {
            "inter"
        };
        println!(
            "  [{role}] {}  (issuer: {})  valid {} … {}",
            c.subject_cn, c.issuer_cn, c.not_before, c.not_after
        );
    }
    Ok(())
}
