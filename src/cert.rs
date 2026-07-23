use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode, EncodePem};
use der::pem::LineEnding;
use x509_cert::Certificate;

#[derive(Clone)]
pub struct CertInfo {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub not_before: String,
    pub not_after: String,
    pub is_root: bool,
    pub is_leaf: bool,
    pub pem: String,
}

pub struct ConversionResult {
    pub certs: Vec<CertInfo>,
    pub pem_output: String,
}

#[derive(Debug)]
pub enum ConvertError {
    Parse(String),
    NoCertificates,
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvertError::Parse(m) => write!(f, "Could not parse PKCS#7 data: {m}"),
            ConvertError::NoCertificates => {
                write!(f, "No certificates were found inside the p7b file")
            }
        }
    }
}

impl std::error::Error for ConvertError {}

/// Strip PEM armor if present, returning raw DER/BER bytes.
fn to_binary(data: &[u8]) -> Result<Vec<u8>, ConvertError> {
    let looks_pem = data
        .iter()
        .take(64)
        .collect::<Vec<_>>()
        .windows(5)
        .any(|w| w == [&b'-', &b'-', &b'-', &b'-', &b'-']);

    if looks_pem {
        let block = pem::parse(data).map_err(|e| ConvertError::Parse(e.to_string()))?;
        Ok(block.into_contents())
    } else {
        Ok(data.to_vec())
    }
}

/// Extract certificates from a strictly DER-encoded PKCS#7 SignedData.
fn extract_certificates_der(der_bytes: &[u8]) -> Result<Vec<Certificate>, ConvertError> {
    let ci = ContentInfo::from_der(der_bytes)
        .map_err(|e| ConvertError::Parse(e.to_string()))?;
    let signed: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| ConvertError::Parse(format!("not a SignedData structure: {e}")))?;

    let mut out = Vec::new();
    if let Some(set) = &signed.certificates {
        for choice in set.0.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = choice {
                out.push(cert.clone());
            }
        }
    }

    if out.is_empty() {
        return Err(ConvertError::NoCertificates);
    }
    Ok(out)
}

/// Extract certificates from a BER-encoded PKCS#7 SignedData.
/// Handles indefinite-length encoding from Windows/enterprise CA exports.
fn extract_certificates_ber(bin: &[u8]) -> Result<Vec<Certificate>, ConvertError> {
    use rasn_cms::pkcs7_compat::SignedData as P7SignedData;
    use rasn_cms::{CertificateChoices, ContentInfo as RasnContentInfo};

    let ci: RasnContentInfo = rasn::ber::decode(bin)
        .map_err(|e| ConvertError::Parse(format!("BER decode failed: {e}")))?;
    let signed: P7SignedData = rasn::ber::decode(ci.content.as_bytes())
        .map_err(|e| ConvertError::Parse(format!("BER SignedData decode failed: {e}")))?;

    let mut out = Vec::new();
    if let Some(set) = &signed.certificates {
        for choice in set.to_vec() {
            if let CertificateChoices::Certificate(cert) = choice {
                let der = rasn::der::encode(cert.as_ref())
                    .map_err(|e| ConvertError::Parse(format!("re-encode failed: {e}")))?;
                let xc = Certificate::from_der(&der)
                    .map_err(|e| ConvertError::Parse(e.to_string()))?;
                out.push(xc);
            }
        }
    }

    if out.is_empty() {
        return Err(ConvertError::NoCertificates);
    }
    Ok(out)
}

/// Extract X.509 certificates from p7b bytes. Tries strict DER first, falls back to lenient BER.
fn extract_certificates(bin: &[u8]) -> Result<Vec<Certificate>, ConvertError> {
    match extract_certificates_der(bin) {
        Ok(certs) => Ok(certs),
        Err(_) => extract_certificates_ber(bin),
    }
}

/// Extract the CommonName (CN) from a distinguished name, falling back to the full string.
fn common_name(name: &x509_cert::name::Name) -> String {
    let full = name.to_string();
    for part in full.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.to_string();
        }
    }
    if full.is_empty() { "(no subject)".to_string() } else { full }
}

/// DER encoding of a distinguished name, used to match subjects to issuers.
fn name_der(name: &x509_cert::name::Name) -> Vec<u8> {
    name.to_der().unwrap_or_default()
}

/// Order certificates into a chain: leaf first, root last.
fn order_chain(certs: &[Certificate]) -> Vec<usize> {
    let subjects: Vec<Vec<u8>> = certs
        .iter()
        .map(|c| name_der(&c.tbs_certificate.subject))
        .collect();
    let issuers: Vec<Vec<u8>> = certs
        .iter()
        .map(|c| name_der(&c.tbs_certificate.issuer))
        .collect();

    let leaf = (0..certs.len())
        .find(|&i| !issuers.iter().enumerate().any(|(j, iss)| j != i && *iss == subjects[i]))
        .unwrap_or(0);

    let mut order = Vec::with_capacity(certs.len());
    let mut visited = vec![false; certs.len()];
    let mut current = leaf;

    loop {
        if visited[current] {
            break;
        }
        visited[current] = true;
        order.push(current);

        if subjects[current] == issuers[current] {
            break;
        }
        match (0..certs.len())
            .find(|&j| !visited[j] && subjects[j] == issuers[current])
        {
            Some(next) => current = next,
            None => break,
        }
    }

    for (i, seen) in visited.iter().enumerate() {
        if !seen {
            order.push(i);
        }
    }
    order
}

/// Convert raw p7b bytes into an ordered PEM chain.
pub fn convert_p7b(data: &[u8], include_root: bool) -> Result<ConversionResult, ConvertError> {
    let bin = to_binary(data)?;
    let certs = extract_certificates(&bin)?;
    let order = order_chain(&certs);

    let mut infos = Vec::with_capacity(order.len());
    for &idx in &order {
        let cert = &certs[idx];
        let subject = &cert.tbs_certificate.subject;
        let issuer = &cert.tbs_certificate.issuer;
        let is_root = name_der(subject) == name_der(issuer);
        let is_leaf = idx == order[0];

        let pem = cert
            .to_pem(LineEnding::LF)
            .map_err(|e| ConvertError::Parse(e.to_string()))?;

        infos.push(CertInfo {
            subject_cn: common_name(subject),
            issuer_cn: common_name(issuer),
            not_before: cert.tbs_certificate.validity.not_before.to_string(),
            not_after: cert.tbs_certificate.validity.not_after.to_string(),
            is_root,
            is_leaf,
            pem,
        });
    }

    let mut pem_output = String::new();
    for info in &infos {
        if info.is_root && !include_root {
            continue;
        }
        pem_output.push_str(&info.pem);
    }

    if pem_output.is_empty() {
        return Err(ConvertError::NoCertificates);
    }

    Ok(ConversionResult {
        certs: infos,
        pem_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DER_P7B: &[u8] = include_bytes!("../tests/fixtures/chain.p7b");
    const PEM_P7B: &[u8] = include_bytes!("../tests/fixtures/chain_pem.p7b");

    #[test]
    fn orders_der_chain_leaf_to_root() {
        let r = convert_p7b(DER_P7B, true).expect("convert der");
        assert_eq!(r.certs.len(), 3);

        assert_eq!(r.certs[0].subject_cn, "aiqum.example.com");
        assert!(r.certs[0].is_leaf && !r.certs[0].is_root);

        assert_eq!(r.certs[1].subject_cn, "Test Intermediate CA");
        assert!(!r.certs[1].is_leaf && !r.certs[1].is_root);

        assert_eq!(r.certs[2].subject_cn, "Test Root CA");
        assert!(r.certs[2].is_root);

        let positions: Vec<usize> = ["aiqum", "Intermediate", "Root"]
            .iter()
            .map(|needle| find_cert_order_marker(&r, needle))
            .collect();
        assert!(positions[0] < positions[1] && positions[1] < positions[2]);
        assert_eq!(r.pem_output.matches("BEGIN CERTIFICATE").count(), 3);
    }

    #[test]
    fn parses_pem_armored_p7b() {
        let r = convert_p7b(PEM_P7B, true).expect("convert pem");
        assert_eq!(r.certs.len(), 3);
        assert_eq!(r.certs[0].subject_cn, "aiqum.example.com");
    }

    #[test]
    fn excludes_root_when_requested() {
        let r = convert_p7b(DER_P7B, false).expect("convert");
        assert_eq!(r.certs.len(), 3);
        assert_eq!(r.pem_output.matches("BEGIN CERTIFICATE").count(), 2);
    }

    #[test]
    fn rejects_garbage() {
        assert!(convert_p7b(b"not a certificate at all", true).is_err());
    }

    #[test]
    fn parses_ber_indefinite_length() {
        let ber = to_indefinite_length(DER_P7B);
        assert!(
            ber.windows(2).any(|w| w == [0x00, 0x00]),
            "expected indefinite-length end-of-contents markers"
        );
        assert!(extract_certificates_der(&ber).is_err());

        let r = convert_p7b(&ber, true).expect("convert indefinite-length BER");
        assert_eq!(r.certs.len(), 3);
        assert_eq!(r.certs[0].subject_cn, "aiqum.example.com");
        assert_eq!(r.certs[2].subject_cn, "Test Root CA");
        assert_eq!(r.pem_output.matches("BEGIN CERTIFICATE").count(), 3);
    }

    fn to_indefinite_length(der: &[u8]) -> Vec<u8> {
        fn encode_len(len: usize, out: &mut Vec<u8>) {
            if len < 0x80 {
                out.push(len as u8);
            } else {
                let mut bytes = len.to_be_bytes().to_vec();
                while bytes.len() > 1 && bytes[0] == 0 {
                    bytes.remove(0);
                }
                out.push(0x80 | bytes.len() as u8);
                out.extend_from_slice(&bytes);
            }
        }
        fn tlv(input: &[u8], pos: &mut usize, out: &mut Vec<u8>) {
            let tag_start = *pos;
            let first = input[*pos];
            *pos += 1;
            if first & 0x1f == 0x1f {
                while input[*pos] & 0x80 != 0 {
                    *pos += 1;
                }
                *pos += 1;
            }
            let tag_bytes = input[tag_start..*pos].to_vec();
            let constructed = first & 0x20 != 0;

            let len_byte = input[*pos];
            *pos += 1;
            let len = if len_byte & 0x80 == 0 {
                len_byte as usize
            } else {
                let n = (len_byte & 0x7f) as usize;
                let mut l = 0usize;
                for _ in 0..n {
                    l = (l << 8) | input[*pos] as usize;
                    *pos += 1;
                }
                l
            };
            let content_start = *pos;
            let content_end = content_start + len;

            out.extend_from_slice(&tag_bytes);
            if constructed {
                out.push(0x80);
                let mut cpos = content_start;
                while cpos < content_end {
                    tlv(input, &mut cpos, out);
                }
                out.extend_from_slice(&[0x00, 0x00]);
            } else {
                encode_len(len, out);
                out.extend_from_slice(&input[content_start..content_end]);
            }
            *pos = content_end;
        }

        let mut out = Vec::new();
        let mut pos = 0;
        tlv(der, &mut pos, &mut out);
        out
    }

    fn find_cert_order_marker(r: &ConversionResult, subject_needle: &str) -> usize {
        let info = r
            .certs
            .iter()
            .find(|c| c.subject_cn.contains(subject_needle))
            .expect("cert present");
        r.pem_output.find(info.pem.trim()).unwrap_or(usize::MAX)
    }
}
