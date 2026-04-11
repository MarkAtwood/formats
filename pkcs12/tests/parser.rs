#![cfg(feature = "parser")]

#[cfg(feature = "builder")]
use pkcs12::builder::{EncryptionAlgorithm, MacAlgorithm, PfxBuilder};
use pkcs12::parser::parse_pfx;

#[cfg(feature = "builder")]
const PASSWORD: &str = "parser-test-password";
#[cfg(feature = "builder")]
const ENC_ITERS: u32 = 1_000;
#[cfg(feature = "builder")]
const MAC_ITERS: i32 = 1_000;

/// Build a PFX with PfxBuilder, then parse it back with parse_pfx.
///
/// Verifies that:
/// - MAC verification succeeds
/// - the recovered cert bytes match the original
/// - the recovered key bytes match the original
#[cfg(feature = "builder")]
#[test]
fn parser_roundtrip() {
    let cert_der = include_bytes!("examples/cert.der");
    let key_der = include_bytes!("examples/key.der");

    let pfx_der = PfxBuilder::new(PASSWORD)
        .with_cert(cert_der.as_slice())
        .with_key(key_der.as_slice())
        .with_cert_encryption(EncryptionAlgorithm::Pbes2Aes256Cbc {
            iterations: ENC_ITERS,
        })
        .with_key_encryption(EncryptionAlgorithm::Pbes2Aes256Cbc {
            iterations: ENC_ITERS,
        })
        .with_mac_algorithm(MacAlgorithm::HmacSha256 {
            iterations: MAC_ITERS,
        })
        .build_with_rng(&mut rand::rng())
        .expect("builder should succeed");

    let contents = parse_pfx(&pfx_der, PASSWORD).expect("parser should succeed");

    assert!(contents.mac_verified, "MAC should be verified");
    assert_eq!(cert_der.as_slice(), contents.certificate.as_slice());
    assert_eq!(key_der.as_slice(), contents.key_der.as_slice());
    assert!(
        contents.additional_certificates.is_empty(),
        "no CA certs were added"
    );
}

/// Build a PFX with a CA cert chain, parse it back, and verify all certs are
/// recovered in order (EE cert first, CA cert in additional_certificates).
#[cfg(feature = "builder")]
#[test]
fn parser_roundtrip_with_ca_cert() {
    let cert_der = include_bytes!("examples/cert.der");
    let ca_der = include_bytes!("examples/GoodCACert.der");
    let key_der = include_bytes!("examples/key.der");

    let pfx_der = PfxBuilder::new(PASSWORD)
        .with_cert(cert_der.as_slice())
        .with_ca_cert(ca_der.as_slice())
        .with_key(key_der.as_slice())
        .with_cert_encryption(EncryptionAlgorithm::Pbes2Aes256Cbc {
            iterations: ENC_ITERS,
        })
        .with_key_encryption(EncryptionAlgorithm::Pbes2Aes256Cbc {
            iterations: ENC_ITERS,
        })
        .with_mac_algorithm(MacAlgorithm::HmacSha256 {
            iterations: MAC_ITERS,
        })
        .build_with_rng(&mut rand::rng())
        .expect("builder should succeed");

    let contents = parse_pfx(&pfx_der, PASSWORD).expect("parser should succeed");

    assert!(contents.mac_verified);
    assert_eq!(cert_der.as_slice(), contents.certificate.as_slice());
    assert_eq!(key_der.as_slice(), contents.key_der.as_slice());
    assert_eq!(1, contents.additional_certificates.len());
    assert_eq!(
        ca_der.as_slice(),
        contents.additional_certificates[0].as_slice()
    );
}

/// A wrong password must cause decryption to fail, not silently return garbage.
#[cfg(feature = "builder")]
#[test]
fn parser_wrong_password_errors() {
    let cert_der = include_bytes!("examples/cert.der");
    let key_der = include_bytes!("examples/key.der");

    let pfx_der = PfxBuilder::new(PASSWORD)
        .with_cert(cert_der.as_slice())
        .with_key(key_der.as_slice())
        .build_with_rng(&mut rand::rng())
        .expect("builder should succeed");

    // Wrong password should produce a MAC mismatch or a decryption error —
    // either is acceptable; what is NOT acceptable is Ok with wrong bytes.
    let result = parse_pfx(&pfx_der, "definitely-wrong-password");
    assert!(
        result.is_err(),
        "wrong password must return an error, not silently succeed"
    );
}

/// Corrupt the MAC digest bytes; parse_pfx must return MacMismatch.
#[cfg(feature = "builder")]
#[test]
fn parser_mac_mismatch_errors() {
    let cert_der = include_bytes!("examples/cert.der");
    let key_der = include_bytes!("examples/key.der");

    let mut pfx_der = PfxBuilder::new(PASSWORD)
        .with_cert(cert_der.as_slice())
        .with_key(key_der.as_slice())
        .build_with_rng(&mut rand::rng())
        .expect("builder should succeed");

    // Flip the last byte of the serialized PFX.  The MAC digest is near the
    // end of the structure so this reliably corrupts it.
    let last = pfx_der.len() - 1;
    pfx_der[last] ^= 0xff;

    let result = parse_pfx(&pfx_der, PASSWORD);
    assert!(
        matches!(
            result,
            Err(pkcs12::parser::Error::MacMismatch) | Err(pkcs12::parser::Error::Asn1(_))
        ),
        "corrupt MAC must return MacMismatch or Asn1, got: {result:?}"
    );
}

/// Parse an OpenSSL-generated PFX with HMAC-SHA-1 MAC and legacy
/// `pbeWithSHAAnd3-KeyTripleDES-CBC` cert bag encryption.
///
/// `example14.pfx` was generated with:
///   openssl pkcs12 -export -out example14.pfx -inkey key.pem -in cert.pem \
///     -macalg sha1 -certpbe pbeWithSHA1And3-KeyTripleDES-CBC \
///     -keypbe AES-256-CBC -iter 2048 -maciter 2048 -passout pass:1234
///
/// The key bag uses PBES2/AES-256-CBC with HMAC-SHA1 PRF, so `sha1-insecure`
/// is required in addition to `parser`.
///
/// The expected cert and key DER bytes were extracted independently via:
///   openssl pkcs12 -in example14.pfx -passin pass:1234 -nodes -nokeys | openssl x509 -outform DER
///   openssl pkcs12 -in example14.pfx -passin pass:1234 -nodes -nocerts | openssl pkcs8 -topk8 -nocrypt -outform DER
///
/// Oracle checksums (SHA-256):
///   cert: 2774218a5f619160565dd4999eb64b03ea593e5f3d9ac7a65b8c43a7251a4b88
///   key:  126877df1e57f3f80cc765fe2d37644852fb17fda3ceb0df8e621c0676982a0d
#[cfg(feature = "sha1-insecure")]
#[test]
fn parser_legacy_3des_cert_bag_openssl_fixture() {
    let pfx_der = include_bytes!("examples/example14.pfx");
    let expected_cert = include_bytes!("examples/example14_cert.der");
    let expected_key = include_bytes!("examples/example14_key.der");

    let contents = parse_pfx(pfx_der, "1234").expect("should parse example14.pfx");

    assert!(
        contents.mac_verified,
        "HMAC-SHA-1 MAC must verify for example14.pfx"
    );
    assert_eq!(
        expected_cert.as_slice(),
        contents.certificate.as_slice(),
        "certificate must match OpenSSL-extracted DER"
    );
    assert_eq!(
        expected_key.as_slice(),
        contents.key_der.as_slice(),
        "private key must match OpenSSL-extracted DER"
    );
}

/// Parse an OpenSSL-generated PFX with HMAC-SHA-1 MAC (the OpenSSL default).
///
/// `example4.pfx` was generated by OpenSSL with:
///   openssl pkcs12 -export -out example4.pfx -inkey key.pem -in cert.pem \
///     -macalg sha1 -certpbe AES-192-CBC -keypbe AES-256-CBC -passout pass:1234
///
/// Both bag groups use PBES2 with HMAC-SHA1 as the PBKDF2 PRF, so
/// `sha1-insecure` is required in addition to `parser`.
///
/// The expected cert and key DER bytes were extracted independently via:
///   openssl pkcs12 -in example4.pfx -passin pass:1234 -nodes -nokeys | openssl x509 -outform DER
///   openssl pkcs12 -in example4.pfx -passin pass:1234 -nodes -nocerts | openssl pkcs8 -topk8 -nocrypt -outform DER
///
/// Oracle checksums (SHA-256):
///   cert: 2774218a5f619160565dd4999eb64b03ea593e5f3d9ac7a65b8c43a7251a4b88
///   key:  126877df1e57f3f80cc765fe2d37644852fb17fda3ceb0df8e621c0676982a0d
#[cfg(feature = "sha1-insecure")]
#[test]
fn parser_sha1_mac_openssl_fixture() {
    let pfx_der = include_bytes!("examples/example4.pfx");
    let expected_cert = include_bytes!("examples/example4_cert.der");
    let expected_key = include_bytes!("examples/example4_key.der");

    let contents = parse_pfx(pfx_der, "1234").expect("should parse example4.pfx");

    assert!(
        contents.mac_verified,
        "HMAC-SHA-1 MAC must verify for example4.pfx"
    );
    assert_eq!(
        expected_cert.as_slice(),
        contents.certificate.as_slice(),
        "certificate must match OpenSSL-extracted DER"
    );
    assert_eq!(
        expected_key.as_slice(),
        contents.key_der.as_slice(),
        "private key must match OpenSSL-extracted DER"
    );
}
