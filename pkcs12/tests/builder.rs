#![cfg(feature = "builder")]

use cms::encrypted_data::EncryptedData;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use der::{
    Decode, Encode,
    asn1::{ContextSpecific, OctetString},
};
use pkcs8::EncryptedPrivateKeyInfoRef;

use pkcs12::{
    AuthenticatedSafe, CertBag, PKCS_12_CERT_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID,
    builder::{EncryptionAlgorithm, MacAlgorithm, PfxBuilder},
    pfx::Pfx,
    safe_bag::SafeContents,
};

const PASSWORD: &str = "builder-test-password";
const ENC_ITERS: u32 = 1_000;
const MAC_ITERS: i32 = 1_000;

/// Build a PFX from the example cert and key, then parse it back and verify
/// that the recovered cert and key bytes match the original files.
///
/// Uses low iteration counts so the test runs quickly; the cryptographic
/// correctness of PBES2/PBKDF2 is tested separately in the pkcs5 crate.
#[test]
fn builder_roundtrip() {
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

    let pfx = Pfx::from_der(&pfx_der).expect("built PFX should parse");

    // Unwrap outer Data ContentInfo → OctetString → AuthenticatedSafe
    let auth_safe_os = OctetString::from_der(&pfx.auth_safe.content.to_der().unwrap()).unwrap();
    let auth_safes = AuthenticatedSafe::from_der(auth_safe_os.as_bytes()).unwrap();
    assert_eq!(2, auth_safes.len());

    // auth_safe[0]: EncryptedData containing the cert bag(s)
    {
        let ci = auth_safes.first().unwrap();
        assert_eq!(ID_ENCRYPTED_DATA, ci.content_type);

        let enc_data = EncryptedData::from_der(&ci.content.to_der().unwrap()).unwrap();
        let params_der = enc_data
            .enc_content_info
            .content_enc_alg
            .parameters
            .as_ref()
            .unwrap()
            .to_der()
            .unwrap();
        let params = pkcs5::pbes2::Parameters::from_der(&params_der).unwrap();
        let scheme = pkcs5::EncryptionScheme::from(params);

        let mut ciphertext = enc_data
            .enc_content_info
            .encrypted_content
            .clone()
            .unwrap()
            .as_bytes()
            .to_vec();
        let plaintext = scheme
            .decrypt_in_place(PASSWORD, &mut ciphertext)
            .expect("cert bag decryption should succeed");

        let cert_bags = SafeContents::from_der(plaintext).unwrap();
        assert_eq!(1, cert_bags.len());
        let sb = cert_bags.first().unwrap();
        assert_eq!(PKCS_12_CERT_BAG_OID, sb.bag_id);

        let cs: ContextSpecific<CertBag> = ContextSpecific::from_der(&sb.bag_value).unwrap();
        assert_eq!(cert_der.as_slice(), cs.value.cert_value.as_bytes());
    }

    // auth_safe[1]: Data ContentInfo containing the key bag
    {
        let ci = auth_safes.get(1).unwrap();
        assert_eq!(ID_DATA, ci.content_type);

        let key_os = OctetString::from_der(&ci.content.to_der().unwrap()).unwrap();
        let key_bags = SafeContents::from_der(key_os.as_bytes()).unwrap();
        assert_eq!(1, key_bags.len());
        let sb = key_bags.first().unwrap();
        assert_eq!(PKCS_12_PKCS8_KEY_BAG_OID, sb.bag_id);

        let cs: ContextSpecific<EncryptedPrivateKeyInfoRef<'_>> =
            ContextSpecific::from_der(&sb.bag_value).unwrap();
        let mut ciphertext = cs.value.encrypted_data.as_bytes().to_vec();
        let plaintext = cs
            .value
            .encryption_algorithm
            .decrypt_in_place(PASSWORD, &mut ciphertext)
            .expect("key decryption should succeed");
        assert_eq!(key_der.as_slice(), plaintext);
    }
}
