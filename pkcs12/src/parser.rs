//! Parser for PKCS#12 PFX (`.p12` / `.pfx`) files.
//!
//! Use [`parse_pfx`] to decode a PKCS#12 archive, verify its MAC, and return
//! the decrypted private key and certificates.
//!
//! # Example
//!
//! ```rust,ignore
//! use pkcs12::parser::parse_pfx;
//!
//! let pfx_der = std::fs::read("archive.p12").unwrap();
//! let contents = parse_pfx(&pfx_der, "hunter2").expect("parse failed");
//!
//! println!("MAC verified: {}", contents.mac_verified);
//! std::fs::write("key.der", contents.key_der.as_ref()).unwrap();
//! ```

use alloc::vec::Vec;

use cms::{content_info::ContentInfo, encrypted_data::EncryptedData};
use const_oid::db::{rfc5911, rfc5912};
use der::{Decode, Encode, asn1::OctetString};
use hmac::{Hmac, KeyInit, Mac};
use pkcs5::pbes2;
use pkcs8::EncryptedPrivateKeyInfoRef;
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    AuthenticatedSafe, CertBag, MacData, PKCS_12_CERT_BAG_OID, PKCS_12_KEY_BAG_OID,
    PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC, PKCS_12_PKCS8_KEY_BAG_OID,
    kdf::{Pkcs12KeyType, derive_key_utf8},
    pbe_params::Pkcs12PbeParams,
    pfx::Pfx,
    safe_bag::SafeContents,
};

/// Length of HMAC-SHA-1 output (and MAC key), in bytes.
const HMAC_SHA1_LEN: usize = 20;

/// Length of HMAC-SHA-256 output (and MAC key), in bytes.
const HMAC_SHA256_LEN: usize = 32;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error returned by [`parse_pfx`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER decoding error.
    Asn1(der::Error),
    /// Decryption failed (wrong password or corrupt ciphertext).
    Decrypt(pkcs5::Error),
    /// MAC digest did not match — the archive is corrupt or the password is wrong.
    MacMismatch,
    /// The archive contains an algorithm we do not support.
    ///
    /// Currently supported encryption: PBES2 (any PBKDF2 PRF, AES or 3DES
    /// cipher) and PKCS#12 legacy PBE with 3-key Triple-DES (SHA-1 KDF).
    /// Currently supported MAC: HMAC-SHA-1, HMAC-SHA-256.
    /// EnvelopedData (public-key-encrypted) bags are not supported.
    UnsupportedAlgorithm,
    /// No private key bag was found in the archive.
    MissingKey,
    /// No certificate bag was found in the archive.
    MissingCert,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "ASN.1 error: {e}"),
            Self::Decrypt(e) => write!(f, "decryption error: {e}"),
            Self::MacMismatch => write!(f, "MAC verification failed"),
            Self::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
            Self::MissingKey => write!(f, "no private key found in archive"),
            Self::MissingCert => write!(f, "no certificate found in archive"),
        }
    }
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Self::Asn1(e)
    }
}

impl From<pkcs5::Error> for Error {
    fn from(e: pkcs5::Error) -> Self {
        Self::Decrypt(e)
    }
}

// ── Output type ───────────────────────────────────────────────────────────────

/// Contents extracted from a PKCS#12 archive by [`parse_pfx`].
#[derive(Debug)]
pub struct Pkcs12Contents {
    /// Decrypted private key in DER-encoded PKCS#8 `PrivateKeyInfo` format.
    ///
    /// Wrapped in [`Zeroizing`] so the bytes are erased on drop.
    pub key_der: Zeroizing<Vec<u8>>,

    /// DER-encoded X.509 end-entity certificate.
    ///
    /// When multiple certificates are present this is the first one encountered
    /// in the archive (the conventional position for the end-entity cert).
    pub certificate: Vec<u8>,

    /// Any additional DER-encoded X.509 certificates (CA chain, etc.).
    pub additional_certificates: Vec<Vec<u8>>,

    /// Whether the `MacData` integrity check was verified.
    ///
    /// `true` — MAC was present and the HMAC matched the archive contents.
    /// `false` — no `MacData` was present (the archive is unverified).
    ///
    /// Note: a `MacMismatch` error is returned instead of `false` when a MAC
    /// is present but the digest does not match.
    pub mac_verified: bool,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse and decrypt a PKCS#12 PFX archive.
///
/// Performs the following steps in order:
///
/// 1. Decode the outer `PFX` structure from `pfx_der`.
/// 2. Verify `MacData` (if present) using HMAC-SHA-1 or HMAC-SHA-256 with a
///    key derived by the PKCS#12 §B.2 KDF.  An absent MAC is not an error;
///    the caller can inspect [`Pkcs12Contents::mac_verified`].
/// 3. Decrypt or unwrap each `SafeContents` bag group.
/// 4. Return the first private key and all certificates found.
///
/// # Errors
///
/// Returns [`Error`] if:
/// - DER decoding fails,
/// - the MAC is present and does not match,
/// - the MAC or encryption algorithm is not supported (SHA-1 and SHA-256 MACs
///   are supported; PBES2 and PKCS#12 legacy 3DES bag encryption are supported),
/// - no private key is found, or
/// - no certificate is found.
pub fn parse_pfx(pfx_der: &[u8], password: &str) -> Result<Pkcs12Contents, Error> {
    // ── 1. Decode outer PFX ───────────────────────────────────────────────────
    let pfx = Pfx::from_der(pfx_der)?;

    // ── 2. Extract the AuthenticatedSafe DER bytes ────────────────────────────
    //
    // RFC 7292 §4: "the content type field of authSafe shall be of type Data".
    // We validate this explicitly so a malformed file gets a clear error rather
    // than a confusing ASN.1 parse failure inside OctetString::from_der.
    //
    // The content field holds the DER encoding of an OctetString wrapping the
    // AuthenticatedSafe SEQUENCE OF.  We need the raw bytes both for MAC
    // verification and for parsing the bag groups.
    if pfx.auth_safe.content_type != rfc5911::ID_DATA {
        return Err(Error::UnsupportedAlgorithm);
    }
    let auth_safe_content_der = pfx.auth_safe.content.to_der()?;
    let auth_safe_os = OctetString::from_der(&auth_safe_content_der)?;
    let auth_safe_der = auth_safe_os.as_bytes();

    // ── 3. MAC verification ───────────────────────────────────────────────────
    let mac_verified = match &pfx.mac_data {
        Some(mac_data) => {
            verify_mac(mac_data, auth_safe_der, password)?;
            true
        }
        // RFC 7292 §4: MacData is OPTIONAL.  An absent MAC means the archive
        // is unverified; we accept it and flag mac_verified = false.
        None => false,
    };

    // ── 4. Parse AuthenticatedSafe ────────────────────────────────────────────
    let auth_safe = AuthenticatedSafe::from_der(auth_safe_der)?;

    // ── 5. Walk bag groups, collect certs and key ─────────────────────────────
    //
    // Two distinct password encodings are in play:
    //   • PBES2 (RFC 8018 §5.2): password is raw UTF-8 bytes — `password.as_bytes()`.
    //   • Legacy PKCS#12 PBE (Appendix C): password is BMP/UTF-16BE, handled
    //     internally by `derive_key_utf8` when given a `&str`.
    // We pass `password` as `&str` to `unwrap_safe_contents` so the legacy
    // PBE path can call `derive_key_utf8` directly.  The shrouded-key path
    // (PBES2 via pkcs8) uses `password.as_bytes()` at the call site below.
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut key_der: Option<Zeroizing<Vec<u8>>> = None;

    for ci in &auth_safe {
        let safe_contents = unwrap_safe_contents(ci, password)?;
        for bag in &safe_contents {
            if bag.bag_id == PKCS_12_CERT_BAG_OID {
                // certBag: bag_value is a DER-encoded CertBag SEQUENCE.
                let cb = CertBag::from_der(&bag.bag_value)?;
                certs.push(cb.cert_value.as_bytes().to_vec());
            } else if bag.bag_id == PKCS_12_PKCS8_KEY_BAG_OID {
                // pkcs8ShroudedKeyBag: bag_value is EncryptedPrivateKeyInfo.
                // Take the first key found; ignore subsequent ones.
                if key_der.is_none() {
                    key_der = Some(decrypt_shrouded_key(&bag.bag_value, password.as_bytes())?);
                }
            } else if bag.bag_id == PKCS_12_KEY_BAG_OID {
                // keyBag: bag_value is a plain PrivateKeyInfo — already decrypted.
                if key_der.is_none() {
                    key_der = Some(Zeroizing::new(bag.bag_value.clone()));
                }
            }
            // All other bag types (secretBag, safeContentsBag, crlBag, …) are
            // silently skipped; they are not needed to reconstruct the key pair.
        }
    }

    // ── 6. Assemble result ────────────────────────────────────────────────────
    let key_der = key_der.ok_or(Error::MissingKey)?;

    if certs.is_empty() {
        return Err(Error::MissingCert);
    }

    let mut cert_iter = certs.into_iter();
    // `expect` is safe: we just verified `certs` is non-empty above.
    #[allow(clippy::unwrap_used)]
    let certificate = cert_iter.next().expect("certs is non-empty");
    let additional_certificates = cert_iter.collect();

    Ok(Pkcs12Contents {
        key_der,
        certificate,
        additional_certificates,
        mac_verified,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Verify the PKCS#12 MAC.
///
/// Supports HMAC-SHA-1 (legacy OpenSSL default) and HMAC-SHA-256.  The MAC
/// key is derived from `password` using the PKCS#12 §B.2 KDF (which encodes
/// the password as BMP/UTF-16BE internally).  Comparison is constant-time via
/// [`hmac::Mac::verify_slice`].
///
/// Why SHA-1: OpenSSL's default for `openssl pkcs12 -export` is HMAC-SHA-1
/// even in current versions.  Rejecting it with `UnsupportedAlgorithm` would
/// break interop with the majority of real-world PFX files.  SHA-1 is weak
/// for collision resistance but HMAC-SHA-1 remains sound for MAC purposes
/// (NIST SP 800-131A Rev 2 still allows HMAC-SHA-1 for legacy use).
fn verify_mac(mac_data: &MacData, auth_safe_der: &[u8], password: &str) -> Result<(), Error> {
    let oid = mac_data.mac.algorithm.oid;

    if oid == rfc5912::ID_SHA_256 {
        let mac_key = Zeroizing::new(derive_key_utf8::<Sha256>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            HMAC_SHA256_LEN,
        )?);
        // `new_from_slice` only fails for zero-length keys; mac_key is always
        // HMAC_SHA256_LEN (32) bytes so this error path is unreachable.
        #[allow(clippy::unwrap_used)]
        let mut hmac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
        hmac.update(auth_safe_der);
        // verify_slice performs a constant-time comparison.
        hmac.verify_slice(mac_data.mac.digest.as_bytes())
            .map_err(|_| Error::MacMismatch)
    } else if oid == rfc5912::ID_SHA_1 {
        let mac_key = Zeroizing::new(derive_key_utf8::<Sha1>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            HMAC_SHA1_LEN,
        )?);
        // `new_from_slice` only fails for zero-length keys; mac_key is always
        // HMAC_SHA1_LEN (20) bytes so this error path is unreachable.
        #[allow(clippy::unwrap_used)]
        let mut hmac = Hmac::<Sha1>::new_from_slice(&mac_key).unwrap();
        hmac.update(auth_safe_der);
        hmac.verify_slice(mac_data.mac.digest.as_bytes())
            .map_err(|_| Error::MacMismatch)
    } else {
        Err(Error::UnsupportedAlgorithm)
    }
}

/// Decrypt or unwrap a `SafeContents` from a `ContentInfo`.
///
/// Handles `id-data` (plaintext) and `id-encryptedData` (PBES2 or legacy
/// PKCS#12 PBE encrypted) bag groups.  Unknown content types (e.g. `id-envelopedData`,
/// public-key-encrypted bags) are **skipped** rather than treated as errors.
/// This matches the RFC 7292 §4.1 intent that an `AuthenticatedSafe` is a
/// sequence of independently interpretable bag groups: one unrecognised group
/// must not prevent extraction of certs and keys from the others.
fn unwrap_safe_contents(ci: &ContentInfo, password: &str) -> Result<SafeContents, Error> {
    if ci.content_type == rfc5911::ID_DATA {
        // id-data: content is OctetString(SafeContents DER).
        let content_der = ci.content.to_der()?;
        let os = OctetString::from_der(&content_der)?;
        Ok(SafeContents::from_der(os.as_bytes())?)
    } else if ci.content_type == rfc5911::ID_ENCRYPTED_DATA {
        // id-encryptedData: content is EncryptedData; decrypt to get SafeContents.
        // `password` is passed as &str so the legacy-PBE path inside can reach
        // the PKCS#12 §B.2 KDF; PBES2 converts to bytes internally.
        let content_der = ci.content.to_der()?;
        let enc_data = EncryptedData::from_der(&content_der)?;
        let plaintext = decrypt_encrypted_data(&enc_data, password)?;
        Ok(SafeContents::from_der(&plaintext)?)
    } else {
        // Unknown bag group type (e.g. id-envelopedData for public-key-encrypted
        // bags).  Return an empty SafeContents so the caller's loop continues;
        // we do not abort the whole parse for one unsupported group.
        Ok(SafeContents::new())
    }
}

/// Decrypt an `EncryptedData` bag group and return the plaintext.
///
/// Handles PBES2 (modern, OpenSSL default with AES) and PKCS#12 legacy PBE
/// (`pbeWithSHAAnd3-KeyTripleDES-CBC`, the pre-PBES2 default used by older
/// Java, older macOS, and some OpenSSL invocations with `-certpbe` overrides).
///
/// `password` is `&str` (not `&[u8]`) because the legacy-PBE path needs it
/// for the PKCS#12 §B.2 KDF, which encodes the password as BMP/UTF-16BE.
/// PBES2 converts it to raw bytes via `.as_bytes()` internally.
fn decrypt_encrypted_data(enc_data: &EncryptedData, password: &str) -> Result<Vec<u8>, Error> {
    let alg = &enc_data.enc_content_info.content_enc_alg;

    // Dispatch on the outer OID.  PKCS#12 legacy PBE has its own KDF and
    // cipher; handle it before attempting PBES2 parameter parsing which would
    // fail on the different parameter structure.
    if alg.oid == PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC {
        let ciphertext = enc_data
            .enc_content_info
            .encrypted_content
            .as_ref()
            .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?
            .as_bytes();
        return decrypt_pkcs12_pbe_3des(alg, ciphertext, password);
    }

    // PBES2 path: extract parameters and delegate to pkcs5.
    let params_any = alg
        .parameters
        .as_ref()
        .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;
    let params = pbes2::Parameters::from_der(&params_any.to_der()?)?;
    let scheme = pkcs5::EncryptionScheme::from(params);

    // `decrypt_in_place` overwrites `buf` with the plaintext in-place.  Wrap
    // in `Zeroizing` so the buffer is erased on drop even if the result is cert
    // data (not secret), for uniform defence-in-depth.
    let mut buf = Zeroizing::new(
        enc_data
            .enc_content_info
            .encrypted_content
            .as_ref()
            .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?
            .as_bytes()
            .to_vec(),
    );

    // PBES2 uses raw UTF-8 bytes (RFC 8018 §5.2 treats the password as an
    // opaque octet string).
    let plaintext = scheme.decrypt_in_place(password.as_bytes(), &mut buf)?;
    Ok(plaintext.to_vec())
}

/// Decrypt a bag group protected with `pbeWithSHAAnd3-KeyTripleDES-CBC`.
///
/// This is the PKCS#12 Appendix C legacy PBE scheme: the PKCS#12 §B.2 KDF
/// (SHA-1, BMP/UTF-16BE password encoding) derives a 24-byte 3DES key and an
/// 8-byte IV; 3-key Triple-DES CBC with PKCS#7 padding is then applied.
///
/// Why `&str`: the PKCS#12 §B.2 KDF encodes the password as BMP/UTF-16BE
/// internally.  `derive_key_utf8` handles that encoding, so we forward the
/// original `&str` instead of pre-converting to bytes.
fn decrypt_pkcs12_pbe_3des(
    alg_id: &spki::AlgorithmIdentifier<der::Any>,
    ciphertext: &[u8],
    password: &str,
) -> Result<Vec<u8>, Error> {
    // Parse the pkcs-12PbeParams SEQUENCE { salt OCTET STRING, iterations INTEGER }.
    let params_any = alg_id
        .parameters
        .as_ref()
        .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;
    let pbe_params = Pkcs12PbeParams::from_der(&params_any.to_der()?)?;

    // 3-key Triple-DES key = 24 bytes; DES block/IV = 8 bytes.
    let key = Zeroizing::new(derive_key_utf8::<Sha1>(
        password,
        pbe_params.salt.as_bytes(),
        Pkcs12KeyType::EncryptionKey,
        pbe_params.iterations,
        24,
    )?);
    // The IV is derived from the password (not stored in the PBE params, unlike
    // PBES2).  Wrap in Zeroizing for consistency with `key` and to avoid leaving
    // password-derived material on the heap after the function returns.
    let iv = Zeroizing::new(derive_key_utf8::<Sha1>(
        password,
        pbe_params.salt.as_bytes(),
        Pkcs12KeyType::Iv,
        pbe_params.iterations,
        8,
    )?);

    use des::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};

    // `new_from_slices` only fails when key/IV lengths are wrong.  We derived
    // exactly 24 and 8 bytes above, matching TdesEde3's requirements, so
    // this error path is unreachable.
    #[allow(clippy::unwrap_used)]
    cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
        .unwrap()
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| pkcs5::Error::DecryptFailed.into())
}

/// Decrypt a `pkcs8ShroudedKeyBag` value (DER-encoded `EncryptedPrivateKeyInfo`).
///
/// Returns the decrypted PKCS#8 `PrivateKeyInfo` DER bytes, wrapped in
/// [`Zeroizing`] so they are erased on drop.
fn decrypt_shrouded_key(bag_value: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let epki = EncryptedPrivateKeyInfoRef::from_der(bag_value)?;

    // `decrypt_in_place` overwrites `buf` with the plaintext in-place.
    // `buf` MUST be `Zeroizing` — after decryption it holds the raw private key
    // bytes.  Without zeroization the key would linger in heap memory after the
    // buffer is dropped, even though the *returned* value is zeroized.
    let mut buf = Zeroizing::new(epki.encrypted_data.as_bytes().to_vec());
    let plaintext = epki
        .encryption_algorithm
        .decrypt_in_place(password, &mut buf)?;

    Ok(Zeroizing::new(plaintext.to_vec()))
}
