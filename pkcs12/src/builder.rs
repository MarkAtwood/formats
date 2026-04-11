//! Builder for PKCS#12 PFX (`.p12` / `.pfx`) files.
//!
//! Use [`PfxBuilder`] to create a new PKCS#12 archive containing a certificate,
//! private key, and optional CA certificate chain.  Both the certificate bags
//! and the private key are encrypted with PBES2/PBKDF2-SHA-256/AES-256-CBC.
//! `MacData` integrity is protected with HMAC-SHA-256 keyed via the PKCS#12
//! §B.2 KDF.
//!
//! # Example
//!
//! ```rust,ignore
//! use pkcs12::builder::PfxBuilder;
//!
//! let pfx_der = PfxBuilder::new("hunter2")
//!     .with_cert(cert_der)
//!     .with_key(key_der)
//!     .build_with_rng(&mut rand::rng())
//!     .expect("PFX build failed");
//!
//! std::fs::write("output.p12", &pfx_der).unwrap();
//! ```

use alloc::{string::String, vec::Vec};

use cms::{
    content_info::{CmsVersion, ContentInfo},
    encrypted_data::EncryptedData,
    enveloped_data::EncryptedContentInfo,
};
use const_oid::db::{rfc5911, rfc5912};
use der::{Any, Decode, Encode, asn1::OctetString};
use hmac::{Hmac, KeyInit, Mac};
use pkcs5::pbes2;
use rand_core::CryptoRng;
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use pkcs8::EncryptedPrivateKeyInfoOwned;

use crate::{
    CertBag, DigestInfo, MacData, PKCS_12_CERT_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID,
    PKCS_12_X509_CERT_OID, SafeBag,
    kdf::{Pkcs12KeyType, derive_key_utf8},
    pfx::{Pfx, Version},
    safe_bag::SafeContents,
};

/// Length of HMAC-SHA-256 output (and MAC key), in bytes.
const HMAC_SHA256_LEN: usize = 32;

/// Length of the PBKDF2 salt for content encryption, in bytes.
const PBKDF2_SALT_LEN: usize = 16;

/// AES block size (= AES-CBC IV length), in bytes.
const AES_IV_LEN: usize = 16;

/// Length of the MAC salt used with the PKCS#12 §B.2 KDF, in bytes.
const MAC_SALT_LEN: usize = 8;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error returned by [`PfxBuilder::build_with_rng`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER encoding or decoding error.
    Asn1(der::Error),
    /// PBES2 encryption error.
    Encrypt(pkcs5::Error),
    /// A required field was not set before calling
    /// [`build_with_rng`][PfxBuilder::build_with_rng].
    ///
    /// The string names the missing field (e.g. `"cert"` or `"key"`).
    MissingField(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "ASN.1 error: {e}"),
            Self::Encrypt(e) => write!(f, "encryption error: {e}"),
            Self::MissingField(name) => write!(f, "required field not set: {name}"),
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
        Self::Encrypt(e)
    }
}

// ── Algorithm selection ───────────────────────────────────────────────────────

/// Encryption algorithm for PKCS#12 bag content.
///
/// `#[non_exhaustive]` permits adding new variants (e.g., PBES2-AES-GCM) in
/// future minor releases without a breaking change.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum EncryptionAlgorithm {
    /// PBES2 with PBKDF2-SHA-256 and AES-256-CBC.
    ///
    /// OWASP recommends ≥ 600 000 iterations for PBKDF2-SHA-256.
    Pbes2Aes256Cbc {
        /// PBKDF2 iteration count.
        iterations: u32,
    },
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::Pbes2Aes256Cbc {
            iterations: 600_000,
        }
    }
}

/// MAC algorithm for PKCS#12 `MacData`.
///
/// `#[non_exhaustive]` permits adding new variants in future minor releases.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum MacAlgorithm {
    /// HMAC-SHA-256 with a key derived by the PKCS#12 §B.2 KDF.
    HmacSha256 {
        /// PKCS#12 KDF iteration count for MAC key derivation.
        iterations: i32,
    },
}

impl Default for MacAlgorithm {
    fn default() -> Self {
        Self::HmacSha256 {
            iterations: 100_000,
        }
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for PKCS#12 PFX (`.p12` / `.pfx`) files.
///
/// The builder uses a consuming-setter pattern: each `with_*` method takes
/// `self` by value and returns a new `PfxBuilder`.
///
/// # Structure of the generated file
///
/// - `AuthenticatedSafe[0]` — `id-encryptedData` content-info containing an
///   `EncryptedData` whose plaintext is `SafeContents` holding one
///   `certBag` per certificate (end-entity + any CA certs).
/// - `AuthenticatedSafe[1]` — `id-data` content-info whose value is an
///   `OctetString` wrapping `SafeContents` with a single
///   `pkcs8ShroudedKeyBag` holding the encrypted private key.
/// - `MacData` — HMAC-SHA-256 over the `AuthenticatedSafe` DER, with a
///   PKCS#12 §B.2 KDF-derived key.
pub struct PfxBuilder {
    password: Zeroizing<String>,
    cert_der: Option<Vec<u8>>,
    key_der: Option<Zeroizing<Vec<u8>>>,
    ca_certs_der: Vec<Vec<u8>>,
    cert_enc_alg: EncryptionAlgorithm,
    key_enc_alg: EncryptionAlgorithm,
    mac_alg: MacAlgorithm,
}

impl PfxBuilder {
    /// Create a new builder with the given passphrase.
    ///
    /// `password` must consist only of Unicode Basic Multilingual Plane
    /// characters (U+0000–U+FFFF).  Characters outside the BMP (e.g.,
    /// emoji) will cause [`build_with_rng`][Self::build_with_rng] to fail.
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: Zeroizing::new(password.into()),
            cert_der: None,
            key_der: None,
            ca_certs_der: Vec::new(),
            cert_enc_alg: EncryptionAlgorithm::default(),
            key_enc_alg: EncryptionAlgorithm::default(),
            mac_alg: MacAlgorithm::default(),
        }
    }

    /// Set the end-entity certificate (DER-encoded X.509 `Certificate`).
    pub fn with_cert(mut self, cert_der: impl Into<Vec<u8>>) -> Self {
        self.cert_der = Some(cert_der.into());
        self
    }

    /// Set the private key (DER-encoded PKCS#8 `PrivateKeyInfo`).
    ///
    /// The key bytes are wrapped in [`Zeroizing`] and erased when the builder
    /// is dropped.
    pub fn with_key(mut self, key_der: impl Into<Vec<u8>>) -> Self {
        self.key_der = Some(Zeroizing::new(key_der.into()));
        self
    }

    /// Add a CA certificate to the certificate chain (DER-encoded X.509).
    ///
    /// Multiple CA certificates may be added by calling this method repeatedly.
    /// They are stored in the same encrypted `certBag` group as the
    /// end-entity certificate.
    pub fn with_ca_cert(mut self, ca_der: impl Into<Vec<u8>>) -> Self {
        self.ca_certs_der.push(ca_der.into());
        self
    }

    /// Select the encryption algorithm for the certificate bag(s).
    ///
    /// Defaults to [`EncryptionAlgorithm::Pbes2Aes256Cbc`] with 600 000
    /// iterations.
    pub fn with_cert_encryption(mut self, alg: EncryptionAlgorithm) -> Self {
        self.cert_enc_alg = alg;
        self
    }

    /// Select the encryption algorithm for the private key bag.
    ///
    /// Defaults to [`EncryptionAlgorithm::Pbes2Aes256Cbc`] with 600 000
    /// iterations.
    pub fn with_key_encryption(mut self, alg: EncryptionAlgorithm) -> Self {
        self.key_enc_alg = alg;
        self
    }

    /// Select the MAC algorithm for `MacData`.
    ///
    /// Defaults to [`MacAlgorithm::HmacSha256`] with 100 000 iterations.
    pub fn with_mac_algorithm(mut self, alg: MacAlgorithm) -> Self {
        self.mac_alg = alg;
        self
    }

    /// Consume the builder and produce raw DER bytes of the PFX structure.
    ///
    /// Randomness is used to generate the PBKDF2 salt, AES-CBC IV, and MAC
    /// salt; pass a cryptographically secure RNG (e.g., `rand::rng()`).
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if:
    /// - a certificate or key has not been set (both are required),
    /// - DER encoding fails,
    /// - encryption fails, or
    /// - the password contains characters outside the Unicode BMP.
    pub fn build_with_rng<R: CryptoRng>(self, rng: &mut R) -> Result<Vec<u8>, Error> {
        let cert_der = self.cert_der.ok_or(Error::MissingField("cert"))?;
        let key_der = self.key_der.ok_or(Error::MissingField("key"))?;

        // ── 1. Cert SafeContents ─────────────────────────────────────────────
        let mut cert_bags: SafeContents = Vec::new();

        let ee_bag = CertBag {
            cert_id: PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(cert_der)?,
        };
        cert_bags.push(SafeBag {
            bag_id: PKCS_12_CERT_BAG_OID,
            bag_value: ee_bag.to_der()?,
            bag_attributes: None,
        });

        for ca in &self.ca_certs_der {
            let ca_bag = CertBag {
                cert_id: PKCS_12_X509_CERT_OID,
                cert_value: OctetString::new(ca.as_slice())?,
            };
            cert_bags.push(SafeBag {
                bag_id: PKCS_12_CERT_BAG_OID,
                bag_value: ca_bag.to_der()?,
                bag_attributes: None,
            });
        }

        let cert_safe_contents_der = cert_bags.to_der()?;

        // ── 2. Encrypt cert bags → EncryptedData ContentInfo ─────────────────
        // PBES2/PBKDF2 treats the password as an opaque byte string (RFC 8018
        // §5.2), so we pass raw UTF-8 bytes.  The MAC path uses &str because
        // the PKCS#12 §B.2 KDF requires UTF-16BE (BMP) encoding internally —
        // see `compute_mac` and `kdf::derive_key_utf8`.
        let cert_ci = encrypt_safe_contents(
            rng,
            &cert_safe_contents_der,
            self.password.as_bytes(),
            &self.cert_enc_alg,
        )?;

        // ── 3. Key bag (pkcs8ShroudedKeyBag) ─────────────────────────────────
        // Same UTF-8 bytes rationale as the cert encryption above.
        let epki_der = encrypt_key(rng, &key_der, self.password.as_bytes(), &self.key_enc_alg)?;
        let key_bag = SafeBag {
            bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
            bag_value: epki_der,
            bag_attributes: None,
        };
        let key_safe_contents_der = alloc::vec![key_bag].to_der()?;

        let key_ci = data_content_info(&key_safe_contents_der)?;

        // ── 4. AuthenticatedSafe ──────────────────────────────────────────────
        let auth_safe: Vec<ContentInfo> = alloc::vec![cert_ci, key_ci];
        let auth_safe_der = auth_safe.to_der()?;

        // ── 5. Outer Data ContentInfo (PFX.authSafe) ──────────────────────────
        let pfx_auth_safe = data_content_info(&auth_safe_der)?;

        // ── 6. MacData ────────────────────────────────────────────────────────
        let mac_data = compute_mac(&self.password, &auth_safe_der, &self.mac_alg, rng)?;

        // ── 7. Assemble and encode ────────────────────────────────────────────
        let pfx = Pfx {
            version: Version::V3,
            auth_safe: pfx_auth_safe,
            mac_data: Some(mac_data),
        };

        Ok(pfx.to_der()?)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Wrap `payload` in a CMS `id-data` ContentInfo:
/// `ContentInfo { content_type: id-data, content: [0] OctetString(payload) }`.
///
/// `ContentInfo.content` is typed as [`Any`], which holds a raw TLV.  We must
/// therefore build the complete OCTET STRING TLV (`to_der()`) first, then
/// parse it back as `Any`.  Passing `payload` directly would lose the tag/length
/// header and produce malformed DER.
fn data_content_info(payload: &[u8]) -> Result<ContentInfo, Error> {
    let os_der = OctetString::new(payload)?.to_der()?;
    Ok(ContentInfo {
        content_type: rfc5911::ID_DATA,
        content: Any::from_der(&os_der)?,
    })
}

/// Encrypt `plaintext` and return DER-encoded `EncryptedPrivateKeyInfo` bytes
/// suitable for use as a `pkcs8ShroudedKeyBag` `bag_value`.
fn encrypt_key<R: CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    password: &[u8],
    alg: &EncryptionAlgorithm,
) -> Result<Vec<u8>, Error> {
    let (params, ciphertext) = pbes2_encrypt(rng, plaintext, password, alg)?;
    let epki = EncryptedPrivateKeyInfoOwned {
        encryption_algorithm: pkcs5::EncryptionScheme::from(params),
        encrypted_data: OctetString::new(ciphertext.as_slice())?,
    };
    Ok(epki.to_der()?)
}

/// Encrypt `safe_contents_der` and return a CMS `id-encryptedData` ContentInfo.
fn encrypt_safe_contents<R: CryptoRng>(
    rng: &mut R,
    safe_contents_der: &[u8],
    password: &[u8],
    alg: &EncryptionAlgorithm,
) -> Result<ContentInfo, Error> {
    let (params, ciphertext) = pbes2_encrypt(rng, safe_contents_der, password, alg)?;
    let content_enc_alg = scheme_to_alg_id(&pkcs5::EncryptionScheme::from(params))?;

    let enc_data = EncryptedData {
        version: CmsVersion::V0,
        enc_content_info: EncryptedContentInfo {
            content_type: rfc5911::ID_DATA,
            content_enc_alg,
            encrypted_content: Some(OctetString::new(ciphertext.as_slice())?),
        },
        unprotected_attrs: None,
    };

    let enc_data_der = enc_data.to_der()?;
    Ok(ContentInfo {
        content_type: rfc5911::ID_ENCRYPTED_DATA,
        content: Any::from_der(&enc_data_der)?,
    })
}

/// Generate PBES2 parameters with a random salt and IV, then encrypt `plaintext`.
///
/// Returns `(params, ciphertext)`.
fn pbes2_encrypt<R: CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    password: &[u8],
    alg: &EncryptionAlgorithm,
) -> Result<(pbes2::Parameters, Vec<u8>), Error> {
    match alg {
        EncryptionAlgorithm::Pbes2Aes256Cbc { iterations } => {
            let mut salt = [0u8; PBKDF2_SALT_LEN];
            rng.fill_bytes(&mut salt);
            let mut iv = [0u8; AES_IV_LEN];
            rng.fill_bytes(&mut iv);

            let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(*iterations, &salt, iv)?;
            let ciphertext = params.encrypt(password, plaintext)?;
            Ok((params, ciphertext))
        }
    }
}

/// Encode a `pkcs5::EncryptionScheme` as an owned `AlgorithmIdentifier`.
///
/// The CMS `EncryptedContentInfo.content_enc_alg` field requires
/// [`AlgorithmIdentifierOwned`] (from `spki`), but `pkcs5` only exposes
/// [`pkcs5::EncryptionScheme`].  Because `EncryptionScheme` serialises
/// identically to an `AlgorithmIdentifier` SEQUENCE, a DER round-trip is the
/// least-surprising way to bridge the type gap.
///
/// The private-key path does *not* need this helper: `EncryptedPrivateKeyInfo`
/// (from `pkcs8`) already accepts `EncryptionScheme` directly.
fn scheme_to_alg_id(scheme: &pkcs5::EncryptionScheme) -> Result<AlgorithmIdentifierOwned, Error> {
    let der = scheme.to_der()?;
    Ok(AlgorithmIdentifierOwned::from_der(&der)?)
}

/// Compute PKCS#12 `MacData` using HMAC-SHA-256.
///
/// `password` is a `&str` (not `&[u8]`) because the PKCS#12 §B.2 KDF mandates
/// BMP (UTF-16BE) encoding of the password, which [`derive_key_utf8`] performs
/// internally.  Content-encryption (PBES2) uses raw UTF-8 bytes instead; see
/// the call sites in [`PfxBuilder::build_with_rng`].
fn compute_mac<R: CryptoRng>(
    password: &str,
    auth_safe_der: &[u8],
    alg: &MacAlgorithm,
    rng: &mut R,
) -> Result<MacData, Error> {
    match alg {
        MacAlgorithm::HmacSha256 { iterations } => {
            let mut mac_salt = [0u8; MAC_SALT_LEN];
            rng.fill_bytes(&mut mac_salt);

            // Derive the HMAC key using the PKCS#12 §B.2 KDF.
            let mac_key = Zeroizing::new(derive_key_utf8::<Sha256>(
                password,
                &mac_salt,
                Pkcs12KeyType::Mac,
                *iterations,
                HMAC_SHA256_LEN,
            )?);

            // Compute HMAC-SHA-256 over the AuthenticatedSafe DER.
            // `new_from_slice` only fails for a zero-length key; `mac_key` is
            // `HMAC_SHA256_LEN` (32) bytes, so this error path is unreachable.
            let mut hmac = Hmac::<Sha256>::new_from_slice(&mac_key)
                .map_err(|_| der::Error::from(der::ErrorKind::Failed))?;
            hmac.update(auth_safe_der);
            let tag = hmac.finalize().into_bytes();

            Ok(MacData {
                mac: DigestInfo {
                    algorithm: AlgorithmIdentifierOwned {
                        oid: rfc5912::ID_SHA_256,
                        parameters: None,
                    },
                    digest: OctetString::new(tag.as_slice())?,
                },
                mac_salt: OctetString::new(mac_salt.as_slice())?,
                iterations: *iterations,
            })
        }
    }
}
