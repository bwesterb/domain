//! DNSSEC signing and verification for ML-DSA-44.
//!
//! [draft-westerbaan-dnssec-mldsa] describes the use of the ML-DSA-44
//! signature scheme (specified in [FIPS 204]) with DNSSEC.  ML-DSA-44 is
//! believed to be secure even against adversaries in possession of a
//! cryptographically relevant quantum computer.
//!
//! This backend implements ML-DSA-44 using BoringSSL, through the
//! [`boring`] and [`boring_sys`] crates.  It complements the Ring and
//! OpenSSL backends, which do not support ML-DSA.  This backend also
//! provides message digests, so it can be used on its own.
//!
//! Signatures are generated and verified using the "pure" ML-DSA variant
//! with an empty context string, as required by the draft.  Signing uses
//! the hedged variant of ML-DSA, so signing the same data twice produces
//! different (but equally valid) signatures.
//!
//! [draft-westerbaan-dnssec-mldsa]: https://datatracker.ietf.org/doc/draft-westerbaan-dnssec-mldsa/
//! [FIPS 204]: https://doi.org/10.6028/NIST.FIPS.204

#![cfg(feature = "mldsa")]
#![cfg_attr(docsrs, doc(cfg(feature = "mldsa")))]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
#[cfg(feature = "unstable-crypto-sign")]
use core::mem::MaybeUninit;
use core::ptr::null;

use super::common::{AlgorithmError, DigestType};
use crate::base::iana::SecurityAlgorithm;
use crate::rdata::Dnskey;

/// The size of an ML-DSA-44 public key in its DNSKEY encoding.
pub const PUBLIC_KEY_SIZE: usize = 1312;

/// The size of an ML-DSA-44 signature.
pub const SIGNATURE_SIZE: usize = 2420;

/// The size of the seed an ML-DSA-44 private key is derived from.
pub const SEED_SIZE: usize = 32;

/// Bindings for the ML-DSA-44 API in BoringSSL's `openssl/mldsa.h`, which
/// the `boring-sys` crate does not currently generate.
mod ffi {
    #![allow(non_camel_case_types)]
    #![allow(missing_docs)]
    // The private key functionality is only used for signing.
    #![cfg_attr(not(feature = "unstable-crypto-sign"), allow(dead_code))]

    use boring_sys::{CBB, CBS};
    use core::ffi::c_int;

    /// The size of `struct MLDSA44_private_key` in `openssl/mldsa.h`.
    const PRIVATE_KEY_REPR_SIZE: usize =
        (32 + 64 + 256 * 4 * 4) + 32 + 256 * 4 * (4 + 4 + 4);

    /// The size of `struct MLDSA44_public_key` in `openssl/mldsa.h`.
    const PUBLIC_KEY_REPR_SIZE: usize = 32 + 64 + 256 * 4 * 4;

    /// BoringSSL's `struct MLDSA44_private_key`.
    ///
    /// The contents are opaque; the format is unstable.
    #[derive(Clone)]
    #[repr(C, align(4))]
    pub(super) struct MLDSA44_private_key {
        /// The unstable internal representation.
        opaque: [u8; PRIVATE_KEY_REPR_SIZE],
    }

    /// BoringSSL's `struct MLDSA44_public_key`.
    ///
    /// The contents are opaque; the format is unstable.
    #[derive(Clone)]
    #[repr(C, align(4))]
    pub(super) struct MLDSA44_public_key {
        /// The unstable internal representation.
        opaque: [u8; PUBLIC_KEY_REPR_SIZE],
    }

    unsafe extern "C" {
        pub(super) fn MLDSA44_generate_key(
            out_encoded_public_key: *mut u8,
            out_seed: *mut u8,
            out_private_key: *mut MLDSA44_private_key,
        ) -> c_int;

        pub(super) fn MLDSA44_private_key_from_seed(
            out_private_key: *mut MLDSA44_private_key,
            seed: *const u8,
            seed_len: usize,
        ) -> c_int;

        pub(super) fn MLDSA44_public_from_private(
            out_public_key: *mut MLDSA44_public_key,
            private_key: *const MLDSA44_private_key,
        ) -> c_int;

        pub(super) fn MLDSA44_sign(
            out_encoded_signature: *mut u8,
            private_key: *const MLDSA44_private_key,
            msg: *const u8,
            msg_len: usize,
            context: *const u8,
            context_len: usize,
        ) -> c_int;

        pub(super) fn MLDSA44_verify(
            public_key: *const MLDSA44_public_key,
            signature: *const u8,
            signature_len: usize,
            msg: *const u8,
            msg_len: usize,
            context: *const u8,
            context_len: usize,
        ) -> c_int;

        pub(super) fn MLDSA44_marshal_public_key(
            out: *mut CBB,
            public_key: *const MLDSA44_public_key,
        ) -> c_int;

        pub(super) fn MLDSA44_parse_public_key(
            public_key: *mut MLDSA44_public_key,
            in_: *mut CBS,
        ) -> c_int;
    }
}

/// Serialize a parsed public key into its standard encoding.
#[cfg(feature = "unstable-crypto-sign")]
fn marshal_public_key(
    key: &ffi::MLDSA44_public_key,
) -> Box<[u8; PUBLIC_KEY_SIZE]> {
    let mut out = Box::new([0u8; PUBLIC_KEY_SIZE]);
    // SAFETY: 'cbb' writes to the correctly sized buffer 'out' and
    // 'key' is a valid public key.
    unsafe {
        let mut cbb = MaybeUninit::<boring_sys::CBB>::uninit();
        if boring_sys::CBB_init_fixed(
            cbb.as_mut_ptr(),
            out.as_mut_ptr(),
            out.len(),
        ) != 1
            || ffi::MLDSA44_marshal_public_key(cbb.as_mut_ptr(), key) != 1
        {
            unreachable!("marshaling a valid key into 1312 bytes works");
        }
    }
    out
}

//----------- DigestBuilder --------------------------------------------------

/// Builder for computing a message digest.
pub struct DigestBuilder(boring::hash::Hasher);

impl DigestBuilder {
    /// Create a new builder for a specified digest type.
    pub fn new(digest_type: DigestType) -> Self {
        use boring::hash::{Hasher, MessageDigest};
        Self(
            match digest_type {
                DigestType::Sha1 => Hasher::new(MessageDigest::sha1()),
                DigestType::Sha256 => Hasher::new(MessageDigest::sha256()),
                DigestType::Sha384 => Hasher::new(MessageDigest::sha384()),
            }
            .expect("assume that new cannot fail"),
        )
    }

    /// Add input to the digest computation.
    pub fn update(&mut self, data: &[u8]) {
        self.0
            .update(data)
            .expect("assume that update does not fail")
    }

    /// Finish computing the digest.
    pub fn finish(mut self) -> Digest {
        Digest(self.0.finish().expect("assume that finish does not fail"))
    }
}

//----------- Digest ---------------------------------------------------------

/// A message digest.
pub struct Digest(boring::hash::DigestBytes);

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//----------- PublicKey ------------------------------------------------------

/// An ML-DSA-44 public key for verifying a signature.
#[derive(Clone)]
pub struct PublicKey {
    /// The parsed public key.
    key: Box<ffi::MLDSA44_public_key>,

    /// The encoded public key.
    encoded: Box<[u8; PUBLIC_KEY_SIZE]>,

    /// Flags from [`Dnskey`].
    flags: u16,
}

impl PublicKey {
    /// Create a public key from a [`Dnskey`].
    pub fn from_dnskey(
        dnskey: &Dnskey<impl AsRef<[u8]>>,
    ) -> Result<Self, AlgorithmError> {
        if dnskey.algorithm() != SecurityAlgorithm::MLDSA44 {
            return Err(AlgorithmError::Unsupported);
        }
        let encoded: Box<[u8]> = dnskey.public_key().as_ref().into();
        let encoded: Box<[u8; PUBLIC_KEY_SIZE]> = encoded
            .try_into()
            .map_err(|_| AlgorithmError::InvalidData)?;

        boring_sys::init();
        let mut key = Box::<ffi::MLDSA44_public_key>::new_uninit();
        // CBS_init is inline in BoringSSL, so construct the CBS directly.
        let mut cbs = boring_sys::CBS {
            data: encoded.as_ptr(),
            len: encoded.len(),
        };
        // SAFETY: 'key' and 'cbs' are valid for the duration of the call.
        if unsafe {
            ffi::MLDSA44_parse_public_key(key.as_mut_ptr(), &mut cbs)
        } != 1
        {
            return Err(AlgorithmError::InvalidData);
        }
        // SAFETY: 'key' was initialized by 'MLDSA44_parse_public_key'.
        let key = unsafe { key.assume_init() };

        Ok(Self {
            key,
            encoded,
            flags: dnskey.flags(),
        })
    }

    /// Verify a signature.
    pub fn verify(
        &self,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), AlgorithmError> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(AlgorithmError::InvalidData);
        }
        boring_sys::init();
        // SAFETY: all pointers are valid for the given lengths for the
        // duration of the call.
        let valid = unsafe {
            ffi::MLDSA44_verify(
                self.key.as_ref(),
                signature.as_ptr(),
                signature.len(),
                signed_data.as_ptr(),
                signed_data.len(),
                null(),
                0,
            )
        } == 1;
        if valid {
            Ok(())
        } else {
            Err(AlgorithmError::BadSig)
        }
    }

    /// Convert to a [`Dnskey`].
    pub fn dnskey(&self) -> Dnskey<Vec<u8>> {
        Dnskey::new(
            self.flags,
            3,
            SecurityAlgorithm::MLDSA44,
            self.encoded.to_vec(),
        )
        .expect("long enough")
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "unstable-crypto-sign")]
/// Submodule for private keys and signing.
pub mod sign {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::fmt;
    use core::ptr::null;

    use secrecy::{ExposeSecret, SecretBox};

    use super::{
        PUBLIC_KEY_SIZE, PublicKey, SEED_SIZE, SIGNATURE_SIZE, ffi,
        marshal_public_key,
    };
    use crate::base::iana::SecurityAlgorithm;
    use crate::crypto::sign::{
        FromBytesError, GenerateError, GenerateParams, SecretKeyBytes,
        SignError, SignRaw, Signature,
    };
    use crate::rdata::Dnskey;

    //----------- KeyPair ----------------------------------------------------

    /// An ML-DSA-44 key pair.
    pub struct KeyPair {
        /// The private key.
        key: Box<ffi::MLDSA44_private_key>,

        /// The seed the private key is derived from.
        seed: SecretBox<[u8; SEED_SIZE]>,

        /// The encoded public key.
        encoded_public: Box<[u8; PUBLIC_KEY_SIZE]>,

        /// Flags from [`Dnskey`].
        flags: u16,
    }

    //--- Conversion to and from bytes

    impl KeyPair {
        /// Import a key pair from bytes.
        pub fn from_bytes<Octs>(
            secret: &SecretKeyBytes,
            public: &Dnskey<Octs>,
        ) -> Result<Self, FromBytesError>
        where
            Octs: AsRef<[u8]>,
        {
            let SecretKeyBytes::MlDsa44(seed) = secret else {
                return Err(FromBytesError::UnsupportedAlgorithm);
            };

            boring_sys::init();
            let mut key = Box::<ffi::MLDSA44_private_key>::new_uninit();
            // SAFETY: 'key' and the 32-byte seed are valid for the
            // duration of the call.
            if unsafe {
                ffi::MLDSA44_private_key_from_seed(
                    key.as_mut_ptr(),
                    seed.expose_secret().as_ptr(),
                    seed.expose_secret().len(),
                )
            } != 1
            {
                return Err(FromBytesError::Implementation);
            }
            // SAFETY: 'key' was initialized by
            // 'MLDSA44_private_key_from_seed'.
            let key = unsafe { key.assume_init() };

            let mut public_key = Box::<ffi::MLDSA44_public_key>::new_uninit();
            // SAFETY: 'public_key' and 'key' are valid for the duration of
            // the call.
            if unsafe {
                ffi::MLDSA44_public_from_private(
                    public_key.as_mut_ptr(),
                    key.as_ref(),
                )
            } != 1
            {
                return Err(FromBytesError::Implementation);
            }
            // SAFETY: 'public_key' was initialized by
            // 'MLDSA44_public_from_private'.
            let public_key = unsafe { public_key.assume_init() };
            let encoded_public = marshal_public_key(&public_key);

            // Ensure that the public and private key match.
            if public.public_key().as_ref() != encoded_public.as_slice() {
                return Err(FromBytesError::InvalidKey);
            }

            Ok(Self {
                key,
                seed: SecretBox::new(Box::new(*seed.expose_secret())),
                encoded_public,
                flags: public.flags(),
            })
        }

        /// Export the secret key into bytes.
        pub fn to_bytes(&self) -> SecretKeyBytes {
            SecretKeyBytes::MlDsa44(SecretBox::new(Box::new(
                *self.seed.expose_secret(),
            )))
        }
    }

    //--- SignRaw

    impl SignRaw for KeyPair {
        fn algorithm(&self) -> SecurityAlgorithm {
            SecurityAlgorithm::MLDSA44
        }

        fn dnskey(&self) -> Dnskey<Vec<u8>> {
            Dnskey::new(
                self.flags,
                3,
                SecurityAlgorithm::MLDSA44,
                self.encoded_public.to_vec(),
            )
            .expect("long enough")
        }

        fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
            // This uses the hedged variant of ML-DSA with an empty context
            // string.
            let mut signature = Box::new([0u8; SIGNATURE_SIZE]);
            boring_sys::init();
            // SAFETY: all pointers are valid for the given lengths for the
            // duration of the call.
            if unsafe {
                ffi::MLDSA44_sign(
                    signature.as_mut_ptr(),
                    self.key.as_ref(),
                    data.as_ptr(),
                    data.len(),
                    null(),
                    0,
                )
            } != 1
            {
                return Err(SignError);
            }
            Ok(Signature::MlDsa44(signature))
        }
    }

    //--- Debug

    impl fmt::Debug for KeyPair {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("KeyPair")
                .field("flags", &self.flags)
                .finish_non_exhaustive()
        }
    }

    //----------- generate() -------------------------------------------------

    /// Generate a new secret key for the given algorithm.
    pub fn generate(
        params: &GenerateParams,
        flags: u16,
    ) -> Result<(SecretKeyBytes, Dnskey<Vec<u8>>), GenerateError> {
        let GenerateParams::MlDsa44 = params else {
            return Err(GenerateError::UnsupportedAlgorithm);
        };

        boring_sys::init();
        let mut encoded_public = Box::new([0u8; PUBLIC_KEY_SIZE]);
        let mut seed = Box::new([0u8; SEED_SIZE]);
        let mut key = Box::<ffi::MLDSA44_private_key>::new_uninit();
        // SAFETY: all pointers are valid buffers of the expected sizes.
        if unsafe {
            ffi::MLDSA44_generate_key(
                encoded_public.as_mut_ptr(),
                seed.as_mut_ptr(),
                key.as_mut_ptr(),
            )
        } != 1
        {
            return Err(GenerateError::Implementation);
        }

        let secret = SecretKeyBytes::MlDsa44(SecretBox::new(seed));
        let public = Dnskey::new(
            flags,
            3,
            SecurityAlgorithm::MLDSA44,
            encoded_public.to_vec(),
        )
        .expect("long enough");
        Ok((secret, public))
    }

    //--- Conversion to the public key

    impl KeyPair {
        /// The public key of this key pair.
        pub fn public_key(&self) -> PublicKey {
            PublicKey::from_dnskey(&SignRaw::dnskey(self))
                .expect("valid key pair")
        }
    }

    //============ Tests =====================================================

    #[cfg(test)]
    mod tests {
        use alloc::string::ToString;

        use crate::base::iana::SecurityAlgorithm;
        use crate::crypto::mldsa::PublicKey;
        use crate::crypto::mldsa::test_vectors::{PRIVATE_KEY, dnskey};
        use crate::crypto::sign::{
            FromBytesError, GenerateParams, SecretKeyBytes, SignRaw,
        };
        use crate::rdata::Dnskey;

        use super::KeyPair;

        #[test]
        fn from_bytes() {
            let secret =
                SecretKeyBytes::parse_from_bind(PRIVATE_KEY).unwrap();
            assert_eq!(secret.algorithm(), SecurityAlgorithm::MLDSA44);

            let key = KeyPair::from_bytes(&secret, &dnskey()).unwrap();
            assert_eq!(SignRaw::dnskey(&key), dnskey());
            assert_eq!(SignRaw::dnskey(&key).key_tag(), 59829);
        }

        #[test]
        fn mismatched_public_key() {
            let secret =
                SecretKeyBytes::parse_from_bind(PRIVATE_KEY).unwrap();

            // Flip a bit in the public key.
            let mut public = dnskey().public_key().to_vec();
            public[0] ^= 1;
            let public =
                Dnskey::new(257, 3, SecurityAlgorithm::MLDSA44, public)
                    .unwrap();

            assert!(matches!(
                KeyPair::from_bytes(&secret, &public),
                Err(FromBytesError::InvalidKey)
            ));
        }

        #[test]
        fn secret_roundtrip() {
            let secret =
                SecretKeyBytes::parse_from_bind(PRIVATE_KEY).unwrap();
            let key = KeyPair::from_bytes(&secret, &dnskey()).unwrap();
            let same = key.to_bytes().display_as_bind().to_string();
            assert!(same.contains("Algorithm: 18 (MLDSA44)"));
            assert!(same.contains(
                "PrivateKey: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            ));
        }

        #[test]
        fn sign_and_verify() {
            let secret =
                SecretKeyBytes::parse_from_bind(PRIVATE_KEY).unwrap();
            let key = KeyPair::from_bytes(&secret, &dnskey()).unwrap();

            let signature = key.sign_raw(b"Hello, World!").unwrap();
            assert_eq!(signature.algorithm(), SecurityAlgorithm::MLDSA44);
            assert_eq!(signature.as_ref().len(), super::SIGNATURE_SIZE);

            let public = PublicKey::from_dnskey(&dnskey()).unwrap();
            public.verify(b"Hello, World!", signature.as_ref()).unwrap();
            assert!(
                public.verify(b"Hello, World?", signature.as_ref()).is_err()
            );
        }

        #[test]
        fn generate() {
            let (secret, public) =
                crate::crypto::sign::generate(&GenerateParams::MlDsa44, 257)
                    .unwrap();
            assert_eq!(secret.algorithm(), SecurityAlgorithm::MLDSA44);
            assert_eq!(public.algorithm(), SecurityAlgorithm::MLDSA44);
            assert_eq!(
                public.public_key().len(),
                crate::crypto::mldsa::PUBLIC_KEY_SIZE
            );

            let key = KeyPair::from_bytes(&secret, &public).unwrap();
            let signature = key.sign_raw(b"Hello, World!").unwrap();
            key.public_key()
                .verify(b"Hello, World!", signature.as_ref())
                .unwrap();
        }
    }
}

//============ Test vectors ==================================================

/// Test vectors from Section 6 of draft-westerbaan-dnssec-mldsa-03.
#[cfg(test)]
pub(crate) mod test_vectors {
    // Not all vectors are used in every feature configuration.
    #![allow(dead_code)]

    use alloc::vec::Vec;

    use crate::base::iana::SecurityAlgorithm;
    use crate::rdata::Dnskey;
    use crate::utils::base64;

    /// The example private key in BIND format.
    pub(crate) const PRIVATE_KEY: &str = "\
        Private-key-format: v1.3\n\
        Algorithm: 18 (MLDSA44)\n\
        PrivateKey: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n";

    /// The example public key in Base64.
    pub(crate) const PUBLIC_KEY_B64: &str = concat!(
        "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",
        "yDCzJCyDEg==",
    );

    /// The example RRSIG signature (over the example MX RRset) in Base64.
    pub(crate) const SIGNATURE_B64: &str = concat!(
        "kdySHzwB7NftjQSAF7snCeKau3NoqpLNg16h/eHZV8L3Zpi30lkRyiS4FLMM",
        "ZqTjzbf1A/bShg4qZpYlnfqXN8uqFWF9GEEJOgte1CFdF4GC05gEBU88Kryf",
        "nGAcpXKafw9htDxZrqmqVSWN+1guW7HyUUFo1IuWTnZKuhZptDJkq+Ml+5ZH",
        "y4p+2Tdwk8MH7tJlTYk/UVaM1wIXPB2YgJ++kD0zhys5c38rztcaOmMXt6ej",
        "yAEY37Dc1Z/KsrRQZWv+XZ/CTliuh+dGJHoGuTm5KwS0us884ukWNC/wIU/S",
        "dlGoBDVXsT163Tr6lTf8pJ4xixcKIN8nsKSFxP9j+AbaN5SofIAvp4LGIFLg",
        "MKsRV/cqeYo8PegVD2EhAQ2/HVTO3uO8vlqLK7nWVVK2+2aYKIL2EqzjhRYK",
        "U5DhMwS9ZgbG0niszGXpvZcNcOyABXysdVuaDjnUuamYVACOUrV786LNmt8I",
        "WDnXWoPPMErPk5vNyHq6+ZHg79UeZpSzx0Ae/1aIfi2WEta9Or5sGItBn6vF",
        "Wi9kJRuhuoMIXf9CLBV/LHL/PIenBxXSnr2Owg54AuSN2tmk2lDy8BfKzzvx",
        "TOoKXx4edo96Xv6QWASAxO9JmyEvhnF3SBI6HG3fn2+k8rgJLIHpsr4pZhMh",
        "4/SQWaojxt51nEIFi1bl7P6sAmCdMP81LSNx05hIkKcPeO33hA2VSDO7GzOE",
        "snBOzbhUX9gbFr3aNV/Wrbs/cZMAL1I0IKG20jkmEfZ9PeKN0hXCxHJo4hPF",
        "L2mm9ciGpuXS7oN8f7YublNTwRY8b4plScVICpyBT5UDOgezR9/+DnklL0fz",
        "IORMTRnpD1hq4BqZMgNMwvczFg3DrSLQP/cBiKLn3toJrkSuU9aXodEqW3lh",
        "RdMvDUqTtHgMKas5velmabpENAbixiB8n5zoENnMLV6w/13a+yOTT2WUvESg",
        "HqF92FfQMdQl36noyewmjUFZopirCGV6AkebdVsTY27DtYkGWamLXcm3w2d6",
        "AYV/LssvyK/Jlnw/E7YRJWkO+8PvHA2tvfQSr8fNC4ll/KHdwr8d0Q8spPcO",
        "HMMui20XDYeprPmp64hSt4IBuiQusdm3SQsWjQvaUsg8sykZd24S/wNQiGsw",
        "XaoG6oWYYCZupfvGc0sgb+9qxZU5fSAYKwx5LjYajruvQ5flebAtrUdLuPbG",
        "Mb2I7Z8c4IvDmbA6ljqMK60w1XI+wU7jSWzoEaiIeAUR1aT925KFMEhmFG3k",
        "Tr5ZPI57wM7pEI9jBME80lu7D3f4z++icSHSJ5YNa/+kp7eSIT94m4Tj7nel",
        "mN0WnKFgzGZKnuiDGJew5FFnfB0qfvqUNUPt1rVaIr7rzBBL4j8WQHqOo17A",
        "+0pnIqKTe1Z8MxFnPwP1eWHa3T/7JeEPSD5JFOpEWxs12twxTC42BrTCckSm",
        "rfmksfxmJa0mfflaOPHkjahTprrItJzG1efHYCu5nP5rsclZF0hDOR1OZrgK",
        "2IhnG1VotIPB4+/+70+uD0qcqY3L2yonxFlQS8sEmMcXi9xQTxdFG4NOk/TQ",
        "G50Oly1tRp9UoLjwTDtlIjh71Lz9lajbAabV4WtIvd7cwaREO0kFAtzIgfJR",
        "VMasWvUo6e93qQBThzvkCNs8ngsa0jXJL1HrERP+qkiULCDMr19FVimWmIzL",
        "CkR9pg9WWjruY5krgdVbINUqjsyyGriPEhy2JneNWdOdFoAwkWtGbIpQhHs2",
        "bLHpG9xPPF+ElqLmjNa76BhXv4caurHYn7K0m4NMVgDywGXoh0OGe/PoXQ4g",
        "Ht7EbHgbCQO9V8+/1+MWw9ZrU6btOGJ2JVXeyRXYyJarn+cnPL1nWOlq7bMD",
        "3mazOTNZPc5UENSvDL51hmd3WD71i2u9btqIzjnmSxggPHRsVcOaGXHM3aUJ",
        "nrDtwi1EY7THlJatS+ItjWQMCDh8g/4LF9S2UWGFc21MimswWvgh1jB/4hYI",
        "9C8PSCpAeV26dXoANntR/lLms42488dVJ1wyNGjaNNX1itiqFYsNUn3LyT3T",
        "dVUgBwkfzO1I4UnhDIbsHJWbs7Dl/52Ei4MbpPJXnL1gMNc6SD1EkT1CeY9f",
        "esHF20wr8tb7V+qPO2TCE26syB9lZ41OSOYgqPYK/OHyoLedQmTOFls0QMj2",
        "F0bks3pJm/TDDMEuUdhulPatnZBNIXexqNImQUFyipcJ9W5KnD6Wr5+jyULy",
        "VBQRpWPzipfPFACb5d5lWPtrvh4kurYt3sSdUy+WJKuYb1roxXTZJqP0QDgn",
        "VEYL5nJnxqSRD9fx7HMRHXODkVioBFmSUgwP5XBljn/YpIgG8Ix42hyKMCti",
        "yv1gIY3/m8cfHyj5I6xcDHUTZHyM9+KSZeipf6wUnngoZuYzP9N3Nozo8LI+",
        "w3Mo6s/VjhmsALOYcus720s0MQY5prhkcZYUvgv9YL9R+1Fm7Kxy3cjpnGqy",
        "WwxN6YmNw/f6C+21Dlex7+09o2ygi0M1NEZZ0FhdaBmxVxtSjbBm3uKu9taW",
        "0zO534HXlifFkxf6GhboxbGdm1yekVIjDLnC+iodQyLwIi0vvc435Xk4GRBs",
        "8D5Pxf3vT3tgPy5sDXbJ3lT58MekKdT/HobugDOdu0ltGenFjnKFhdJudvQ/",
        "FFjqJk1HYnjxxdP3QYKlSHOv2ADtRqgI0VHLJmECOifYr90uWml1uzaUzK0X",
        "Tulm8fn6lfpF3EWJYSsq1iXQWuiRw9u6dxiS02+c4Z8Nzumoh48W+z0GFy+q",
        "ClyhqdedA6k3WZIJi919e5b24mj5rqzcgrA6KMqnTJDKh2cuoKC1fI88w774",
        "co0XPDyg+v/RD2ET1fquDGHjeVyVBsknNZQ5lwvLeAy/uH+Ql5qECQ9WCIJP",
        "ydZZhB906hkHZ+vch1fG+vhgMtoXhtZ4UXzQwbJBL/4wxtOau3IgWGkJEImJ",
        "PK3KE+7phfn5YmGSjVCp8o1t2QxpwJ1ZPBuTrUWy15gruIP8e415f0UPUZjF",
        "G+p6JqsUzaBzgZvAg9nY/vHEC0sXuC7lnqmDxr8LU9JMD77XrBccXMP199d/",
        "10bJW8TH+yzqE4syjdUPEalQnwP/fh9us92eSdv50vr0/KPhzfWzcRwWFxof",
        "S15zlJe3xNj+BAURHCApKjBkh5emuLy+w9zn6vn6/QsbXWp6hZWcoLO6ytLf",
        "6/H+DhguNzs/VFVbg5SXo62wztPoAAAAAAAAAAAAAA0jNEY=",
    );

    /// The SHA-256 digest from the example DS record, in hex.
    pub(crate) const DS_DIGEST_HEX: &str = "\
        812cb1a22af04380e2f72d91c06c14eb1a918cf30037a8a9c67497e9264b4bfa";

    /// The example DNSKEY.
    pub(crate) fn dnskey() -> Dnskey<Vec<u8>> {
        Dnskey::new(
            257,
            3,
            SecurityAlgorithm::MLDSA44,
            base64::decode::<Vec<u8>>(PUBLIC_KEY_B64).unwrap(),
        )
        .unwrap()
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::test_vectors::dnskey;
    use crate::base::iana::SecurityAlgorithm;
    use crate::crypto::common::{AlgorithmError, PublicKey};
    use crate::rdata::Dnskey;

    #[test]
    fn key_tag() {
        assert_eq!(dnskey().key_tag(), 59829);
    }

    #[test]
    fn from_dnskey() {
        let key = PublicKey::from_dnskey(&dnskey()).unwrap();
        // With only the mldsa backend enabled this pattern is irrefutable.
        #[allow(irrefutable_let_patterns)]
        let PublicKey::MlDsa(key) = key else {
            panic!("expected the ML-DSA backend to be selected");
        };
        assert_eq!(key.dnskey(), dnskey());
    }

    #[test]
    fn from_dnskey_invalid() {
        // A truncated public key is rejected.
        let mut public = dnskey().public_key().to_vec();
        public.pop();
        let dnskey =
            Dnskey::new(257, 3, SecurityAlgorithm::MLDSA44, public).unwrap();
        assert!(matches!(
            PublicKey::from_dnskey(&dnskey),
            Err(AlgorithmError::InvalidData)
        ));
    }
}
