//! Bindings for the "whitelist" ring signature implementation in secp256k1-zkp.
//!
//! This implementation is used for Liquid PAK list inclusion proofs.

#[cfg(feature = "std")]
use std::{fmt, str};

use core::ptr;

use ffi::CPtr;
#[cfg(feature = "std")]
use from_hex;
use {ffi, Error, PublicKey, Secp256k1, SecretKey, Signing, Verification};

/// A whitelist ring signature.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
#[repr(transparent)]
pub struct WhitelistSignature(ffi::WhitelistSignature);

impl WhitelistSignature {
    /// Number of keys in the whitelist.
    pub fn n_keys(&self) -> usize {
        self.0.n_keys as usize
    }

    /// Serialize to bytes.
    #[cfg(feature = "std")]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0; 32 + self.n_keys()];

        let mut out_len = 0;
        let ret = unsafe {
            ffi::secp256k1_whitelist_signature_serialize(
                ffi::secp256k1_context_no_precomp,
                buf.as_mut_ptr(),
                &mut out_len,
                &self.0,
            )
        };
        assert_eq!(ret, 1, "failed to serialize whitelist signature");
        assert_eq!(
            out_len,
            buf.len(),
            "whitelist serialized to unexpected length"
        );

        buf
    }

    /// Parse a whitelist ring signature from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut sig = ffi::WhitelistSignature::default();

        let ret = unsafe {
            ffi::secp256k1_whitelist_signature_parse(
                ffi::secp256k1_context_no_precomp,
                &mut sig,
                bytes.as_ptr(),
                bytes.len(),
            )
        };

        if ret != 1 {
            return Err(Error::InvalidPedersenCommitment);
        }

        Ok(WhitelistSignature(sig))
    }

    /// Create a new whitelist ring signature for the given PAK list and whitelist key.
    pub fn sign<C: Signing>(
        secp: &Secp256k1<C>,
        online_keys: &[PublicKey],
        offline_keys: &[PublicKey],
        whitelist_key: &PublicKey,
        online_secret_key: &SecretKey,
        summed_secret_key: &SecretKey,
        key_index: usize,
    ) -> Result<WhitelistSignature, Error> {
        if online_keys.len() != offline_keys.len() {
            return Err(Error::InvalidPakList);
        }
        let n_keys = online_keys.len();

        let mut sig = ffi::WhitelistSignature::default();
        let ret = unsafe {
            ffi::secp256k1_whitelist_sign(
                *secp.ctx(),
                &mut sig,
                // These two casts are legit because PublicKey has repr(transparent).
                online_keys.as_c_ptr() as *const secp256k1::secp256k1_sys::PublicKey,
                offline_keys.as_c_ptr() as *const secp256k1::secp256k1_sys::PublicKey,
                n_keys,
                whitelist_key.as_c_ptr(),
                online_secret_key.as_ptr(),
                summed_secret_key.as_ptr(),
                key_index,
                None,
                ptr::null_mut(),
            )
        };

        if ret != 0 {
            return Err(Error::CannotCreateWhitelistSignature);
        }

        Ok(WhitelistSignature(sig))
    }

    /// Verify the given whitelist signature against the PAK list and whitelist key.
    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        online_keys: &[PublicKey],
        offline_keys: &[PublicKey],
        whitelist_key: &PublicKey,
    ) -> Result<(), Error> {
        if online_keys.len() != offline_keys.len() {
            return Err(Error::InvalidPakList);
        }
        let n_keys = online_keys.len();

        let mut sig = ffi::WhitelistSignature::default();
        let ret = unsafe {
            ffi::secp256k1_whitelist_verify(
                *secp.ctx(),
                &mut sig,
                // These two casts are legit because PublicKey has repr(transparent).
                online_keys.as_c_ptr() as *const secp256k1::secp256k1_sys::PublicKey,
                offline_keys.as_c_ptr() as *const secp256k1::secp256k1_sys::PublicKey,
                n_keys,
                whitelist_key.as_c_ptr(),
            )
        };

        if ret != 0 {
            return Err(Error::InvalidWhitelistProof);
        }

        Ok(())
    }

    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::WhitelistSignature {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::WhitelistSignature {
        &mut self.0
    }
}

#[cfg(feature = "std")]
impl fmt::LowerHex for WhitelistSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.serialize().iter() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl fmt::Display for WhitelistSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

#[cfg(feature = "std")]
impl str::FromStr for WhitelistSignature {
    type Err = Error;
    fn from_str(s: &str) -> Result<WhitelistSignature, Error> {
        let mut buf = vec![0; s.len() / 2];
        from_hex(s, &mut buf).map_err(|_| Error::InvalidWhitelistSignature)?;
        WhitelistSignature::from_slice(&buf)
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for WhitelistSignature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for WhitelistSignature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                WhitelistSignature::from_slice,
            ))
        }
    }
}

impl CPtr for WhitelistSignature {
    type Target = ffi::WhitelistSignature;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

#[cfg(all(test, feature = "global-context"))]
mod tests {
    use super::*;
    use rand::{rngs::ThreadRng, thread_rng, RngCore};
    use {SECP256K1, PublicKey};

    #[test]
    fn test_whitelist_proof_roundtrip() {
        let mut rng = thread_rng();
        let keys_online = (0..5).map(|_| SECP256K1.generate_keypair(&mut rng)).collect::<Vec<_>>();
        let keys_offline = (0..5).map(|_| SECP256K1.generate_keypair(&mut rng)).collect::<Vec<_>>();

        // extract the pubkeys to serve as PAK list
        let pak_online = keys_online.iter().map(|p| p.1).collect::<Vec<_>>();
        let pak_offline = keys_offline.iter().map(|p| p.1).collect::<Vec<_>>();
        
        let (whitelist_sk, whitelist_pk) = SECP256K1.generate_keypair(&mut rng);

        // sign

        let our_idx = 2;
        let summed_key = {
            let mut ret = keys_offline[our_idx].0.clone();
            ret.add_assign(&whitelist_sk[..]).unwrap();
            ret
        };

        let signature = WhitelistSignature::sign(
            SECP256K1,
            &pak_online,
            &pak_offline,
            &whitelist_pk,
            &keys_online[our_idx].0,
            &summed_key,
            our_idx,
        ).unwrap();

        let encoded = signature.serialize();
        
        // verify

        let decoded = WhitelistSignature::from_slice(&encoded).unwrap();
        assert_eq!(signature, decoded);
        decoded.verify(SECP256K1, &pak_online, &pak_offline, &whitelist_pk).unwrap();
    }

    /////////////

    // #[test]
    // fn test_ecdsa_adaptor_signature_plain_valid() {
    //     let msg = msg_from_str("8131e6f4b45754f2c90bd06688ceeabc0c45055460729928b4eecf11026a9e2d");
    //     let pubkey = "035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c"
    //         .parse()
    //         .unwrap();
    //     let encryption_key = "02c2662c97488b07b6e819124b8989849206334a4c2fbdf691f7b34d2b16e9c293"
    //         .parse()
    //         .unwrap();
    //     let adaptor_sig : EcdsaAdaptorSignature = "03424d14a5471c048ab87b3b83f6085d125d5864249ae4297a57c84e74710bb6730223f325042fce535d040fee52ec13231bf709ccd84233c6944b90317e62528b2527dff9d659a96db4c99f9750168308633c1867b70f3a18fb0f4539a1aecedcd1fc0148fc22f36b6303083ece3f872b18e35d368b3958efe5fb081f7716736ccb598d269aa3084d57e1855e1ea9a45efc10463bbf32ae378029f5763ceb40173f"
    //         .parse()
    //         .unwrap();

    //     adaptor_sig
    //         .verify(&SECP256K1, &msg, &pubkey, &encryption_key)
    //         .expect("adaptor signature verification to pass");

    //     let sig = compact_sig_from_str("424d14a5471c048ab87b3b83f6085d125d5864249ae4297a57c84e74710bb67329e80e0ee60e57af3e625bbae1672b1ecaa58effe613426b024fa1621d903394");
    //     let expected_decryption_key: SecretKey =
    //         "0b2aba63b885a0f0e96fa0f303920c7fb7431ddfa94376ad94d969fbf4109dc8"
    //             .parse()
    //             .unwrap();

    //     let recovered = adaptor_sig
    //         .recover(&SECP256K1, &sig, &encryption_key)
    //         .expect("to be able to recover the decryption key");

    //     assert_eq!(expected_decryption_key, recovered);
    // }

    // #[test]
    // fn test_ecdsa_adaptor_signature_wrong_proof() {
    //     let msg = msg_from_str("8131e6f4b45754f2c90bd06688ceeabc0c45055460729928b4eecf11026a9e2d");
    //     let pubkey = "035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c"
    //         .parse()
    //         .unwrap();
    //     let encryption_key = "0214ccb756249ad6e733c80285ea7ac2ee12ffebbcee4e556e6810793a60c45ad4"
    //         .parse()
    //         .unwrap();
    //     let adaptor_sig: EcdsaAdaptorSignature = "03f94dca206d7582c015fb9bffe4e43b14591b30ef7d2b464d103ec5e116595dba03127f8ac3533d249280332474339000922eb6a58e3b9bf4fc7e01e4b4df2b7a4100a1e089f16e5d70bb89f961516f1de0684cc79db978495df2f399b0d01ed7240fa6e3252aedb58bdc6b5877b0c602628a235dd1ccaebdddcbe96198c0c21bead7b05f423b673d14d206fa1507b2dbe2722af792b8c266fc25a2d901d7e2c335"
    //         .parse()
    //         .unwrap();

    //     adaptor_sig
    //         .verify(&SECP256K1, &msg, &pubkey, &encryption_key)
    //         .expect_err("providing a wrong proof should fail validation");
    // }

    // #[test]
    // fn test_ecdsa_adaptor_signature_recover_wrong_sig_r_value() {
    //     let encryption_key = "035176d24129741b0fcaa5fd6750727ce30860447e0a92c9ebebdeb7c3f93995ed"
    //         .parse()
    //         .unwrap();
    //     let adaptor_sig: EcdsaAdaptorSignature = "03aa86d78059a91059c29ec1a757c4dc029ff636a1e6c1142fefe1e9d7339617c003a8153e50c0c8574a38d389e61bbb0b5815169e060924e4b5f2e78ff13aa7ad858e0c27c4b9eed9d60521b3f54ff83ca4774be5fb3a680f820a35e8840f4aaf2de88e7c5cff38a37b78725904ef97bb82341328d55987019bd38ae1745e3efe0f8ea8bdfede0d378fc1f96e944a7505249f41e93781509ee0bade77290d39cd12"
    //         .parse()
    //         .unwrap();

    //     let sig = compact_sig_from_str("f7f7fe6bd056fc4abd70d335f72d0aa1e8406bba68f3e579e4789475323564a452c46176c7fb40aa37d5651341f55697dab27d84a213b30c93011a7790bace8c");
    //     adaptor_sig
    //         .recover(&SECP256K1, &sig, &encryption_key)
    //         .expect_err("providing wrong r value should prevent us from recovering decryption key");
    // }

    // #[test]
    // fn test_ecdsa_adaptor_signature_recover_from_high_s_signature() {
    //     let encryption_key = "02042537e913ad74c4bbd8da9607ad3b9cb297d08e014afc51133083f1bd687a62"
    //         .parse()
    //         .unwrap();
    //     let adaptor_sig: EcdsaAdaptorSignature = "032c637cd797dd8c2ce261907ed43e82d6d1a48cbabbbece801133dd8d70a01b1403eb615a3e59b1cbbf4f87acaf645be1eda32a066611f35dd5557802802b14b19c81c04c3fefac5783b2077bd43fa0a39ab8a64d4d78332a5d621ea23eca46bc011011ab82dda6deb85699f508744d70d4134bea03f784d285b5c6c15a56e4e1fab4bc356abbdebb3b8fe1e55e6dd6d2a9ea457e91b2e6642fae69f9dbb5258854"
    //         .parse()
    //         .unwrap();

    //     let sig = compact_sig_from_str("2c637cd797dd8c2ce261907ed43e82d6d1a48cbabbbece801133dd8d70a01b14b5f24321f550b7b9dd06ee4fcfd82bdad8b142ff93a790cc4d9f7962b38c6a3b");
    //     let expected_decryption_key: SecretKey =
    //         "324719b51ff2474c9438eb76494b0dc0bcceeb529f0a5428fd198ad8f886e99c"
    //             .parse()
    //             .unwrap();
    //     let recovered = adaptor_sig
    //         .recover(&SECP256K1, &sig, &encryption_key)
    //         .expect("with high s we should still be able to recover the decryption key");

    //     assert_eq!(expected_decryption_key, recovered);
    // }

    // #[cfg(feature = "serde")]
    // #[test]
    // fn test_ecdsa_adaptor_sig_de_serialization() {
    //     use serde_test::Configure;
    //     use serde_test::{assert_tokens, Token};

    //     let sig = EcdsaAdaptorSignature::from_slice(&[
    //         3, 44, 99, 124, 215, 151, 221, 140, 44, 226, 97, 144, 126, 212, 62, 130, 214, 209, 164,
    //         140, 186, 187, 190, 206, 128, 17, 51, 221, 141, 112, 160, 27, 20, 3, 235, 97, 90, 62,
    //         89, 177, 203, 191, 79, 135, 172, 175, 100, 91, 225, 237, 163, 42, 6, 102, 17, 243, 93,
    //         213, 85, 120, 2, 128, 43, 20, 177, 156, 129, 192, 76, 63, 239, 172, 87, 131, 178, 7,
    //         123, 212, 63, 160, 163, 154, 184, 166, 77, 77, 120, 51, 42, 93, 98, 30, 162, 62, 202,
    //         70, 188, 1, 16, 17, 171, 130, 221, 166, 222, 184, 86, 153, 245, 8, 116, 77, 112, 212,
    //         19, 75, 234, 3, 247, 132, 210, 133, 181, 198, 193, 90, 86, 228, 225, 250, 180, 188, 53,
    //         106, 187, 222, 187, 59, 143, 225, 229, 94, 109, 214, 210, 169, 234, 69, 126, 145, 178,
    //         230, 100, 47, 174, 105, 249, 219, 181, 37, 136, 84,
    //     ])
    //     .unwrap();

    //     assert_tokens(
    //         &sig.readable(),
    //         &[Token::Str(
    //             "032c637cd797dd8c2ce261907ed43e82d6d1a48cbabbbece801133dd8d70a01b1403eb615a3e59b1cbbf4f87acaf645be1eda32a066611f35dd5557802802b14b19c81c04c3fefac5783b2077bd43fa0a39ab8a64d4d78332a5d621ea23eca46bc011011ab82dda6deb85699f508744d70d4134bea03f784d285b5c6c15a56e4e1fab4bc356abbdebb3b8fe1e55e6dd6d2a9ea457e91b2e6642fae69f9dbb5258854",
    //         )],
    //     );

    //     assert_tokens(
    //         &sig.compact(),
    //         &[Token::Bytes(&[
    //             3, 44, 99, 124, 215, 151, 221, 140, 44, 226, 97, 144, 126, 212, 62, 130, 214, 209,
    //             164, 140, 186, 187, 190, 206, 128, 17, 51, 221, 141, 112, 160, 27, 20, 3, 235, 97,
    //             90, 62, 89, 177, 203, 191, 79, 135, 172, 175, 100, 91, 225, 237, 163, 42, 6, 102,
    //             17, 243, 93, 213, 85, 120, 2, 128, 43, 20, 177, 156, 129, 192, 76, 63, 239, 172,
    //             87, 131, 178, 7, 123, 212, 63, 160, 163, 154, 184, 166, 77, 77, 120, 51, 42, 93,
    //             98, 30, 162, 62, 202, 70, 188, 1, 16, 17, 171, 130, 221, 166, 222, 184, 86, 153,
    //             245, 8, 116, 77, 112, 212, 19, 75, 234, 3, 247, 132, 210, 133, 181, 198, 193, 90,
    //             86, 228, 225, 250, 180, 188, 53, 106, 187, 222, 187, 59, 143, 225, 229, 94, 109,
    //             214, 210, 169, 234, 69, 126, 145, 178, 230, 100, 47, 174, 105, 249, 219, 181, 37,
    //             136, 84,
    //         ])],
    //     );
    // }

    // fn msg_from_str(input: &str) -> Message {
    //     let mut buf = [0u8; 32];
    //     from_hex(input, &mut buf).unwrap();
    //     Message::from_slice(&buf).unwrap()
    // }

    // fn compact_sig_from_str(input: &str) -> Signature {
    //     let mut buf = [0u8; 64];
    //     from_hex(input, &mut buf).unwrap();
    //     Signature::from_compact(&buf).unwrap()
    // }
}
