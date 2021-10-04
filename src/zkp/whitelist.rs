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
