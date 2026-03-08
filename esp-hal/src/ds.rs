//! # Digital Signature (DS) Accelerator
//!
//! ## Overview
//!
//! The Digital Signature peripheral provides hardware acceleration for
//! digital signature operations using HMAC-derived keys.
//!
//! ## Configuration
//!
//! The DS peripheral requires the DS clock to be enabled before use.
//! The `new()` function handles clock initialization.

use core::convert::TryInto;
use nb::block;

use crate::{
    peripherals::DS,
    sha::{Sha, Sha256},
    system::{GenericPeripheralGuard, Peripheral},
};

#[cfg(esp32s3)]
const MAX_RSA_WORDS: usize = 128;
#[cfg(not(esp32s3))]
const MAX_RSA_WORDS: usize = 96;

const MAX_RSA_BYTES: usize = MAX_RSA_WORDS * 4;
const ENCRYPTED_PARAMS_PREFIX_LEN: usize = 20; // 4-byte payload length + 16-byte IV
const BOX_CIPHER_LEN: usize = 48;

/// RSA key size for DS peripheral
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeySize {
    /// 2048-bit RSA key
    Rsa2048,
    /// 3072-bit RSA key
    Rsa3072,
    /// 4096-bit RSA key (supported on chips with 4096-bit DS operand width)
    #[cfg(esp32s3)]
    Rsa4096,
}

impl KeySize {
    /// Returns key size in bits
    pub fn bits(&self) -> usize {
        match self {
            KeySize::Rsa2048 => 2048,
            KeySize::Rsa3072 => 3072,
            #[cfg(esp32s3)]
            KeySize::Rsa4096 => 4096,
        }
    }

    /// Returns key size in bytes
    pub fn bytes(&self) -> usize {
        self.bits() / 8
    }

    /// Returns signature word count (key_bits / 32)
    pub fn sig_words(&self) -> usize {
        self.bits() / 32
    }
}

/// Error type for DS operations
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// The DS peripheral failed to initialize
    InitFailed,
    /// The encrypted params have incorrect length
    IncorrectCipherLength,
    /// Failed to read key from eFuse
    KeyReadError,
    /// DS signing operation did not complete
    SigningFailed,
    /// The signature padding check passed but MD check failed (signature included for debugging)
    InvalidDigest(Signature),
    /// The signature MD check passed but padding check failed (signature included for debugging)
    InvalidPadding(Signature),
    /// Both MD check and padding check failed (signature included for debugging)
    InvalidDigestAndPadding(Signature),
    /// The key size is not supported
    UnsupportedKeySize,
}

impl Error {
    /// Returns the signature if one is associated with this error (for debugging)
    pub fn signature(&self) -> Option<&Signature> {
        match self {
            Error::InvalidDigest(sig) => Some(sig),
            Error::InvalidPadding(sig) => Some(sig),
            Error::InvalidDigestAndPadding(sig) => Some(sig),
            _ => None,
        }
    }
}

/// DS driver instance
pub struct Ds<'d> {
    ds: DS<'d>,
    _guard: GenericPeripheralGuard<{ Peripheral::Ds as u8 }>,
}

impl<'d> Ds<'d> {
    /// Creates a new instance of the DS peripheral.
    ///
    /// This enables the DS peripheral clock.
    pub fn new(ds: DS<'d>) -> Self {
        let guard = GenericPeripheralGuard::new();
        Self { ds, _guard: guard }
    }

    /// Returns a reference to the peripheral registers.
    pub fn regs(&self) -> &crate::pac::ds::RegisterBlock {
        self.ds.register_block()
    }

    /// Sign a message using the hardware DS peripheral.
    ///
    /// The message is hashed with SHA-256 and then padded with PKCS#1 v1.5
    /// format before being signed by the DS peripheral.
    pub fn sign(
        &mut self,
        message: &[u8],
        sha: &mut Sha<'_>,
        key_size: KeySize,
        encrypted_params: &[u8],
    ) -> Result<Signature, Error> {
        // Hash the message with SHA-256 using hardware SHA
        let mut hasher = sha.start::<Sha256>();
        let mut remaining = message;
        while !remaining.is_empty() {
            remaining = block!(hasher.update(remaining)).expect("infallible");
        }
        let mut hash = [0u8; 32];
        block!(hasher.finish(&mut hash)).unwrap();

        // Create PKCS#1 v1.5 padded message with DigestInfo
        let padded_message = pad_message_for_rsa(&hash, key_size.bytes())?;

        let sig = private_exponentiation(&self.ds, encrypted_params, padded_message, key_size)?;
        Ok(sig)
    }
}

/// Signature output - size depends on key size
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Signature {
    /// 2048-bit RSA signature (256 bytes)
    Rsa2048([u8; 256]),
    /// 3072-bit RSA signature (384 bytes)
    Rsa3072([u8; 384]),
    /// 4096-bit RSA signature (512 bytes)
    #[cfg(esp32s3)]
    Rsa4096([u8; 512]),
}

impl Signature {
    /// Returns the signature as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Signature::Rsa2048(s) => s.as_slice(),
            Signature::Rsa3072(s) => s.as_slice(),
            #[cfg(esp32s3)]
            Signature::Rsa4096(s) => s.as_slice(),
        }
    }

    /// Returns the signature length in bytes
    pub fn len(&self) -> usize {
        match self {
            Signature::Rsa2048(_) => 256,
            Signature::Rsa3072(_) => 384,
            #[cfg(esp32s3)]
            Signature::Rsa4096(_) => 512,
        }
    }

    /// Returns true if signature length is zero.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// RSA private exponentiation.
fn private_exponentiation(
    ds: &DS<'_>,
    encrypted_params: &[u8],
    mut challenge: [u8; MAX_RSA_BYTES],
    key_size: KeySize,
) -> Result<Signature, Error> {
    let regs = ds.register_block();

    let key_bytes = key_size.bytes();
    let sig_words = key_size.sig_words();

    // encrypted_params format:
    // [u32 payload_len][iv(16) || ciphertext]
    // ciphertext format:
    // [Y(key_bytes) || M(key_bytes) || Rb(key_bytes) || Box(48)]
    let expected_payload_len = 16 + (key_bytes * 3) + BOX_CIPHER_LEN;
    let expected_total_len = 4 + expected_payload_len;

    if encrypted_params.len() != expected_total_len {
        return Err(Error::IncorrectCipherLength);
    }

    let payload_len = u32::from_le_bytes(encrypted_params[0..4].try_into().unwrap()) as usize;
    if payload_len != expected_payload_len {
        return Err(Error::IncorrectCipherLength);
    }

    challenge.reverse();

    let iv = &encrypted_params[4..20];
    let ciph = &encrypted_params[ENCRYPTED_PARAMS_PREFIX_LEN..];
    let y_ciph = &ciph[0..key_bytes];
    let m_ciph = &ciph[key_bytes..key_bytes * 2];
    let rb_ciph = &ciph[key_bytes * 2..key_bytes * 3];
    let box_ciph = &ciph[key_bytes * 3..key_bytes * 3 + BOX_CIPHER_LEN];

    regs.set_start().write(|w| w.set_start().set_bit());
    wait_for_ds_start_ready(regs)?;

    // Write IV (step 4 in TRM)
    for (i, v) in iv.chunks(4).enumerate() {
        let data = u32::from_le_bytes(v.try_into().unwrap());
        regs.iv_mem(i).write(|w| unsafe { w.bits(data) });
    }

    // Write X (message/challenge) (step 5 in TRM)
    for (i, v) in challenge[..key_bytes].chunks(4).enumerate() {
        let data = u32::from_le_bytes(v.try_into().unwrap());
        regs.x_mem(i).write(|w| unsafe { w.bits(data) });
    }

    // Write Y (private exponent), padded to max register width
    let mut y_padded = [0u8; MAX_RSA_BYTES];
    y_padded[..key_bytes].copy_from_slice(y_ciph);
    for (i, v) in y_padded.chunks(4).enumerate() {
        let data = u32::from_le_bytes(v.try_into().unwrap());
        regs.y_mem(i).write(|w| unsafe { w.bits(data) });
    }

    // Write M (modulus), padded to max register width
    let mut m_padded = [0u8; MAX_RSA_BYTES];
    m_padded[..key_bytes].copy_from_slice(m_ciph);
    for (i, v) in m_padded.chunks(4).enumerate() {
        let data = u32::from_le_bytes(v.try_into().unwrap());
        regs.m_mem(i).write(|w| unsafe { w.bits(data) });
    }

    // Write Rb (Montgomery parameter), padded to max register width
    let mut rb_padded = [0u8; MAX_RSA_BYTES];
    rb_padded[..key_bytes].copy_from_slice(rb_ciph);
    for (i, v) in rb_padded.chunks(4).enumerate() {
        let data = u32::from_le_bytes(v.try_into().unwrap());
        regs.rb_mem(i).write(|w| unsafe { w.bits(data) });
    }

    // Write box parameters
    for (i, v) in box_ciph.chunks(4).enumerate() {
        let data = u32::from_le_bytes(v.try_into().unwrap());
        regs.box_mem(i).write(|w| unsafe { w.bits(data) });
    }

    // Start DS operation (step 7 in TRM)
    regs.set_continue().write(|w| w.set_continue().set_bit());

    wait_for_ds_idle(regs);

    // Read check result first
    let check_result = regs.query_check().read().bits();

    // Always read signature - even if validation failed, useful for debugging
    let mut sig = [0u32; MAX_RSA_WORDS];
    for (i, sig_word) in sig.iter_mut().enumerate().take(sig_words) {
        let word = regs.z_mem(i).read().bits();
        *sig_word = word;
    }

    regs.set_finish().write(|w| w.set_finish().set_bit());
    wait_for_ds_idle(regs);

    // Convert to bytes
    let mut result = [0u8; MAX_RSA_BYTES];
    for (i, &word) in sig.iter().take(sig_words).rev().enumerate() {
        let bytes = word.to_be_bytes();
        let start = i * 4;
        result[start..start + 4].copy_from_slice(&bytes);
    }

    // Create signature
    let signature = match key_size {
        KeySize::Rsa2048 => Signature::Rsa2048(result[..256].try_into().unwrap()),
        KeySize::Rsa3072 => Signature::Rsa3072(result[..384].try_into().unwrap()),
        #[cfg(esp32s3)]
        KeySize::Rsa4096 => Signature::Rsa4096(result[..512].try_into().unwrap()),
    };

    // Return based on check result
    match check_result {
        0 => Ok(signature),
        1 => Err(Error::InvalidDigest(signature)),
        2 => Err(Error::InvalidPadding(signature)),
        3 => Err(Error::InvalidDigestAndPadding(signature)),
        _ => Err(Error::SigningFailed),
    }
}

fn wait_for_ds_idle(regs: &crate::pac::ds::RegisterBlock) {
    while regs.query_busy().read().query_busy().bit() {
        core::hint::spin_loop();
    }
}

fn wait_for_ds_start_ready(regs: &crate::pac::ds::RegisterBlock) -> Result<(), Error> {
    loop {
        // If key derivation failed, DS can remain busy until timeout unless we check this.
        if regs.query_key_wrong().read().query_key_wrong().bits() != 0 {
            return Err(Error::KeyReadError);
        }

        if !regs.query_busy().read().query_busy().bit() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
}

fn pad_message_for_rsa(
    message_digest: &[u8],
    key_bytes: usize,
) -> Result<[u8; MAX_RSA_BYTES], Error> {
    // Hard-code the ASN.1 DigestInfo prefix for SHA-256
    const SHA256_ASN1_PREFIX: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let mut padded_block = [0u8; MAX_RSA_BYTES];

    // PKCS#1 v1.5 format: 0x00 || 0x01 || PS || 0x00 || T
    padded_block[0] = 0x00;
    padded_block[1] = 0x01;

    // Calculate padding length
    let padding_len = key_bytes
        .checked_sub(SHA256_ASN1_PREFIX.len() + message_digest.len() + 3)
        .ok_or(Error::UnsupportedKeySize)?;

    // Fill with 0xFF bytes
    for i in 0..padding_len {
        padded_block[2 + i] = 0xFF;
    }

    // Add 0x00 separator
    padded_block[2 + padding_len] = 0x00;

    // Add prefix (ASN.1 DigestInfo)
    let prefix_offset = 3 + padding_len;
    padded_block[prefix_offset..(prefix_offset + SHA256_ASN1_PREFIX.len())]
        .copy_from_slice(SHA256_ASN1_PREFIX);

    // Add message digest
    let digest_offset = prefix_offset + SHA256_ASN1_PREFIX.len();
    padded_block[digest_offset..(digest_offset + message_digest.len())]
        .copy_from_slice(message_digest);

    Ok(padded_block)
}
