//! Demonstrates the use of the DS (Digital Signature) peripheral for
//! hardware-accelerated RSA signing.
//!
//! # Prerequisites
//! Before using the DS peripheral, you need to:
//! 1. Generate an RSA private key and flash it to eFuse
//! 2. The DS peripheral uses HMAC to derive the key
//!
//! # Example Usage
//! This example shows how to initialize the DS peripheral and sign a message.

#![no_std]
#![no_main]

use embedded_storage::ReadStorage;
use esp_backtrace as _;
use esp_bootloader_esp_idf::partitions;
use esp_hal::{
    ds::{Ds, KeySize},
    efuse::{self, Efuse},
    hmac::Hmac,
    main,
    sha::Sha,
};
use esp_println::{print, println};
use esp_storage::FlashStorage;

esp_bootloader_esp_idf::esp_app_desc!();

const ENCRYPTED_PAYLOAD_LEN: usize = 1216;
const ENCRYPTED_PARAMS_LEN: usize = 1220;

#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default());

    // Read HMAC key purpose (KEY_PURPOSE_2 for BLOCK_KEY2)
    let key_purpose: u32 = Efuse::read_field_le(efuse::KEY_PURPOSE_2);
    println!("KEY2 purpose: {}", key_purpose);

    // Read HMAC key (will be zeros if read-protected)
    let hmac_key: [u8; 32] = Efuse::read_field_le(efuse::BLOCK_KEY2);
    print!("HMAC key: ");
    for byte in hmac_key.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // Initialize DS peripheral
    let mut ds = Ds::new(peripherals.DS);

    let _hmac = Hmac::new(peripherals.HMAC);

    // Initialize SHA for message hashing
    let mut sha = Sha::new(peripherals.SHA);

    let mut flash = FlashStorage::new(peripherals.FLASH);

    let mut pt_mem = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let pt = partitions::read_partition_table(&mut flash, &mut pt_mem).unwrap();

    // Find esp_secure_cert partition by label instead of fixed index.
    let cert_partition = (0..pt.len())
        .find_map(|i| {
            let p = pt.get_partition(i).ok()?;
            (p.label_as_str() == "esp_secure_cert").then_some(p)
        })
        .expect("esp_secure_cert partition not found");
    let mut cert_partition = cert_partition.as_embedded_storage(&mut flash);

    // Current esp_secure_cert payload layout used by provisioning code:
    // [version: u8][vec_len: u64 le][encrypted_payload: vec_len bytes]
    // where encrypted_payload is [iv (16) || ciphertext (1200)] for RSA-3072.
    let mut version = [0u8; 1];
    cert_partition.read(0, &mut version).unwrap();
    println!("esp_secure_cert version: {}", version[0]);

    let mut payload_len_le = [0u8; 8];
    cert_partition.read(1, &mut payload_len_le).unwrap();
    let payload_len = u64::from_le_bytes(payload_len_le) as usize;
    println!("Stored encrypted payload length: {}", payload_len);

    if payload_len != ENCRYPTED_PAYLOAD_LEN {
        println!(
            "Unexpected encrypted payload length {} (expected {})",
            payload_len, ENCRYPTED_PAYLOAD_LEN
        );
        loop {}
    }

    let mut encrypted_payload = [0u8; ENCRYPTED_PAYLOAD_LEN];
    cert_partition.read(1 + 8, &mut encrypted_payload).unwrap();

    // Repack to DS driver format: [u32 len=1216][iv||ciphertext]
    let mut encrypted_params = [0u8; ENCRYPTED_PARAMS_LEN];
    encrypted_params[..4].copy_from_slice(&(ENCRYPTED_PAYLOAD_LEN as u32).to_le_bytes());
    encrypted_params[4..].copy_from_slice(&encrypted_payload);

    println!("Encrypted params length: {}", encrypted_params.len());

    // Example message to sign
    let message = b"Hello, World!";

    println!("Starting DS sign...");
    match ds.sign(message, &mut sha, KeySize::Rsa3072, &encrypted_params) {
        Ok(signature) => {
            println!("Signature generated: {} bytes", signature.as_bytes().len());
            print!("Signature: ");
            for byte in signature.as_bytes().iter() {
                print!("{:02x}", byte);
            }
            println!();
        }
        Err(e) => {
            println!("DS signing failed: {:?}", e);
        }
    }

    loop {}
}
