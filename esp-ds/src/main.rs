use ::pem::parse_many as parse_pem_many;
use aes::Aes256;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use cbc::Encryptor;
use clap::Parser;
use hmac::Mac;
use num_traits::{One, ToPrimitive, Zero};
use rand::Rng;
use rsa::BigUint;
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;

const DS_KEY_SIZE_BITS: usize = 3072;
const DS_KEY_SIZE_BYTES: usize = DS_KEY_SIZE_BITS / 8;
const DS_NUM_WORDS: usize = DS_KEY_SIZE_BITS / 32;

type HmacSha256 = hmac::Hmac<Sha256>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// CA certificate in PEM format
    #[arg(long, required = true)]
    ca_cert: String,

    /// Device certificate in PEM format
    #[arg(long, required = true)]
    device_cert: String,

    /// Device private key in PEM format
    #[arg(long, required = true)]
    device_key: String,

    /// Output file for the binary data (bincode encoded)
    #[arg(long)]
    output: Option<String>,

    /// Output file for the HMAC key (32 bytes)
    #[arg(long)]
    hmac_key_output: Option<String>,

    /// Read existing HMAC key from eFuse BLOCK_KEY2 instead of generating new one
    #[arg(long)]
    read_efuse_key: bool,

    /// Serial port for flashing
    #[arg(short, long)]
    port: Option<String>,

    /// Flash to esp_secure_cert partition (offset 0xD000)
    #[arg(long)]
    flash: bool,

    /// Burn HMAC key to eFuse BLOCK_KEY2
    #[arg(long)]
    burn_efuse: bool,
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq)]
struct FactoryData {
    ds_encrypted_params: Vec<u8>,
    certificate: Certificate,
}

#[derive(Debug, Clone, PartialEq, bincode::Encode, bincode::Decode)]
struct Certificate {
    ca_cert: Vec<u8>,
    device_cert: Vec<u8>,
}

#[repr(C)]
#[derive(Debug)]
struct EspDsPData {
    y: [u32; DS_NUM_WORDS],
    m: [u32; DS_NUM_WORDS],
    rb: [u32; DS_NUM_WORDS],
    m_prime: u32,
    length: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Determine output folder
    let output_folder = if let Some(ref port) = args.port {
        // Read MAC address from device
        let mac = get_mac_address(port)?;
        let folder_name = format!("esp32c3-{}", mac);
        // Use crate root as base path
        let base_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data");
        let folder_path = base_path.join(&folder_name);

        // Create folder (overwrite if exists)
        if folder_path.exists() {
            fs::remove_dir_all(&folder_path)?;
        }
        fs::create_dir_all(&folder_path)?;

        Some((folder_path, folder_name))
    } else {
        None
    };

    // Load and parse certificates
    let ca_cert_pem = fs::read(&args.ca_cert)?;
    let device_cert_pem = fs::read(&args.device_cert)?;
    let device_key_pem = fs::read(&args.device_key)?;

    // Load RSA private key
    let rsa_private = load_rsa_private_key(&device_key_pem)?;

    // Get HMAC key - either from eFuse or generate new
    let hmac_key = if args.read_efuse_key {
        if let Some(port) = &args.port {
            read_efuse_hmac_key(port)?
        } else {
            return Err("--port required when reading from eFuse".into());
        }
    } else {
        // Generate random HMAC key
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        key
    };

    // Compute encrypted DS params
    let encrypted_params = encrypt_ds_params(&rsa_private, &hmac_key)?;

    // Create certificate structure
    let certificate = Certificate {
        ca_cert: ca_cert_pem,
        device_cert: device_cert_pem,
    };

    // Create factory data
    let factory_data = FactoryData {
        ds_encrypted_params: encrypted_params,
        certificate,
    };

    // Bincode encode with version byte prefix
    let config = bincode::config::standard().with_fixed_int_encoding();
    let mut encoded = vec![0u8]; // Version byte = 0
    let encoded_data = bincode::encode_to_vec(&factory_data, config)?;
    encoded.extend(encoded_data);

    // Output to file or stdout
    if let Some((ref folder, _)) = output_folder {
        let p = folder.join("ds_data.bin");
        fs::write(&p, &encoded)?;
        println!("Wrote bincode to {}", p.display());
    } else if let Some(output_path) = &args.output {
        fs::write(output_path, &encoded)?;
        println!("Wrote bincode to {}", output_path);
    } else {
        std::io::stdout().write_all(&encoded)?;
    }

    // Output HMAC key to separate file if requested
    if let Some((ref folder, _)) = output_folder {
        let p = folder.join("ds_hmac_key.bin");
        fs::write(&p, &hmac_key[..])?;
        println!("Wrote HMAC key to {}", p.display());
    } else if let Some(hmac_key_path) = &args.hmac_key_output {
        fs::write(hmac_key_path, &hmac_key[..])?;
        println!("Wrote HMAC key to {}", hmac_key_path);
    }

    // Flash if requested
    if args.flash {
        if let Some(port) = &args.port {
            println!("Flashing to {} at offset 0xD000...", port);
            flash_partition(port, &encoded)?;
        } else {
            println!("Error: --port required for flashing");
        }
    }

    // Burn eFuse if requested
    if args.burn_efuse {
        if let Some(port) = &args.port {
            println!("Burning HMAC key to eFuse BLOCK_KEY2...");
            burn_efuse(port, &hmac_key)?;
        } else {
            println!("Error: --port required for burning eFuse");
        }
    }

    Ok(())
}

fn load_rsa_private_key(pem_data: &[u8]) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    let pems = parse_pem_many(pem_data)?;

    for pem in pems {
        if pem.tag() == "RSA PRIVATE KEY" || pem.tag() == "PRIVATE KEY" {
            let key = RsaPrivateKey::from_pkcs8_der(pem.contents())?;
            if key.n().bits() == DS_KEY_SIZE_BITS {
                return Ok(key);
            } else {
                return Err(format!(
                    "RSA key size must be {} bits, got {} bits",
                    DS_KEY_SIZE_BITS,
                    key.n().bits()
                )
                .into());
            }
        }
    }

    Err("No RSA private key found in PEM data".into())
}

fn encrypt_ds_params(
    rsa_private: &RsaPrivateKey,
    hmac_key: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Derive AES key: HMAC-SHA256(hmac_key, [0xff; 32])
    let mut mac = HmacSha256::new_from_slice(hmac_key)?;
    mac.update([0xffu8; 32].as_slice());
    let aes_key: [u8; 32] = mac.finalize().into_bytes().into();

    let iv = [
        0xb8, 0xb4, 0x69, 0x18, 0x28, 0xa3, 0x91, 0xd9, 0xd6, 0x62, 0x85, 0x8c, 0xc9, 0x79, 0x48,
        0x86,
    ];

    let plaintext_data = EspDsPData::new(rsa_private)?;
    let encrypted_params = encrypt_private_key_material(&plaintext_data, &aes_key[..], &iv[..])?;

    Ok(encrypted_params)
}

impl EspDsPData {
    fn new(rsa_private: &RsaPrivateKey) -> Result<Self, Box<dyn std::error::Error>> {
        let y_big = rsa_private.d();
        let m_big = rsa_private.n();

        let y_vec = big_number_to_words(y_big);
        let m_vec = big_number_to_words(m_big);

        let length = (DS_KEY_SIZE_BITS / 32 - 1) as u32;

        let y_arr = vec_to_fixed(&y_vec, DS_NUM_WORDS);
        let m_arr = vec_to_fixed(&m_vec, DS_NUM_WORDS);

        let n0 = (m_big & BigUint::from(0xffffffffu32))
            .to_u32()
            .ok_or("Failed to convert modulus remainder to u32")?;
        let inv_n0 = modinv_u32(n0).ok_or("Failed to compute modular inverse for m_prime")?;
        let m_prime = (!inv_n0).wrapping_add(1);

        let rr = BigUint::one() << (DS_KEY_SIZE_BITS * 2);
        let rb_big = &rr % m_big;
        let rb_vec = big_number_to_words(&rb_big);
        let rb_arr = vec_to_fixed(&rb_vec, DS_NUM_WORDS);

        Ok(EspDsPData {
            y: y_arr,
            m: m_arr,
            rb: rb_arr,
            m_prime,
            length,
        })
    }
}

fn big_number_to_words(num: &BigUint) -> Vec<u32> {
    let mut vec = Vec::new();
    let mut n = num.clone();
    let mask = BigUint::from(0xffffffffu32);
    while n > BigUint::zero() {
        let word = (&n & &mask).to_u32().unwrap();
        vec.push(word);
        n >>= 32;
    }
    if vec.is_empty() {
        vec.push(0);
    }
    vec
}

fn vec_to_fixed(vec: &[u32], fixed_len: usize) -> [u32; DS_NUM_WORDS] {
    let mut arr = [0u32; DS_NUM_WORDS];
    for (i, &word) in vec.iter().enumerate().take(fixed_len) {
        arr[i] = word;
    }
    arr
}

fn modinv_u32(a: u32) -> Option<u32> {
    let modulus: i64 = 1i64 << 32;
    let mut r: i64 = modulus;
    let mut new_r: i64 = a as i64;
    let mut t: i64 = 0;
    let mut new_t: i64 = 1;

    while new_r != 0 {
        let quotient = r / new_r;
        let temp_t = t - quotient * new_t;
        t = new_t;
        new_t = temp_t;
        let temp_r = r - quotient * new_r;
        r = new_r;
        new_r = temp_r;
    }
    if r > 1 {
        return None;
    }
    if t < 0 {
        t += modulus;
    }
    Some(t as u32)
}

fn encrypt_private_key_material(
    ds_data: &EspDsPData,
    aes_key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let max_key_size = DS_KEY_SIZE_BYTES;

    let y_bytes = number_as_bytes(&ds_data.y, max_key_size);
    let m_bytes = number_as_bytes(&ds_data.m, max_key_size);
    let rb_bytes = number_as_bytes(&ds_data.rb, max_key_size);

    let mut mprime_length = Vec::new();
    mprime_length.extend_from_slice(&ds_data.m_prime.to_le_bytes());
    mprime_length.extend_from_slice(&ds_data.length.to_le_bytes());

    let mut md_in = Vec::new();
    md_in.extend_from_slice(&y_bytes);
    md_in.extend_from_slice(&m_bytes);
    md_in.extend_from_slice(&rb_bytes);
    md_in.extend_from_slice(&mprime_length);
    md_in.extend_from_slice(iv);

    let md = Sha256::digest(&md_in);

    let mut p = Vec::new();
    p.extend_from_slice(&y_bytes);
    p.extend_from_slice(&m_bytes);
    p.extend_from_slice(&rb_bytes);
    p.extend_from_slice(&md);
    p.extend_from_slice(&mprime_length);
    p.extend_from_slice(&[0x08u8; 8]);

    let expected_len = (max_key_size * 3) + 32 + 8 + 8;
    assert_eq!(p.len(), expected_len, "P length mismatch");

    let mut out_buf = vec![0u8; p.len()];

    type Aes256CbcEnc = Encryptor<Aes256>;
    let ct = Aes256CbcEnc::new(aes_key.into(), iv.into())
        .encrypt_padded_b2b_mut::<aes::cipher::block_padding::NoPadding>(&p, &mut out_buf)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    let iv_and_ct = [iv, ct].concat();

    Ok(iv_and_ct)
}

fn number_as_bytes(words: &[u32; DS_NUM_WORDS], max_size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(max_size);
    for &word in words.iter().take(max_size / 4) {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    while bytes.len() < max_size {
        bytes.push(0);
    }
    bytes
}

fn flash_partition(port: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Write data to temp file
    let temp_data_file = "/tmp/esp_ds_data.bin";
    fs::write(temp_data_file, data)?;

    let output = std::process::Command::new("esptool")
        .args([
            "--chip",
            "esp32c3",
            "--port",
            port,
            "write_flash",
            "0xD000",
            temp_data_file,
        ])
        .output()?;

    // Clean up temp file
    let _ = fs::remove_file(temp_data_file);

    if !output.status.success() {
        return Err(format!(
            "esptool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    println!("Flashed successfully");
    Ok(())
}

fn burn_efuse(port: &str, hmac_key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    // Write HMAC key to temp file
    let temp_key_file = "/tmp/esp_ds_hmac_key.bin";
    fs::write(temp_key_file, hmac_key)?;

    let output = std::process::Command::new("espefuse")
        .args([
            "--port",
            port,
            "burn_key",
            "BLOCK_KEY2",
            temp_key_file,
            "HMAC_DOWN_DIGITAL_SIGNATURE",
            "--no-read-protect",
        ])
        .output()?;

    // Clean up temp file
    let _ = fs::remove_file(temp_key_file);

    if !output.status.success() {
        return Err(format!(
            "espefuse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    println!("HMAC key burned to eFuse successfully");
    Ok(())
}

fn read_efuse_hmac_key(port: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // Read HMAC key from eFuse BLOCK_KEY2
    let output = std::process::Command::new("espefuse")
        .args(["--port", port, "dump"])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "espefuse dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // Parse the output to find BLOCK_KEY2
    // Format: "BLOCK_KEY2      (BLOCK6          ) [6 ] dump: 96b55379 6b3e61c3 533c5554 e09ae681 c55a9134 95e16edd 0c79a8dd 75be99dd"
    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        if line.contains("BLOCK_KEY2") && line.contains("dump:") {
            // Extract hex bytes after "dump:"
            if let Some(dump_pos) = line.find("dump:") {
                let key_str = line[dump_pos + 5..].trim();

                // espefuse dump prints each 32-bit word in big-endian hex text,
                // but eFuse key bytes are consumed little-endian per word by firmware.
                let mut key_bytes = Vec::new();
                for chunk in key_str.split_whitespace() {
                    if chunk.len() == 8 {
                        if let Ok(word) = u32::from_str_radix(chunk, 16) {
                            key_bytes.extend_from_slice(&word.to_le_bytes());
                        }
                    }
                }

                if key_bytes.len() >= 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes[..32]);
                    println!("Read HMAC key from eFuse BLOCK_KEY2");
                    return Ok(key);
                }
            }
        }
    }

    Err("Could not find HMAC key in eFuse dump".into())
}

fn get_mac_address(port: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Use esptool to read MAC address
    let output = std::process::Command::new("esptool")
        .args(["--port", port, "read-mac"])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "esptool read-mac failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Look for MAC address in output
    // Format: "MAC: b8:f8:62:b4:da:18"
    for line in output_str.lines() {
        if line.contains("MAC:") {
            if let Some(mac_start) = line.find("MAC:") {
                let mac_part = line[mac_start + 4..].trim();
                // Convert "b8:f8:62:b4:da:18" to "b8f862b4da18"
                let mac = mac_part.replace(":", "");
                if mac.len() == 12 {
                    return Ok(mac);
                }
            }
        }
    }

    Err("Could not find MAC address".into())
}
