# Parsing Encrypted DS Data into DS Parameters

This document describes how the encrypted Digital Signature (DS) data stored in the esp_secure_cert partition should be parsed into the parameters required by the ESP-IDF DS peripheral.

## Overview

When using RSA Digital Signature (DS) peripheral on ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6, ESP32-H2, or ESP32-P4, the RSA private key parameters are encrypted and stored in the esp_secure_cert partition. The encryption uses HMAC-based key derivation from an eFuse-stored HMAC key.

## TLV Data Structure

The DS data is stored in two TLV entries in the partition:

### 1. DS Data TLV (`ESP_SECURE_CERT_DS_DATA_TLV`, Type = 3)

| Field | Size | Type | Description |
|-------|------|------|-------------|
| `length` | 4 bytes | `int32_t` (little-endian) | RSA key length indicator: `(key_size_bits / 32) - 1` |
| `iv` | 16 bytes | `uint8_t[16]` | AES CBC initialization vector |
| `ciphertext` | Variable | `uint8_t[]` | Encrypted RSA private key parameters |

**Total DS Data Structure (packed):**
```c
struct esp_secure_cert_ds_data {
    int32_t length;           // 4 bytes: key_len / 32 - 1
    uint8_t iv[16];          // 16 bytes: AES IV
    uint8_t c[];             // Variable: encrypted RSA params (ciphertext)
};
```

The `length` field values for different key sizes:
- 1024-bit RSA: `length = 0` (32/32 - 1 = 0)
- 2048-bit RSA: `length = 1` (64/32 - 1 = 1)
- 3072-bit RSA: `length = 2` (96/32 - 1 = 2)
- 4096-bit RSA: `length = 3` (128/32 - 1 = 3)

### 2. DS Context TLV (`ESP_SECURE_CERT_DS_CONTEXT_TLV`, Type = 4)

| Field | Size | Type | Description |
|-------|------|------|-------------|
| `flags` | 4 bytes | `uint32_t` | Reserved/padding |
| `efuse_key_id` | 1 byte | `uint8_t` | eFuse key block ID used for HMAC |
| `padding` | 1 byte | `uint8_t` | Padding byte (0x00) |
| `rsa_key_len` | 2 bytes | `uint16_t` (little-endian) | RSA key length in bits |

## TLV Header Structure

Each TLV entry has the following header format:

```c
typedef struct {
    uint32_t magic;          // 0xBA5EBA11 (ESP_SECURE_CERT_TLV_MAGIC)
    uint32_t flags;          // Key type flags (for private key TLV)
    uint16_t type;           // TLV type identifier
    uint16_t subtype;        // TLV subtype (always 0 for DS)
    uint16_t length;         // Length of TLV data
} esp_secure_cert_tlv_header_t;

// Followed by TLV data, optional padding, and footer (CRC32)
```

## Parsing Steps

### Step 1: Read DS Data TLV

Read the TLV entry with type `ESP_SECURE_CERT_DS_DATA_TLV` (value = 3):

```python
# Example parsing in Python
def parse_ds_data_tlv(tlv_data):
    length = struct.unpack('<i', tlv_data[0:4])[0]
    iv = tlv_data[4:20]
    ciphertext = tlv_data[20:]

    rsa_key_len = (length + 1) * 32 * 8  # Convert to bits

    return {
        'length': length,
        'rsa_key_bits': rsa_key_len,
        'iv': iv,
        'ciphertext': ciphertext
    }
```

### Step 2: Read DS Context TLV

Read the TLV entry with type `ESP_SECURE_CERT_DS_CONTEXT_TLV` (value = 4):

```python
def parse_ds_context_tlv(tlv_data):
    flags = struct.unpack('<I', tlv_data[0:4])[0]
    efuse_key_id = struct.unpack('<B', tlv_data[4:5])[0]
    padding = struct.unpack('<B', tlv_data[5:6])[0]
    rsa_key_len = struct.unpack('<H', tlv_data[6:8])[0]

    return {
        'flags': flags,
        'efuse_key_id': efuse_key_id,
        'rsa_key_len': rsa_key_len
    }
```

### Step 3: Decrypt the Ciphertext (On Device)

The ciphertext is encrypted using AES-256-CBC. The decryption key and IV are derived from the HMAC key stored in eFuse.

**Key Derivation:**
```c
// The AES key is derived using HMAC-SHA256
// HMAC key = eFuse HMAC key with purpose HMAC_DOWN_DIGITAL_SIGNATURE
hmac_key_t hmac_key_id = /* eFuse block with purpose HMAC_UP */;

// Key derivation message: 0xFF * 32
uint8_t key_message[32] = {0xFF, 0xFF, ...};
esp_hmac_calculate(hmac_key_id, key_message, 32, aes_key);

// IV derivation message: 0xCD * 32
uint8_t iv_message[32] = {0xCD, 0xCD, ...};
esp_hmac_calculate(hmac_key_id, iv_message, 32, derived_iv);
```

**Decryption:**
```c
// Decrypt using AES-256-CBC
// The decrypted data contains the RSA private key parameters
esp_secure_cert_crypto_gcm_decrypt(ciphertext, ciphertext_len,
                                   plaintext, aes_key, 32, derived_iv,
                                   NULL, ciphertext + ciphertext_len, 16);
```

### Step 4: Extract RSA Parameters from Decrypted Data

After decryption, the plaintext contains the RSA private key parameters:

| Field | Size | Description |
|-------|------|-------------|
| `Y` | `max_key_len` bytes | RSA private exponent (little-endian) |
| `M` | `max_key_len` bytes | RSA modulus (little-endian) |
| `R` | `max_key_len` bytes | R^2 mod M (Montgomery parameter) |
| `MD` | 32 bytes | SHA-256 hash of (Y \|\| M \|\| R \|\| mprime \|\| length) |
| `mprime` | 4 bytes | Montgomery parameter (int32) |
| `length` | 4 bytes | Key length indicator (int32) |
| `padding` | 8 bytes | All zeros (0x08 * 8) |

The `max_key_len` depends on the target chip's maximum supported RSA key size:
- ESP32-S2, ESP32-S3, ESP32-P4: 4096-bit (512 bytes)
- ESP32-C3, ESP32-C6, ESP32-H2: 3072-bit (384 bytes)

## Using the DS Parameters

After parsing, the DS context structure (`esp_ds_data_ctx_t`) should be populated:

```c
typedef struct {
    esp_ds_data_t *esp_ds_data;    // Pointer to DS data
    uint32_t rsa_length_bits;      // RSA key length in bits
    uint8_t efuse_key_id;          // eFuse key block ID
} esp_ds_data_ctx_t;
```

The `esp_ds_data` structure (from `esp_ds.h`):
```c
typedef struct {
    int32_t length;           // (key_size / 32) - 1
    uint8_t iv[16];          // AES IV
    uint8_t c[ESP_DS_C_LEN];  // Encrypted RSA parameters
} esp_ds_data_t;
```

## Complete Parsing Flow

```
+------------------+     +--------------------+     +------------------+
| Read DS_DATA_TLV| --> | Extract length,   | --> | Read DS_CONTEXT  |
| from partition  |     | iv, ciphertext    |     | TLV for efuse_id|
+------------------+     +--------------------+     +------------------+
                                                                   |
                                                                   v
+------------------+     +--------------------+     +------------------+
| esp_ds_data_ctx_t|<----| Populate DS ctx   |<----| Get rsa_key_len |
| structure        |     | with parsed data  |     | from context    |
+------------------+     +--------------------+     +------------------+
```

## Example: Parsing Raw Binary Data

Given a binary partition file, here's how to extract and parse the DS data:

```python
import struct

def parse_esp_secure_cert_partition(data):
    # TLV header format: magic(4) + flags(4) + type(2) + subtype(2) + length(2)
    offset = 0

    ds_data = None
    ds_context = None

    while offset < len(data):
        magic = struct.unpack('<I', data[offset:offset+4])[0]

        if magic != 0xBA5EBA11:  # ESP_SECURE_CERT_TLV_MAGIC
            break

        flags = struct.unpack('<I', data[offset+4:offset+8])[0]
        tlv_type = struct.unpack('<H', data[offset+8:offset+10])[0]
        subtype = struct.unpack('<H', data[offset+10:offset+12])[0]
        length = struct.unpack('<H', data[offset+12:offset+14])[0]

        # Skip header to get to data
        data_offset = offset + 14

        if tlv_type == 3:  # ESP_SECURE_CERT_DS_DATA_TLV
            ds_data = {
                'length': struct.unpack('<i', data[data_offset:data_offset+4])[0],
                'iv': data[data_offset+4:data_offset+20],
                'ciphertext': data[data_offset+20:data_offset+20+length-20]
            }
        elif tlv_type == 4:  # ESP_SECURE_CERT_DS_CONTEXT_TLV
            ds_context = {
                'efuse_key_id': data[data_offset+4],
                'rsa_key_len': struct.unpack('<H', data[data_offset+6:data_offset+8])[0]
            }

        # Move to next TLV (account for padding and CRC footer)
        padding = (16 - (length % 16)) % 16
        offset += 14 + length + padding + 4  # header + data + padding + CRC

    return ds_data, ds_context
```

## Notes

1. **On-device decryption**: The decryption of the DS ciphertext must happen on the ESP device itself, as it requires access to the HMAC key stored in eFuse.

2. **TLV alignment**: Each TLV entry is padded to a 16-byte boundary, and the total TLV includes a 4-byte CRC32 footer.

3. **Key sizes**: The supported RSA key sizes vary by chip:
   - ESP32-S2, ESP32-S3, ESP32-P4: 1024, 2048, 3072, 4096 bits
   - ESP32-C3, ESP32-C6, ESP32-H2: 1024, 2048, 3072 bits

4. **Reference implementation**: See `srcs/esp_secure_cert_tlv_read.c` in this repository for the official C implementation of DS data parsing.
