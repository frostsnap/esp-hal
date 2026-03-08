# esp-ds - ESP32 Digital Signature Provisioning Tool

CLI tool for provisioning ESP32-C3 devices with RSA-3072 Digital Signature (DS) keys.

## Generate Certificates

```bash
# Generate CA key and certificate (RSA-3072, 100 year expiry)
openssl req -newkey rsa:3072 -nodes -keyout ca.key -x509 -days 36500 -out cacert.pem -subj "/CN=Test CA"

# Generate device private key (RSA-3072)
openssl genrsa -out device.key 3072

# Generate device CSR
openssl req -out device.csr -key device.key -new -subj "/CN=Test Device"

# Sign device certificate with CA
openssl x509 -req -days 36500 -in device.csr -CA cacert.pem -CAkey ca.key -sha256 -CAcreateserial -out device.crt
```

## Usage

### With Existing eFuse HMAC Key

If the device already has an HMAC key burned in eFuse BLOCK_KEY2:

```bash
esp-ds --ca-cert cacert.pem \
       --device-cert device.crt \
       --device-key device.key \
       --read-efuse-key \
       --port /dev/ttyACM0
```

This will:
1. Read HMAC key from eFuse BLOCK_KEY2
2. Encrypt DS params using the existing key
3. Save to `data/esp32c3-<MAC>/ds_data.bin`

### With New HMAC Key

To generate a new HMAC key and burn it to eFuse:

```bash
esp-ds --ca-cert cacert.pem \
       --device-cert device.crt \
       --device-key device.key \
       --port /dev/ttyACM0 \
       --burn-efuse
```

### Flash to Device

After generating the provisioning data:

```bash
# Flash the partition
esptool --chip esp32c3 --port /dev/ttyACM0 write_flash 0xD000 \
    esp-ds/data/esp32c3-<MAC>/ds_data.bin
```

## Output Files

- `ds_data.bin` - Bincode-encoded factory data (flash to partition)
- `ds_hmac_key.bin` - HMAC key (32 bytes, for eFuse burning)

## Flash Partition

The DS data is flashed to the `esp_secure_cert` partition at offset `0xD000` (8KB).

## CLI Options

```
--ca-cert <PATH>           CA certificate in PEM format (required)
--device-cert <PATH>      Device certificate in PEM format (required)
--device-key <PATH>       Device private key in PEM format (required)
--read-efuse-key          Read existing HMAC key from eFuse instead of generating new
-p, --port <PORT>         Serial port for flashing
--flash                   Flash to esp_secure_cert partition
--burn-efuse              Burn HMAC key to eFuse BLOCK_KEY2
```

## Example: Full Provisioning Flow

```bash
# 1. Generate new HMAC key and provision device
esp-ds --ca-cert esp-ds/cacert.pem \
       --device-cert esp-ds/device.crt \
       --device-key esp-ds/device.key \
       --port /dev/ttyACM0 \
       --burn-efuse

# 2. Flash the partition (note: use the MAC address from step 1)
esptool --chip esp32c3 --port /dev/ttyACM0 write_flash 0xD000 \
    esp-ds/data/esp32c3-b8f862b4da18/ds_data.bin
```

## DS Signature Process

1. HMAC key is burned to eFuse BLOCK_KEY2 with purpose `HMAC_DOWN_DIGITAL_SIGNATURE`
2. DS params (RSA private key encrypted with AES-256-CBC) are stored in flash
3. At runtime, HMAC module derives the AES key from eFuse
4. DS peripheral uses the AES key to decrypt params and perform RSA signing
