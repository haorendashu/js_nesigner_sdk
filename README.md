# js_nesigner_sdk

js_nesigner_sdk is a JavaScript SDK for interacting with the [nesigner](https://github.com/haorendashu/nesigner) hardware device. nesigner is an ESP32-based application designed to sign and process Nostr messages. It leverages USB interfaces to receive, process, and respond to messages. The project is built using ESP-IDF and integrates with components like TinyUSB for USB connectivity.

## Installation

```bash
npm install js_nesigner_sdk
```

## Features

- Get public key
- Event signing
- NIP-04 encryption/decryption
- NIP-44 encryption/decryption
- Device management (update key, remove key, etc.)
- Connectivity testing

## Usage

Check demo [here](https://github.com/haorendashu/js_nesigner_sdk/blob/main/index.html).

### Basic Example

```javascript
import { getSerialPort, createNesigner } from 'js_nesigner_sdk';

// Connect to device
const port = await getSerialPort();
const nesigner = await createNesigner(port, 'your_pin_code');

// Get public key
const publicKey = await nesigner.getPublicKey();
console.log('Public Key:', publicKey);

// Sign event
const signature = await nesigner.sign('event_id_hex_string');
console.log('Signature:', signature);

// Encrypt/decrypt
const encrypted = await nesigner.encrypt(otherPublicKey, 'Hello, World!');
const decrypted = await nesigner.decrypt(otherPublicKey, encrypted);
console.log('Decrypted:', decrypted);

// NIP44 Encrypt/decrypt
const encryptedNip44 = await nesigner.nip44Encrypt(otherPublicKey, 'Hello, World!');
const decryptedNip44 = await nesigner.nip44Decrypt(otherPublicKey, encryptedNip44);
console.log('Decrypted NIP44:', decryptedNip44);
```

## API Interface

The `NesignerInterface` provides the following methods:

### Core Functions

- **`getPublicKey(): Promise<string | null>`**  
  Gets the public key from the device.

- **`encrypt(pubkey: string, plaintext: string): Promise<string | null>`**  
  Performs NIP-04 encryption with the specified public key.

- **`decrypt(pubkey: string, ciphertext: string): Promise<string | null>`**  
  Performs NIP-04 decryption with the specified public key.

- **`nip44Encrypt(pubkey: string, plaintext: string): Promise<string | null>`**  
  Performs NIP-44 encryption with the specified public key.

- **`nip44Decrypt(pubkey: string, ciphertext: string): Promise<string | null>`**  
  Performs NIP-44 decryption with the specified public key.

- **`sign(eventId: string): Promise<string | null>`**  
  Signs the specified event ID.

- **`close(): Promise<void>`**  
  Closes the connection.

### Device Management

- **`updateKey(pinCode: string, key: string): Promise<number>`**  
  Updates the key on the device using PIN code.

- **`removeKey(pinCode: string): Promise<number>`**  
  Removes the key from the device using PIN code.

### Diagnostic Functions

- **`ping(): Promise<number | null>`**  
  Tests device connectivity, returns latency.

- **`echo(pinCode: string, msgContent: string): Promise<string | null>`**  
  Sends an echo message for testing.