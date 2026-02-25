# DevDrop

DevDrop is a lightweight, security console utility designed for the ephemeral exchange of encrypted secrets. It utilizes RSA-2048 encryption with a volatile memory architecture. Once a private key is generated, it exists only in RAM and is automatically wiped after a 10-minute duration.

## Technical Overview
* **Asymmetric Encryption:** Uses RSA-OAEP with SHA256 hashing for modern, robust padding.
* **Volatile Architecture:** Private keys are never committed to non-volatile storage (HDD/SSD).
* **Self-Destruct Logic:** Implements a background watchdog using `CancellationTokenSource` and `WaitHandle` to ensure resource disposal.
* **Automated Clipboard Integration:** Utilizes system-level piping to manage public keys and payloads efficiently.

## Operational Flow
1. **Receiver:** Selects option to generate a key. An internal 10-minute timer begins immediately.
2. **Receiver:** Provides the Public Key to the Sender via a secure communication channel.
3. **Sender:** Loads the Public Key, encrypts the desired secret, and generates a Base64 payload.
4. **Sender:** Provides the Encrypted Payload back to the Receiver.
5. **Receiver:** Decrypts the payload to view the secret. 
6. **Termination:** Upon manual acknowledgment or timer expiration, the application clears sensitive buffers, disposes of the RSA object, and terminates the process.

## Installation and Requirements
* **Runtime:** .NET 6.0 SDK or later.
* **Environment:** Windows (required for automated clipboard functionality).

To run the application:
```bash
dotnet build
dotnet run
