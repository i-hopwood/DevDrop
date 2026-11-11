# DevDrop

DevDrop is a lightweight utility for the ephemeral exchange of encrypted secrets. This repository includes:

- **Avalonia UI version** (`DevDrop UI`)
- **Console version** (`DevDrop`)
- **Shared crypto library** (`DevDrop.Core`), used by both apps
- **Tests** (`DevDrop.Tests`)

## Security Model
- **Hybrid encryption:** each message is encrypted with a random AES-256-GCM key. That key is wrapped with the receiver's RSA-2048 public key using RSA-OAEP (SHA-256).
- **Authenticated:** AES-GCM detects any modification of the payload. Tampered, truncated or wrong-key payloads fail to decrypt.
- **Volatile private key:** the private key stays in memory only and is never written to disk.
- **Self-destruct timer:** 10 minutes after a key is generated, the private key is disposed and the app wipes its state. Generating a new key replaces the old one and restarts the timer.
- **Best-effort memory hygiene:** AES keys and plaintext byte buffers are zeroed after use, and the private key is disposed. Managed strings (for example the decrypted text on screen) cannot be reliably zeroed, so don't treat this as protection against a memory dump or a compromised machine.
- **Clipboard exchange:** keys and payloads are designed for copy/paste. Clipboard contents are not cleared automatically.

### Payload format
A payload is a JSON object:

```json
{ "Key": "<Base64 RSA-wrapped AES key>", "Data": "<Base64 nonce(12) | tag(16) | ciphertext>" }
```

> **Compatibility:** this format replaced the earlier AES-CBC format. Payloads created by older builds can't be decrypted.

### Limitations
- **No public-key authentication.** DevDrop does not verify that a public key really belongs to the person you think it does. Share keys over a channel you trust, as an attacker who swaps the key can read the secret.
- **No sender authentication.** Anyone holding your public key can send you a payload.

## Version 1: Avalonia UI
A guided desktop workflow for sender and receiver.

### UI Operational Flow
1. **Receiver:** clicks **Generate New RSA Key**. The public key is copied to the clipboard and a 10-minute timer starts.
2. **Receiver:** shares the public key with the sender over a trusted channel.
3. **Sender:** pastes the key, types the secret and clicks **Encrypt**. The plaintext is cleared from the box after a successful encrypt.
4. **Sender:** sends the encrypted payload back to the receiver.
5. **Receiver:** pastes the payload and clicks **Decrypt**.
6. **Termination:** **Clear Cache** or the timer wipes all fields and disposes the private key.

### Run
```bash
dotnet run --project "DevDrop UI/DevDrop UI.csproj"
```

## Version 2: Console App
The terminal-driven workflow.

### Console Operational Flow
1. **Receiver:** selects **Get Key**. The key is copied to the clipboard and the 10-minute timer starts.
2. **Receiver:** shares the public key with the sender.
3. **Sender:** selects **Encrypt String**, pastes the key and enters the secret. The payload is copied to the clipboard.
4. **Sender:** returns the payload to the receiver.
5. **Receiver:** selects **Decrypt String**, pastes the payload and reads the result.
6. **Termination:** the app exits after decryption, on **Exit**, or when the timer expires. The key is disposed.

Notes:
- The console app may rewrite a secret that is almost JSON. If your secret isn't valid JSON but becomes valid when wrapped in `{ }`, it is wrapped before encryption. Multi-line input ends at the first blank line.
- The clipboard is set through `clip.exe`, so this app is Windows-only.

### Run
```bash
dotnet run --project "DevDrop/DevDrop.csproj"
```

## Tests
```bash
dotnet test DevDrop.Tests/DevDrop.Tests.csproj
```
The tests cover the shared crypto: round trips, tamper detection, wrong keys and malformed payloads. The UI app and the console app's input handling and clipboard code are not covered by automated tests.

## Requirements
- **Runtime:** .NET 10 SDK
- **Platform:** Windows recommended. The console app requires it for clipboard support.
