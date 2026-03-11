# DevDrop

DevDrop is a lightweight, security-focused utility for the ephemeral exchange of encrypted secrets. This repository includes two implementations:

- **Avalonia UI version** (primary desktop experience)
- **Console version** (legacy/compatibility workflow)

Both versions use the same core cryptographic approach: RSA-2048 encryption, in-memory private key handling, and timed key disposal.

## Shared Security Model
- **Asymmetric Encryption:** RSA-OAEP with SHA256 padding.
- **Volatile Key Handling:** Private keys remain in memory only.
- **Self-Destruct Timer:** Private key material is automatically invalidated after 10 minutes.
- **Clipboard-Friendly Exchange:** Designed for quick copy/paste transfer of keys and encrypted payloads.

## Version 1: Avalonia UI (Primary)
The UI app provides a guided desktop workflow for receiver/sender operations.

### UI Operational Flow
1. **Receiver:** Generates a key pair in the UI; a 10-minute timer starts.
2. **Receiver:** Shares the public key with the sender through a secure channel.
3. **Sender:** Uses the public key to encrypt a secret and produce a Base64 payload.
4. **Sender:** Sends the encrypted payload back to the receiver.
5. **Receiver:** Decrypts and views the secret in the app.
6. **Termination:** On completion or timeout, sensitive buffers are cleared and crypto resources are disposed.

### Run the UI App
```bash
dotnet build "DevDrop UI/DevDrop UI.csproj"
dotnet run --project "DevDrop UI/DevDrop UI.csproj"
```

## Version 2: Console App (Legacy)
The console app preserves the original terminal-driven workflow.

### Console Operational Flow
1. **Receiver:** Selects the option to generate a key; the 10-minute timer starts.
2. **Receiver:** Shares the public key with the sender.
3. **Sender:** Loads the public key and encrypts the secret into a Base64 payload.
4. **Sender:** Returns the encrypted payload to the receiver.
5. **Receiver:** Decrypts the payload in the console to view the secret.
6. **Termination:** On acknowledgment or timeout, key material is cleared and RSA resources are disposed.

### Run the Console App
```bash
dotnet build "DevDrop/DevDrop.csproj"
dotnet run --project "DevDrop/DevDrop.csproj"
```

## Installation and Requirements
- **Runtime:** .NET 10 SDK (workspace target).
- **Environment:** Windows recommended (clipboard-focused workflows)
