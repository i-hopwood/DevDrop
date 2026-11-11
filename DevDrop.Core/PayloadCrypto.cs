using System.Security.Cryptography;
using System.Text.Json;

namespace DevDrop.Core;

/// <summary>Wire format: a JSON object with the RSA-wrapped AES key and the AES-GCM data blob.</summary>
public sealed class EncryptedPayload
{
    public string Key { get; set; } = string.Empty;
    public string Data { get; set; } = string.Empty;
}

/// <summary>
/// Hybrid encryption used by both DevDrop apps: a random AES-256-GCM key encrypts the message,
/// and that key is wrapped with RSA-OAEP-SHA256. Data blob layout: nonce(12) | tag(16) | ciphertext.
/// </summary>
public static class PayloadCrypto
{
    public const int AesKeySize = 32;
    public const int GcmNonceSize = 12;
    public const int GcmTagSize = 16;

    /// <summary>Encrypts <paramref name="plaintext"/> for the holder of <paramref name="publicKey"/>; returns payload JSON.</summary>
    public static string Encrypt(byte[] plaintext, RSA publicKey)
    {
        byte[] key = RandomNumberGenerator.GetBytes(AesKeySize);
        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
            byte[] tag = new byte[GcmTagSize];
            byte[] cipher = new byte[plaintext.Length];

            using (var gcm = new AesGcm(key, GcmTagSize))
            {
                gcm.Encrypt(nonce, plaintext, cipher, tag);
            }

            byte[] blob = new byte[GcmNonceSize + GcmTagSize + cipher.Length];
            Buffer.BlockCopy(nonce, 0, blob, 0, GcmNonceSize);
            Buffer.BlockCopy(tag, 0, blob, GcmNonceSize, GcmTagSize);
            Buffer.BlockCopy(cipher, 0, blob, GcmNonceSize + GcmTagSize, cipher.Length);

            return JsonSerializer.Serialize(new EncryptedPayload
            {
                Key = Convert.ToBase64String(publicKey.Encrypt(key, RSAEncryptionPadding.OaepSHA256)),
                Data = Convert.ToBase64String(blob)
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Decrypts a payload with <paramref name="privateKey"/>. Throws <see cref="CryptographicException"/>
    /// (or <see cref="FormatException"/> for bad Base64) if the payload is malformed, was tampered with,
    /// or was encrypted for a different key.
    /// </summary>
    public static string Decrypt(EncryptedPayload payload, RSA privateKey)
    {
        byte[] key = privateKey.Decrypt(Convert.FromBase64String(payload.Key), RSAEncryptionPadding.OaepSHA256);
        byte[]? plain = null;
        try
        {
            if (key.Length != AesKeySize) throw new CryptographicException("Unexpected key length.");

            byte[] blob = Convert.FromBase64String(payload.Data);
            if (blob.Length < GcmNonceSize + GcmTagSize) throw new CryptographicException("Payload too short.");

            int cipherOffset = GcmNonceSize + GcmTagSize;
            var nonce = new ReadOnlySpan<byte>(blob, 0, GcmNonceSize);
            var tag = new ReadOnlySpan<byte>(blob, GcmNonceSize, GcmTagSize);
            var cipher = new ReadOnlySpan<byte>(blob, cipherOffset, blob.Length - cipherOffset);

            plain = new byte[cipher.Length];
            using var gcm = new AesGcm(key, GcmTagSize);
            gcm.Decrypt(nonce, cipher, tag, plain); // throws if the data was modified
            return System.Text.Encoding.UTF8.GetString(plain);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (plain != null) CryptographicOperations.ZeroMemory(plain);
        }
    }
}
