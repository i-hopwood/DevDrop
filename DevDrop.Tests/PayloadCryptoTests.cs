using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DevDrop.Core;
using Xunit;

namespace DevDrop.Tests;

public class PayloadCryptoTests : IDisposable
{
    private readonly RSA _receiver = RSA.Create(2048);

    public void Dispose() => _receiver.Dispose();

    /// <summary>Sender side: only the public key is used, as in the real exchange.</summary>
    private string EncryptFor(RSA receiver, string message)
    {
        using var senderView = RSA.Create();
        senderView.ImportRSAPublicKey(receiver.ExportRSAPublicKey(), out _);
        return PayloadCrypto.Encrypt(Encoding.UTF8.GetBytes(message), senderView);
    }

    private static EncryptedPayload Parse(string json) =>
        JsonSerializer.Deserialize<EncryptedPayload>(json)!;

    private static string Serialize(EncryptedPayload p) => JsonSerializer.Serialize(p);

    // --- round trips -------------------------------------------------------------------

    [Theory]
    [InlineData("hello")]
    [InlineData("")]
    [InlineData("  leading and trailing whitespace  ")]
    [InlineData("line one\r\n\r\nline three after a blank line")]
    [InlineData("{\"user\":\"admin\",\"password\":\"p@ss+w0rd/=\"}")]
    [InlineData("ünïcödé ✓ 日本語 🔐")]
    public void RoundTrip_ReturnsOriginalText(string message)
    {
        string json = EncryptFor(_receiver, message);

        Assert.Equal(message, PayloadCrypto.Decrypt(Parse(json), _receiver));
    }

    [Fact]
    public void RoundTrip_LargeMessage()
    {
        string message = new string('x', 1_000_000);

        string json = EncryptFor(_receiver, message);

        Assert.Equal(message, PayloadCrypto.Decrypt(Parse(json), _receiver));
    }

    [Fact]
    public void Payload_IsValidJson_WithKeyAndDataFields()
    {
        // Regression: the console app's clipboard copy used to strip the quotes from this JSON.
        string json = EncryptFor(_receiver, "secret");

        using var doc = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.String, doc.RootElement.GetProperty("Key").ValueKind);
        Assert.Equal(JsonValueKind.String, doc.RootElement.GetProperty("Data").ValueKind);
    }

    [Fact]
    public void Payload_DoesNotContainPlaintext()
    {
        const string message = "correct horse battery staple";

        string json = EncryptFor(_receiver, message);

        Assert.DoesNotContain(message, json);
        byte[] blob = Convert.FromBase64String(Parse(json).Data);
        Assert.False(blob.AsSpan().IndexOf(Encoding.UTF8.GetBytes(message)) >= 0);
    }

    [Fact]
    public void DataBlob_HasExpectedLayout()
    {
        byte[] plaintext = new byte[100];

        string json = PayloadCrypto.Encrypt(plaintext, _receiver);

        byte[] blob = Convert.FromBase64String(Parse(json).Data);
        Assert.Equal(PayloadCrypto.GcmNonceSize + PayloadCrypto.GcmTagSize + plaintext.Length, blob.Length);
    }

    [Fact]
    public void Encrypt_IsRandomised()
    {
        string a = EncryptFor(_receiver, "same message");
        string b = EncryptFor(_receiver, "same message");

        Assert.NotEqual(Parse(a).Key, Parse(b).Key);   // fresh AES key each time
        Assert.NotEqual(Parse(a).Data, Parse(b).Data); // fresh nonce each time
    }

    // --- integrity: GCM must reject any modification --------------------------------------

    [Theory]
    [InlineData(0)]                                                  // nonce
    [InlineData(PayloadCrypto.GcmNonceSize)]                         // tag
    [InlineData(PayloadCrypto.GcmNonceSize + PayloadCrypto.GcmTagSize)] // first ciphertext byte
    public void TamperedData_IsRejected(int byteIndex)
    {
        var payload = Parse(EncryptFor(_receiver, "do not touch"));
        byte[] blob = Convert.FromBase64String(payload.Data);
        blob[byteIndex] ^= 0x01;
        payload.Data = Convert.ToBase64String(blob);

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(payload, _receiver));
    }

    [Fact]
    public void TamperedLastCiphertextByte_IsRejected()
    {
        var payload = Parse(EncryptFor(_receiver, "do not touch"));
        byte[] blob = Convert.FromBase64String(payload.Data);
        blob[^1] ^= 0x80;
        payload.Data = Convert.ToBase64String(blob);

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(payload, _receiver));
    }

    [Fact]
    public void AppendedBytes_AreRejected()
    {
        var payload = Parse(EncryptFor(_receiver, "do not touch"));
        payload.Data = Convert.ToBase64String(Convert.FromBase64String(payload.Data).Append((byte)0).ToArray());

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(payload, _receiver));
    }

    [Fact]
    public void TamperedWrappedKey_IsRejected()
    {
        var payload = Parse(EncryptFor(_receiver, "do not touch"));
        byte[] wrapped = Convert.FromBase64String(payload.Key);
        wrapped[10] ^= 0x01;
        payload.Key = Convert.ToBase64String(wrapped);

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(payload, _receiver));
    }

    [Fact]
    public void KeyAndDataFromDifferentMessages_AreRejected()
    {
        var first = Parse(EncryptFor(_receiver, "first"));
        var second = Parse(EncryptFor(_receiver, "second"));
        var mixed = new EncryptedPayload { Key = first.Key, Data = second.Data };

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(mixed, _receiver));
    }

    // --- wrong key / malformed input ------------------------------------------------------

    [Fact]
    public void WrongPrivateKey_IsRejected()
    {
        string json = EncryptFor(_receiver, "for the receiver only");
        using var other = RSA.Create(2048);

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(Parse(json), other));
    }

    [Fact]
    public void RegeneratedKey_CannotDecryptOldPayload()
    {
        // Mirrors "Get Key" being pressed again: the old private key is gone.
        string json = EncryptFor(_receiver, "old message");
        using var regenerated = RSA.Create(2048);

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(Parse(json), regenerated));
    }

    [Fact]
    public void DataShorterThanNonceAndTag_IsRejected()
    {
        var payload = Parse(EncryptFor(_receiver, "x"));
        payload.Data = Convert.ToBase64String(new byte[PayloadCrypto.GcmNonceSize + PayloadCrypto.GcmTagSize - 1]);

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(payload, _receiver));
    }

    [Fact]
    public void WrappedKeyOfWrongLength_IsRejected()
    {
        // A validly RSA-wrapped key that is not 32 bytes must not reach AES.
        using var senderView = RSA.Create();
        senderView.ImportRSAPublicKey(_receiver.ExportRSAPublicKey(), out _);
        var payload = Parse(EncryptFor(_receiver, "x"));
        payload.Key = Convert.ToBase64String(
            senderView.Encrypt(new byte[16], RSAEncryptionPadding.OaepSHA256));

        Assert.ThrowsAny<CryptographicException>(() => PayloadCrypto.Decrypt(payload, _receiver));
    }

    [Theory]
    [InlineData("not base64!!", "AAAA")]
    [InlineData("AAAA", "not base64!!")]
    public void InvalidBase64_IsRejected(string key, string data)
    {
        var payload = new EncryptedPayload { Key = key, Data = data };

        Assert.ThrowsAny<Exception>(() => PayloadCrypto.Decrypt(payload, _receiver));
    }

    [Fact]
    public void EmptyFields_AreRejected()
    {
        Assert.ThrowsAny<Exception>(() => PayloadCrypto.Decrypt(new EncryptedPayload(), _receiver));
    }

    [Fact]
    public void LegacyRawRsaPayload_IsRejected()
    {
        // The old console format (RSA-encrypted plaintext, no JSON) no longer has a fallback.
        using var senderView = RSA.Create();
        senderView.ImportRSAPublicKey(_receiver.ExportRSAPublicKey(), out _);
        string legacy = Convert.ToBase64String(
            senderView.Encrypt(Encoding.UTF8.GetBytes("legacy"), RSAEncryptionPadding.OaepSHA256));

        var payload = new EncryptedPayload { Key = legacy, Data = legacy };

        Assert.ThrowsAny<Exception>(() => PayloadCrypto.Decrypt(payload, _receiver));
    }

    // --- sender only ever needs the public key ------------------------------------------

    [Fact]
    public void ExportedPublicKey_RoundTripsThroughBase64()
    {
        // The exact path the apps use: ExportRSAPublicKey -> Base64 -> paste -> ImportRSAPublicKey.
        string pasted = Convert.ToBase64String(_receiver.ExportRSAPublicKey());
        using var sender = RSA.Create();
        sender.ImportRSAPublicKey(Convert.FromBase64String(pasted), out _);

        string json = PayloadCrypto.Encrypt(Encoding.UTF8.GetBytes("via pasted key"), sender);

        Assert.Equal("via pasted key", PayloadCrypto.Decrypt(Parse(json), _receiver));
    }

    [Fact]
    public void PayloadSurvivesJsonSerializeParseCycle()
    {
        string json = EncryptFor(_receiver, "persisted");

        string again = Serialize(Parse(json));

        Assert.Equal("persisted", PayloadCrypto.Decrypt(Parse(again), _receiver));
    }
}
