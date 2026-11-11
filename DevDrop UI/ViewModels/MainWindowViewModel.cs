using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DevDrop.Core;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DevDrop_UI.ViewModels;

public partial class MainWindowViewModel : ObservableObject, IDisposable
{
    [ObservableProperty] private string _myPublicKey = string.Empty;
    [ObservableProperty] private string _recipientPublicKey = string.Empty;
    [ObservableProperty] private string _secretMessage = string.Empty;
    [ObservableProperty] private string _encryptedPayload = string.Empty;
    [ObservableProperty] private string _pastedPayload = string.Empty;
    [ObservableProperty] private string _decryptedMessage = string.Empty;
    [ObservableProperty] private int _timeRemaining = 0;
    [ObservableProperty] private bool _isKeyValid = false;
    [ObservableProperty] private string _statusMessage = string.Empty;
    [ObservableProperty] private string _statusColor = "#4CAF50";
    [ObservableProperty] private bool _isStatusVisible = false;

    private RSA? _rsa;
    private CancellationTokenSource? _timerCts;
    private CancellationTokenSource? _statusCts;
    private bool _disposed = false;

    [RelayCommand]
    private async Task GenerateKeys()
    {
        try
        {
            // Replacing a key must not leave the previous private key (or its plaintext) alive.
            _rsa?.Dispose();
            _rsa = RSA.Create(2048);
            DecryptedMessage = "";
            MyPublicKey = Convert.ToBase64String(_rsa.ExportRSAPublicKey());
            IsKeyValid = true;
            _timerCts?.Cancel();
            _timerCts = new CancellationTokenSource();
            _ = StartTimer(_timerCts.Token);
            await CopyToClipboard(MyPublicKey);
            UpdateStatus("✓ Generated & Copied", "#4CAF50");
        }
        catch (Exception ex) { UpdateStatus($"Error: {ex.Message}", "#F44336"); }
    }

    [RelayCommand]
    private async Task CopyPublicKey()
    {
        if (string.IsNullOrEmpty(MyPublicKey)) return;
        await CopyToClipboard(MyPublicKey);
        UpdateStatus("✓ Copied", "#4CAF50");
    }

    [RelayCommand]
    private async Task Encrypt()
    {
        if (string.IsNullOrWhiteSpace(RecipientPublicKey) || string.IsNullOrWhiteSpace(SecretMessage)) return;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(RecipientPublicKey.Trim()), out _);
            var data = Encoding.UTF8.GetBytes(SecretMessage);
            try
            {
                EncryptedPayload = await Task.Run(() => DoEncrypt(data, rsa));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(data);
            }

            // Don't leave the plaintext on screen: a sender-only session never starts the key timer.
            SecretMessage = "";
            UpdateStatus("✓ Encrypted", "#4CAF50");
        }
        catch { UpdateStatus("✗ Encryption Failed", "#F44336"); }
    }

    [RelayCommand]
    private void Decrypt()
    {
        if (_rsa == null || string.IsNullOrWhiteSpace(PastedPayload)) return;
        try
        {
            var payload = JsonSerializer.Deserialize<EncryptedPayload>(PastedPayload.Trim());
            if (payload == null || string.IsNullOrWhiteSpace(payload.Key) || string.IsNullOrWhiteSpace(payload.Data))
            {
                UpdateStatus("✗ Invalid Payload", "#F44336");
                return;
            }

            DecryptedMessage = DoDecrypt(payload, _rsa);
            UpdateStatus("✓ Decrypted", "#4CAF50");
        }
        catch { UpdateStatus("✗ Decryption Failed", "#F44336"); }
    }

    private static string DoDecrypt(EncryptedPayload payload, RSA rsa) => PayloadCrypto.Decrypt(payload, rsa);

    [RelayCommand]
    private void DismissStatus()
    {
        IsStatusVisible = false;
        _statusCts?.Cancel();
    }

    private static string DoEncrypt(byte[] data, RSA rsa) => PayloadCrypto.Encrypt(data, rsa);

    private async Task StartTimer(CancellationToken ct)
    {
        try
        {
            for (int i = 600; i > 0; i--)
            {
                TimeRemaining = i;
                await Task.Delay(1000, ct);
            }
        }
        catch (OperationCanceledException)
        {
            return; // cancelled by Detonate, a new key, or shutdown
        }

        if (!ct.IsCancellationRequested) Detonate();
    }

    [RelayCommand]
    private void Detonate()
    {
        _timerCts?.Cancel(); _rsa?.Dispose(); _rsa = null;

        MyPublicKey = "";
        RecipientPublicKey = "";
        SecretMessage = "";
        EncryptedPayload = "";
        PastedPayload = "";
        DecryptedMessage = "";
        TimeRemaining = 0;
        IsKeyValid = false;

        UpdateStatus("🔐 Wiped", "#D83B01");
    }

    private async Task CopyToClipboard(string t)
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d)
        {
            var cb = TopLevel.GetTopLevel(d.MainWindow)?.Clipboard;
            if (cb != null) await cb.SetTextAsync(t);
        }
    }

    private void UpdateStatus(string m, string c)
    { 
        StatusMessage = m; 
        StatusColor = c;
        IsStatusVisible = true;
        _statusCts?.Cancel();
        _statusCts = new CancellationTokenSource();
        _ = AutoHideStatus(_statusCts.Token);
    }

    private async Task AutoHideStatus(CancellationToken ct)
    {
        try
        {
            await Task.Delay(3000, ct);
        }
        catch (OperationCanceledException)
        {
            return; // replaced by a newer status or dismissed
        }

        if (!ct.IsCancellationRequested) IsStatusVisible = false;
    }

    // Memory cleanup when app closes
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Cancel all background tasks
        _timerCts?.Cancel();
        _statusCts?.Cancel();

        // Dispose RSA key
        _rsa?.Dispose();
        _rsa = null;

        // Clear sensitive data
        MyPublicKey = "";
        SecretMessage = "";
        RecipientPublicKey = "";
        EncryptedPayload = "";
        PastedPayload = "";
        DecryptedMessage = "";
        StatusMessage = "";

        GC.SuppressFinalize(this);
    }
}
