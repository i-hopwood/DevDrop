using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DevDrop_UI.ViewModels;

public class EncryptedPayload
{
    public string Key { get; set; } = string.Empty;
    public string Data { get; set; } = string.Empty;
}

public partial class MainWindowViewModel : ObservableObject
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

    [RelayCommand]
    private async Task GenerateKeys()
    {
        try
        {
            _rsa = RSA.Create(2048);
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
    private async Task Encrypt()
    {
        if (string.IsNullOrWhiteSpace(RecipientPublicKey) || string.IsNullOrWhiteSpace(SecretMessage)) return;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(RecipientPublicKey.Trim()), out _);
            var data = Encoding.UTF8.GetBytes(SecretMessage);
            EncryptedPayload = await Task.Run(() => DoEncrypt(data, rsa));
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
            byte[] keyMat = _rsa.Decrypt(Convert.FromBase64String(payload!.Key), RSAEncryptionPadding.OaepSHA256);
            byte[] key = new byte[32]; byte[] iv = new byte[16];
            Buffer.BlockCopy(keyMat, 0, key, 0, 32); Buffer.BlockCopy(keyMat, 32, iv, 0, 16);
            using Aes aes = Aes.Create();
            using var ms = new MemoryStream(Convert.FromBase64String(payload.Data));
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read);
            using var sr = new StreamReader(cs, Encoding.UTF8);
            DecryptedMessage = sr.ReadToEnd();
            UpdateStatus("✓ Decrypted", "#4CAF50");
        }
        catch { UpdateStatus("✗ Decryption Failed", "#F44336"); }
    }

    [RelayCommand]
    private void DismissStatus()
    {
        IsStatusVisible = false;
        _statusCts?.Cancel();
    }

    private string DoEncrypt(byte[] data, RSA rsa)
    {
        using Aes aes = Aes.Create();
        aes.GenerateKey(); aes.GenerateIV();
        byte[] encData;
        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(data, 0, data.Length); cs.FlushFinalBlock();
                encData = ms.ToArray();
            }
        }
        byte[] keyMat = new byte[48];
        Buffer.BlockCopy(aes.Key, 0, keyMat, 0, 32); Buffer.BlockCopy(aes.IV, 0, keyMat, 32, 16);
        return JsonSerializer.Serialize(new EncryptedPayload
        {
            Key = Convert.ToBase64String(rsa.Encrypt(keyMat, RSAEncryptionPadding.OaepSHA256)),
            Data = Convert.ToBase64String(encData)
        });
    }

    private async Task StartTimer(CancellationToken ct)
    {
        for (int i = 600; i >= 0 && !ct.IsCancellationRequested; i--)
        {
            TimeRemaining = i;
            await Task.Delay(1000, ct);
        }
        if (!ct.IsCancellationRequested) Detonate();
    }

    [RelayCommand]
    private void Detonate()
    {
        _timerCts?.Cancel(); _rsa?.Dispose(); _rsa = null;
        MyPublicKey = ""; DecryptedMessage = ""; IsKeyValid = false;
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
        await Task.Delay(3000, ct);
        if (!ct.IsCancellationRequested) IsStatusVisible = false;
    }
}