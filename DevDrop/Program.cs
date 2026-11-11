using DevDrop.Core;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DevDrop
{
    internal class Program
    {
        private static bool isRunning = true;
        private static RSA? rsa;
        private static CancellationTokenSource? cts;

        static void Main(string[] args)
        {
            while (isRunning)
            {
                Console.Clear();
                DrawHeader("DEV DROP - SECURE MESSAGING", ConsoleColor.Magenta);
                Console.WriteLine(" 1. Get Key (Start 10m Timer)");
                Console.WriteLine(" 2. Encrypt String");
                Console.WriteLine(" 3. Decrypt String");
                Console.WriteLine(" 4. Exit");
                Console.Write("\n Select an option: ");

                var input = Console.ReadLine();
                if (!int.TryParse(input, out int choice)) continue;

                switch (choice)
                {
                    case 1: GetKeyMenu(); break;
                    case 2: EncryptStringMenu(); break;
                    case 3: DecryptStringMenu(); break;
                    case 4:
                        {
                            DetonateMethod();
                            isRunning = false; break;

                        }

                        }
                }
            }

        #region Logic Methods

        private static void GetKeyMenu()
        {
            Console.Clear();
            string pubKey = GenerateKey();

            DrawHeader("YOUR PUBLIC KEY", ConsoleColor.Cyan);
            Console.WriteLine(pubKey);
            Console.WriteLine("╚" + new string('═', 62) + "╝");

            Console.WriteLine("\n [!] Press any key to COPY to clipboard");
            Console.ReadKey();

            CopyToClipboard(pubKey);
            StartWatch();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n Key copied! Key Is Only Valid for 10 minutes.");
            Console.ResetColor();
            PauseAndContinue("");
        }

        private static void EncryptStringMenu()
        {
            using (RSA encryptionRsa = RSA.Create())
            {
                Console.Clear();
                DrawHeader("ENCRYPTION MODE", ConsoleColor.Blue);
                Console.WriteLine(" Paste the recipient's Public Key:");
                string keyInput = Console.ReadLine()?.Replace(" ", "+");

                try
                {
                    byte[] keyBytes = Convert.FromBase64String(keyInput);
                    encryptionRsa.ImportRSAPublicKey(keyBytes, out _);
                }
                catch
                {
                    PauseAndContinue(" Invalid Key Format.");
                    return;
                }

                Console.WriteLine("\n Enter the Secret Message (finish with an empty line):");
                string rawSecret = ReadMultilineInput();
                if (string.IsNullOrEmpty(rawSecret)) return;

                string secret = rawSecret.Trim();
                if (TryNormalizeJsonInput(secret, out string normalizedSecret))
                {
                    Console.WriteLine(" [Valid JSON received]");
                    secret = normalizedSecret;
                }

                byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
                try
                {
                    string payload = EncryptPayload(secretBytes, encryptionRsa);

                    DrawHeader("ENCRYPTED PAYLOAD", ConsoleColor.Yellow);
                    Console.WriteLine(payload);
                    Console.WriteLine("╚" + new string('═', 62) + "╝");

                    Console.WriteLine("\n Press any key to copy payload to clipboard...");
                    Console.ReadKey();
                    CopyToClipboard(payload);
                }
                catch (Exception ex)
                {
                    PauseAndContinue($" Encryption failed: {ex.Message}");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(secretBytes);
                }
            }
        }

        private static void DecryptStringMenu()
        {
            if (rsa == null)
            {
                PauseAndContinue(" No private key found! You must 'Get Key' first.");
                return;
            }

            Console.Clear();
            DrawHeader("DECRYPTION MODE", ConsoleColor.Green);
            Console.WriteLine(" Paste the Encrypted Payload:");
            string input = Console.ReadLine()?.Replace(" ", "+");
            if (!string.IsNullOrWhiteSpace(input))
            {
                input = DecodeUnicodeEscapes(input);
            }

            try
            {
                string plainText = DecryptPayload(input, rsa);

                DrawHeader("DECRYPTED MESSAGE", ConsoleColor.Green);
                Console.WriteLine($" > {plainText}");
                Console.WriteLine("╚" + new string('═', 62) + "╝");

                Console.WriteLine("\n Read carefully. Press any key to WIPE RAM and EXIT.");
                Console.ReadKey();
                DetonateMethod();
                Environment.Exit(0);
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n Decryption failed! The payload may be corrupt or the key expired.");
                Console.ResetColor();
                PauseAndContinue("");
            }
        }

        #endregion

        #region Helper Tools

        private static string DecodeUnicodeEscapes(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return input;
            }

            StringBuilder sb = new StringBuilder(input.Length);
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] == '\\' && i + 5 < input.Length && input[i + 1] == 'u')
                {
                    string hex = input.Substring(i + 2, 4);
                    if (int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out int code))
                    {
                        sb.Append((char)code);
                        i += 5;
                        continue;
                    }
                }

                sb.Append(input[i]);
            }

            return sb.ToString();
        }

        private static string EncryptPayload(byte[] data, RSA encryptionRsa) =>
            PayloadCrypto.Encrypt(data, encryptionRsa);

        private static string DecryptPayload(string input, RSA decryptionRsa)
        {
            // Any failure (bad format, wrong key, tampered data) propagates to the caller,
            // which reports a generic "decryption failed". There is no legacy/raw-RSA fallback.
            if (!TryParsePayload(input, out var payload))
            {
                throw new InvalidOperationException("Unrecognized payload format.");
            }

            return PayloadCrypto.Decrypt(payload, decryptionRsa);
        }

        private static bool TryParsePayload(string input, out EncryptedPayload payload)
        {
            payload = null;
            if (string.IsNullOrWhiteSpace(input))
            {
                return false;
            }

            try
            {
                payload = JsonSerializer.Deserialize<EncryptedPayload>(input);
            }
            catch
            {
                payload = null;
            }

            if (payload != null && !string.IsNullOrWhiteSpace(payload.Key) && !string.IsNullOrWhiteSpace(payload.Data))
            {
                return true;
            }

            string trimmed = input.Trim();
            if (trimmed.StartsWith("{") && trimmed.EndsWith("}"))
            {
                trimmed = trimmed[1..^1];
            }

            string key = null;
            string data = null;
            string[] parts = trimmed.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (string part in parts)
            {
                if (part.StartsWith("Key", StringComparison.OrdinalIgnoreCase))
                {
                    key = ExtractPayloadValue(part);
                }
                else if (part.StartsWith("Data", StringComparison.OrdinalIgnoreCase))
                {
                    data = ExtractPayloadValue(part);
                }
            }

            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(data))
            {
                return false;
            }

            payload = new EncryptedPayload { Key = key, Data = data };
            return true;
        }

        private static string ExtractPayloadValue(string part)
        {
            int idx = part.IndexOf(':');
            if (idx < 0 || idx == part.Length - 1)
            {
                return null;
            }

            string value = part[(idx + 1)..].Trim();
            if (value.StartsWith("\"") && value.EndsWith("\""))
            {
                value = value[1..^1];
            }

            return value;
        }

        private static string ReadMultilineInput()
        {
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                string line = Console.ReadLine();
                if (string.IsNullOrEmpty(line))
                {
                    break;
                }
                sb.AppendLine(line);
            }

            return sb.ToString().Trim();
        }

        private static bool TryNormalizeJsonInput(string input, out string normalized)
        {
            normalized = input?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(normalized))
            {
                return false;
            }

            if (TryParseJson(normalized))
            {
                return true;
            }

            string candidate = TrimTrailingComma(normalized);
            bool startsObject = candidate.StartsWith("{");
            bool startsArray = candidate.StartsWith("[");
            bool endsObject = candidate.EndsWith("}");
            bool endsArray = candidate.EndsWith("]");

            if (!startsObject && !startsArray)
            {
                candidate = "{\n" + candidate;
            }

            if (!endsObject && !endsArray)
            {
                candidate += "\n}";
            }

            if (TryParseJson(candidate))
            {
                normalized = candidate;
                return true;
            }

            normalized = input?.Trim() ?? string.Empty;
            return false;
        }

        private static bool TryParseJson(string input)
        {
            try
            {
                using var _ = JsonDocument.Parse(input);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string TrimTrailingComma(string input)
        {
            string trimmed = input.TrimEnd();
            while (trimmed.EndsWith(",", StringComparison.Ordinal))
            {
                trimmed = trimmed[..^1].TrimEnd();
            }

            return trimmed;
        }

        private static string GenerateKey()
        {
            // Replacing a key must not leave the previous private key alive.
            rsa?.Dispose();
            rsa = RSA.Create(2048);
            return Convert.ToBase64String(rsa.ExportRSAPublicKey());
        }

        public static void StartWatch()
        {
            // Restarting replaces the previous timer instead of stacking watchers.
            // A superseded timer is cancelled only through its own source and never detonates.
            cts?.Cancel();
            var current = new CancellationTokenSource();
            cts = current;

            Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(10), current.Token);
                }
                catch (OperationCanceledException)
                {
                    return; // superseded by a newer key
                }

                DetonateMethod();
                Environment.Exit(0);
            });
        }

        public static void DetonateMethod()
        {
            if (rsa != null)
            {
                rsa.Dispose();
                rsa = null;
            }
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("DATA WIPED. PROCESS TERMINATED.");
            Console.ResetColor();
        }

        private static void CopyToClipboard(string text)
        {
            try
            {
                // Pass the text through stdin so quotes/JSON are never interpreted by a shell.
                ProcessStartInfo psi = new ProcessStartInfo("clip.exe")
                {
                    RedirectStandardInput = true,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using Process? p = Process.Start(psi);
                if (p == null) return;
                // Payloads and keys are ASCII (Base64/JSON), so ASCII avoids a BOM and codepage issues.
                byte[] bytes = Encoding.ASCII.GetBytes(text);
                p.StandardInput.BaseStream.Write(bytes, 0, bytes.Length);
                p.StandardInput.Close();
                p.WaitForExit(2000);
            }
            catch { }
        }

        private static void DrawHeader(string title, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine("╔" + new string('═', 62) + "╗");
            Console.WriteLine("║ " + title.PadRight(61) + "║");
            Console.WriteLine("╠" + new string('═', 62) + "╣");
            Console.ResetColor();
        }

        private static void PauseAndContinue(string message)
        {
            if (!string.IsNullOrEmpty(message)) Console.WriteLine($"\n {message}");
            Console.WriteLine(" Press any key to continue...");
            Console.ReadKey();
        }

        #endregion
    }
}
