using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DevDrop
{
    internal class Program
    {
        private static bool isRunning = true;
        private static RSA rsa;
        private static CancellationTokenSource cts = new CancellationTokenSource();
        private static CancellationToken token = cts.Token;

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
                    case 4: isRunning = false; break;
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

                Console.WriteLine("\n Enter the Secret Message:");
                string secret = Console.ReadLine();
                if (string.IsNullOrEmpty(secret)) return;

                byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
                try
                {
                    byte[] encrypted = encryptionRsa.Encrypt(secretBytes, RSAEncryptionPadding.OaepSHA256);
                    string base64Encrypted = Convert.ToBase64String(encrypted);

                    DrawHeader("ENCRYPTED PAYLOAD", ConsoleColor.Yellow);
                    Console.WriteLine(base64Encrypted);
                    Console.WriteLine("╚" + new string('═', 62) + "╝");

                    Console.WriteLine("\n Press any key to copy payload to clipboard...");
                    Console.ReadKey();
                    CopyToClipboard(base64Encrypted);
                }
                catch (Exception ex)
                {
                    PauseAndContinue($" Encryption failed: {ex.Message}");
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

            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(input);
                byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
                string plainText = Encoding.UTF8.GetString(decryptedBytes);

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

        private static string GenerateKey()
        {
            rsa = RSA.Create(2048);
            return Convert.ToBase64String(rsa.ExportRSAPublicKey());
        }

        public static void StartWatch()
        {
            cts.CancelAfter(TimeSpan.FromMinutes(10));
            Task.Run(() =>
            {
                token.WaitHandle.WaitOne();
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
                ProcessStartInfo psi = new ProcessStartInfo("powershell", $"-Command \"Set-Clipboard -Value '{text}'\"")
                {
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process.Start(psi);
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