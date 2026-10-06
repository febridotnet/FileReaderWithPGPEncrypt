using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

class Program
{
    static async Task Main(string[] args)
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellationTokenSource.Cancel();
        };

        Console.WriteLine("PGP File Decryptor scheduled for 6:00 AM, 12:00 PM, and 8:00 PM.");
        ExecuteRun();

        while (!cancellationTokenSource.IsCancellationRequested)
        {
            DateTime nextRun = GetNextRun(DateTime.Now);
            Console.WriteLine($"Next run: {nextRun:yyyy-MM-dd HH:mm:ss}");

            try
            {
                while (!cancellationTokenSource.IsCancellationRequested)
                {
                    TimeSpan remaining = nextRun - DateTime.Now;
                    if (remaining <= TimeSpan.Zero)
                        break;

                    if (!Console.IsOutputRedirected)
                    {
                        Console.Write($"\rCountdown to next run: {remaining:hh\\:mm\\:ss}   ");
                    }

                    await Task.Delay(
                        remaining < TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1),
                        cancellationTokenSource.Token);
                }

                if (!Console.IsOutputRedirected)
                    Console.WriteLine();
            }
            catch (OperationCanceledException) when (cancellationTokenSource.IsCancellationRequested)
            {
                break;
            }

            if (!cancellationTokenSource.IsCancellationRequested)
                ExecuteRun();
        }

        Console.WriteLine("Application closed by user.");
    }

    static void ExecuteRun()
    {
        try
        {
            Run();
        }
        catch (Exception ex)
        {
            string msg = $"Fatal error: {ex.InnerException?.Message ?? ex.Message}";
            Console.WriteLine(msg);
            LogError(msg);
        }
    }

    static DateTime GetNextRun(DateTime now)
    {
        int[] scheduledHours = [6, 12, 20];

        foreach (int hour in scheduledHours)
        {
            DateTime scheduledTime = now.Date.AddHours(hour);
            if (scheduledTime > now)
                return scheduledTime;
        }

        return now.Date.AddDays(1).AddHours(scheduledHours[0]);
    }

    static void Run()
    {
        string configPath = Path.Combine(AppContext.BaseDirectory, "config.inf");
        Console.WriteLine($"config path: {configPath}");
        Console.WriteLine();
        Console.WriteLine("=== PGP File Decryptor v1.0 ===");

        if (!File.Exists(configPath))
        {
            Console.WriteLine("config.inf tidak ditemukan!");
            return;
        }

        var config = LoadConfig(configPath);
        ValidateConfig(config);

        var files = Directory.GetFiles(config.InboundFolder, "*.pgp", SearchOption.TopDirectoryOnly);

        Console.WriteLine($"Total file .pgp: {files.Length}");
        foreach (var file in files)
        {
            bool success = false;

            try
            {
                Console.WriteLine($"Processing: {file}");

                Stream signingKeyStream = null;
                if (!string.IsNullOrWhiteSpace(config.SigningKeyPath) && File.Exists(config.SigningKeyPath))
                    signingKeyStream = File.OpenRead(config.SigningKeyPath);

                using (signingKeyStream)
                using (var inputStream = new FileStream(
                    file,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite
                ))
                using (var keyStream = File.OpenRead(config.PrivateKeyPath))
                using (var memoryStream = new MemoryStream())
                {
                    success = DecryptFileSafe(
                        inputStream,
                        memoryStream,
                        keyStream,
                        signingKeyStream,
                        "WTCID_Prod_26".ToCharArray()
                    );

                    if (!success)
                    {
                        string msg = $"Decrypt gagal: {file}";
                        Console.WriteLine(msg);
                        LogError(msg);
                        MoveFile(file, config.FailedFolder);
                        continue;
                    }
                    else
                    {
                        string content = System.Text.Encoding.UTF8.GetString(memoryStream.ToArray());

                        string outputFile = Path.Combine(
                            config.OutboundFolder,
                            Path.GetFileNameWithoutExtension(file) + ".csv"
                        );

                        File.WriteAllText(outputFile, content);

                        Console.WriteLine($"SUCCESS -> {outputFile}");
                    }
                }
                GC.Collect();
                GC.WaitForPendingFinalizers();
                System.Threading.Thread.Sleep(200);

                MoveFile(file, config.ArchivedFolder);
            }
            catch (Exception ex)
            {
                string errorMsg = $"File: {file} | Error: {ex.InnerException?.Message}";
                Console.WriteLine(errorMsg);
                LogError(errorMsg);
                MoveFile(file, config.FailedFolder);

                System.Threading.Thread.Sleep(200);
            }
        }
        Console.WriteLine("=== SELESAI ===");
    }

    static bool DecryptFileSafe(Stream inputStream, Stream outputStream, Stream privateKeyStream, Stream signingKeyStream, char[] passPhrase)
    {
        try
        {
            inputStream = Org.BouncyCastle.Bcpg.OpenPgp.PgpUtilities.GetDecoderStream(inputStream);

            PgpObjectFactory pgpFactory = new PgpObjectFactory(inputStream);
            PgpEncryptedDataList enc;

            object obj = pgpFactory.NextPgpObject();

            if (obj is PgpEncryptedDataList list)
                enc = list;
            else
                enc = (PgpEncryptedDataList)pgpFactory.NextPgpObject();

            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData encryptedData = null;

            PgpSecretKeyRingBundle keyRing =
                new PgpSecretKeyRingBundle(
                    Org.BouncyCastle.Bcpg.OpenPgp.PgpUtilities.GetDecoderStream(privateKeyStream));

            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(keyRing, pked.KeyId, passPhrase);
                if (privateKey != null)
                {
                    encryptedData = pked;
                    break;
                }
            }

            if (privateKey == null || encryptedData == null)
            {
                return false;
            }

            Stream clear = encryptedData.GetDataStream(privateKey);
            PgpObjectFactory plainFact = new PgpObjectFactory(clear);

            PgpPublicKeyRingBundle signingKeyRing = signingKeyStream == null
                ? null
                : new PgpPublicKeyRingBundle(
                    Org.BouncyCastle.Bcpg.OpenPgp.PgpUtilities.GetDecoderStream(signingKeyStream));

            List<PgpOnePassSignature> onePassSignatures = new List<PgpOnePassSignature>();
            PgpSignatureList signatureList = null;
            bool dataDitemukan = false;

            void ProcessPgpObject(object pgpObject)
            {
                if (pgpObject is PgpOnePassSignatureList onePassList)
                {
                    for (int i = 0; i < onePassList.Count; i++)
                    {
                        PgpOnePassSignature onePassSignature = onePassList[i];
                        if (signingKeyRing == null)
                            break;

                        PgpPublicKey publicKey = FindPublicKey(signingKeyRing, onePassSignature.KeyId);
                        if (publicKey != null)
                        {
                            onePassSignature.InitVerify(publicKey);
                            onePassSignatures.Add(onePassSignature);
                        }
                    }
                }
                else if (pgpObject is PgpLiteralData literalData)
                {
                    Stream unc = literalData.GetInputStream();
                    byte[] buffer = new byte[8192];
                    int read;

                    while ((read = unc.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        foreach (PgpOnePassSignature onePassSignature in onePassSignatures)
                            onePassSignature.Update(buffer, 0, read);

                        outputStream.Write(buffer, 0, read);
                    }

                    outputStream.Flush();
                    dataDitemukan = true;
                }
                else if (pgpObject is PgpSignatureList sigList)
                {
                    signatureList = sigList;
                }
            }

            object first = plainFact.NextPgpObject();

            if (first == null)
            {
                return false;
            }

            if (first is PgpCompressedData compressedData)
            {
                Stream compressedStream = compressedData.GetDataStream();
                PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedStream);

                // Loop terus menerus sampai isi data (PgpLiteralData) ditemukan
                object innerMessage = compressedFactory.NextPgpObject();
                while (innerMessage != null)
                {
                    ProcessPgpObject(innerMessage);
                    innerMessage = compressedFactory.NextPgpObject();
                }
            }
            else
            {
                ProcessPgpObject(first);

                object next;
                while ((next = plainFact.NextPgpObject()) != null)
                {
                    ProcessPgpObject(next);
                }
            }

            if (!dataDitemukan)
            {
                return false;
            }

            if (signingKeyStream != null && onePassSignatures.Count > 0)
            {
                if (signatureList == null || onePassSignatures.Count != signatureList.Count)
                {
                    return false;
                }

                for (int i = 0; i < onePassSignatures.Count; i++)
                {
                    if (!onePassSignatures[i].Verify(signatureList[i]))
                    {
                        return false;
                    }
                }
            }

            if (encryptedData.IsIntegrityProtected() && !encryptedData.Verify())
            {
                return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle keyRing, long keyId, char[] pass)
    {
        try
        {
            PgpSecretKey secretKey = keyRing.GetSecretKey(keyId);
            return secretKey?.ExtractPrivateKey(pass);
        }
        catch
        {
            return null;
        }
    }

    static PgpPublicKey FindPublicKey(PgpPublicKeyRingBundle keyRingBundle, long keyId)
    {
        try
        {
            PgpPublicKeyRing keyRing = keyRingBundle.GetPublicKeyRing(keyId);
            return keyRing?.GetPublicKey(keyId);
        }
        catch
        {
            return null;
        }
    }

    static Config LoadConfig(string path)
    {
        var config = new Config();

        foreach (var line in File.ReadAllLines(path))
        {
            var trimmed = line.Trim();

            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("[") || trimmed.StartsWith(";"))
                continue;

            var parts = trimmed.Split('=', 2);
            if (parts.Length != 2) continue;

            string key = parts[0].Trim().ToLower();
            string value = parts[1].Trim();

            switch (key)
            {
                case "inboundfolder":
                    config.InboundFolder = value;
                    break;
                case "outboundfolder":
                    config.OutboundFolder = value;
                    break;
                case "archivedfolder":
                    config.ArchivedFolder = value;
                    break;
                case "failedfolder":
                    config.FailedFolder = value;
                    break;
                case "privatekeypath":
                    config.PrivateKeyPath = value;
                    break;
                case "signingkey":
                    config.SigningKeyPath = value;
                    break;
            }
        }

        return config;
    }

    static void ValidateConfig(Config config)
    {
        if (!Directory.Exists(config.InboundFolder))
            throw new Exception("Inbound folder tidak valid");

        if (!Directory.Exists(config.OutboundFolder))
            Directory.CreateDirectory(config.OutboundFolder);

        if (!Directory.Exists(config.ArchivedFolder))
            Directory.CreateDirectory(config.ArchivedFolder);

        if (!Directory.Exists(config.FailedFolder))
            Directory.CreateDirectory(config.FailedFolder);

        if (!File.Exists(config.PrivateKeyPath))
            throw new Exception("Private key tidak ditemukan");
    }
    
    static void LogError(string message)
    {
        try
        {
            string logPath = Path.Combine(AppContext.BaseDirectory, "error.log");

            string logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] ERROR: {message}{Environment.NewLine}";

            File.AppendAllText(logPath, logMessage);
        }
        catch(Exception e)
        {
            Console.WriteLine($"Gagal menulis log error.\nError: {e.Message}");
        }
    }

    static void MoveFile(string sourceFile, string destinationFolder)
    {
        try
        {
            string fileName = Path.GetFileName(sourceFile);

            string destPath = Path.Combine(destinationFolder, fileName);

            if (File.Exists(destPath))
            {
                string newFileName = Path.GetFileNameWithoutExtension(fileName)
                    + "_" + DateTime.Now.ToString("yyyyMMddHHmmss")
                    + Path.GetExtension(fileName);

                destPath = Path.Combine(destinationFolder, newFileName);
            }

            File.Move(sourceFile, destPath);

            Console.WriteLine($"Moved to {destinationFolder} -> {destPath}");
            Console.WriteLine("");
        }
        catch (Exception ex)
        {
            LogError($"Gagal move file: {sourceFile} | {ex.Message}");
        }
    }

}

class Config
{
    public string InboundFolder { get; set; }
    public string OutboundFolder { get; set; }
    public string ArchivedFolder { get; set; }
    public string FailedFolder { get; set; }
    public string PrivateKeyPath { get; set; }
    public string SigningKeyPath { get; set; }
    public string Passphrase { get; set; }
}