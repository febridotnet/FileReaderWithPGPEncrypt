using System;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== PGP File Decryptor v1.0 ===");

        string configPath = Path.Combine(AppContext.BaseDirectory, "config.inf");

        if (!File.Exists(configPath))
        {
            Console.WriteLine("config.inf tidak ditemukan!");
            return;
        }

        var config = LoadConfig(configPath);
        ValidateConfig(config);

        var files = Directory.GetFiles(config.InboundFolder, "*.pgp", SearchOption.AllDirectories);

        Console.WriteLine($"Total file .pgp: {files.Length}");
        foreach (var file in files)
        {
            bool success = false;

            try
            {
                Console.WriteLine($"Processing: {file}");

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
                        "HCM_SIT_id26".ToCharArray()
                    );

                    if (!success)
                    {
                        string msg = $"Decrypt gagal: {file}";
                        Console.WriteLine(msg);
                        LogError(msg);
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

                MoveToArchive(file, config.ArchivedFolder);
            }
            catch (Exception ex)
            {
                string errorMsg = $"File: {file} | Error: {ex.Message}";
                Console.WriteLine(errorMsg);
                LogError(errorMsg);

                System.Threading.Thread.Sleep(200);
            }
        }
        Console.WriteLine("=== SELESAI ===");
    }

    static bool DecryptFileSafe(Stream inputStream, Stream outputStream, Stream privateKeyStream, char[] passPhrase)
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

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData compressedData)
            {
                Stream compressedStream = compressedData.GetDataStream();
                PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedStream);
                object innerMessage = compressedFactory.NextPgpObject();
                bool dataDitemukan = false;

                // Loop terus menerus sampai isi data (PgpLiteralData) ditemukan
                while (innerMessage != null)
                {
                    if (innerMessage is PgpLiteralData literalData)
                    {
                        Stream unc = literalData.GetInputStream();
                        Streams.PipeAll(unc, outputStream);
                        outputStream.Flush();
                    }
                    innerMessage = compressedFactory.NextPgpObject();
                }
            }
            else if (message is PgpLiteralData literalData)
            {
                Stream unc = literalData.GetInputStream();
                Streams.PipeAll(unc, outputStream);
            }
            else
            {
                return false;
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
                case "privatekeypath":
                    config.PrivateKeyPath = value;
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

    static void MoveToArchive(string sourceFile, string archiveFolder)
    {
        try
        {
            string fileName = Path.GetFileName(sourceFile);

            string destPath = Path.Combine(archiveFolder, fileName);

            if (File.Exists(destPath))
            {
                string newFileName = Path.GetFileNameWithoutExtension(fileName)
                    + "_" + DateTime.Now.ToString("yyyyMMddHHmmss")
                    + Path.GetExtension(fileName);

                destPath = Path.Combine(archiveFolder, newFileName);
            }

            File.Move(sourceFile, destPath);

            Console.WriteLine($"Moved to archive -> {destPath}");
        }
        catch (Exception ex)
        {
            LogError($"Gagal move file ke archive: {sourceFile} | {ex.Message}");
        }
    }

}

class Config
{
    public string InboundFolder { get; set; }
    public string OutboundFolder { get; set; }
    public string ArchivedFolder { get; set; }
    public string PrivateKeyPath { get; set; }
    public string Passphrase { get; set; }
}