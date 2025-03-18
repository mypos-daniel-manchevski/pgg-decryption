using System.Diagnostics;
using PgpCore;

namespace PgpDecrypt;

class Program
{
    private const string openPgpExePath = @"C:\Program Files (x86)\GnuPG\bin\gpg.exe";
    private const string encryptedFilePath = @"C:\Data\FT\service\kleo_encrypted.gpg";
    private const string outputFilePath = @"C:\Data\FT\service\net-decrypted_file.txt";
    private const string privateKeyPath = @"C:\Users\daniel.manchevski\Downloads\BNPP-TEST-sftp_0x66DB15A6_SECRET.asc";
    private const string passphrase = "V8s8^75RI#Bv";

    static async Task Main(string[] args)
    {
        // This uses gpg.exe to decrypt
        Console.WriteLine("OpenPgp:");
        await UseOpenPgp();

        // This uses Dotnet PgpCore lib to decrypt
        Console.WriteLine("\nPgpCore lib:");
        await UseLib();
    }

    static async Task UseOpenPgp()
    {
        {
            // Step 1: Import the private key.
            string importArguments = $"--batch --yes --import \"{privateKeyPath}\"";
            ProcessStartInfo importInfo = new ProcessStartInfo
            {
                FileName = openPgpExePath,
                Arguments = importArguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using (Process importProcess = new Process { StartInfo = importInfo })
                {
                    importProcess.Start();
                    string importOutput = await importProcess.StandardOutput.ReadToEndAsync();
                    string importError = await importProcess.StandardError.ReadToEndAsync();
                    importProcess.WaitForExit();

                    if (importProcess.ExitCode != 0)
                    {
                        Console.WriteLine("Private key import failed with error: " + importError);
                        return;
                    }
                    else
                    {
                        Console.WriteLine("Private key imported successfully.");
                        //Console.WriteLine("Decryption Output: " + importOutput);
                    }
                }

                // Step 2: Decrypt the file.
                string decryptArguments =
                    $"--batch --yes --passphrase \"{passphrase}\" --output \"{outputFilePath}\" --decrypt \"{encryptedFilePath}\"";
                ProcessStartInfo decryptInfo = new ProcessStartInfo
                {
                    FileName = openPgpExePath,
                    Arguments = decryptArguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process decryptProcess = new Process { StartInfo = decryptInfo })
                {
                    decryptProcess.Start();
                    string decryptOutput = await decryptProcess.StandardOutput.ReadToEndAsync();
                    string decryptError = await decryptProcess.StandardError.ReadToEndAsync();
                    decryptProcess.WaitForExit();

                    if (decryptProcess.ExitCode == 0)
                    {
                        Console.WriteLine("Decryption successful. Output written to " + outputFilePath);
                        //Console.WriteLine("Decryption Output: " + decryptOutput);
                    }
                    else
                    {
                        Console.WriteLine("Decryption failed with exit code: " + decryptProcess.ExitCode);
                        Console.WriteLine("Error: " + decryptError);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error during processing: " + ex.Message);
            }
        }
    }

    static async Task UseLib()
    {
        string fileContent = File.ReadAllText(privateKeyPath);

        try
        {
            FileInfo privateKey = new FileInfo(privateKeyPath);
            EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, passphrase);

            FileInfo inputFile = new FileInfo(encryptedFilePath);
            FileInfo decryptedFile = new FileInfo(outputFilePath);

            PGP pgp = new PGP(encryptionKeys);
            await pgp.DecryptAsync(inputFile, decryptedFile); Console.WriteLine("Decryption successful. Output written to " + outputFilePath);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error during decryption: " + ex.Message);
        }
    }

}