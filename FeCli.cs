using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

class FeCli
{
    private static readonly byte[] FileSignature = Encoding.ASCII.GetBytes("FECLI"); // magic bytes

    static void Main(string[] args)
    {
        if (args.Length == 0 || args[0].ToLower() == "help")
        {
            ShowHelp();
            return;
        }

        string command = args[0].ToLower();

        if (args.Length < 2)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Error: Missing file name.");
            Console.ResetColor();
            return;
        }

        string filePath = args[1];

        if (!File.Exists(filePath))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Error: File not found - " + filePath);
            Console.ResetColor();
            return;
        }

        try
        {
            switch (command)
            {
                case "encrypt":
                    if (IsFileEncrypted(filePath))
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Info: This file is already encrypted.");
                        Console.ResetColor();
                        return;
                    }

                    Console.Write("Enter password: ");
                    string encPwd = ReadPassword();

                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("Create backup before encryption? (y/n): ");
                    string choice = Console.ReadLine().ToLower();
                    bool makeBackup = (choice == "y" || choice == "yes");
                    Console.ResetColor();

                    EncryptFile(filePath, encPwd, makeBackup);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("File successfully encrypted: " + filePath);
                    Console.ResetColor();
                    break;

                case "decrypt":
                    if (!IsFileEncrypted(filePath))
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Info: This file is not encrypted.");
                        Console.ResetColor();
                        return;
                    }

                    Console.Write("Enter password: ");
                    string decPwd = ReadPassword();

                    DecryptFile(filePath, decPwd);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("File successfully decrypted: " + filePath);
                    Console.ResetColor();
                    break;

                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error: Unknown command - " + command);
                    ShowHelp();
                    Console.ResetColor();
                    break;
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Error: Access denied. Please check file permissions.");
            Console.ResetColor();
        }
        catch (IOException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("File I/O Error: " + ex.Message);
            Console.ResetColor();
        }
        catch (CryptographicException)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Error: Incorrect password or corrupted file.");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Unexpected Error: " + ex.Message);
            Console.ResetColor();
        }
    }

    private static void ShowHelp()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("                 FeCli 1.5                        ");
        Console.WriteLine("         Small Tool, Strong Protection            ");
        Console.WriteLine();
        Console.ResetColor();

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("How to use it:");
        Console.ResetColor();
        Console.WriteLine("  fecli help                 Show this menu");
        Console.WriteLine("  fecli encrypt <filename>   Lock (encrypt) your file");
        Console.WriteLine("  fecli decrypt <filename>   Unlock (decrypt) your file");
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("Examples:");
        Console.ResetColor();
        Console.WriteLine("  fecli encrypt \"D:\\file1.txt\"");
        Console.WriteLine("  fecli decrypt \"D:\\file1.txt\"");
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("    Copyright (c) 2015 - 2025 Ari Sohandri Putra.");
        Console.WriteLine("    All rights reserved.");
        Console.WriteLine("    https://github.com/arisohandriputra/FeCli");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static bool IsFileEncrypted(string filePath)
    {
        byte[] header = new byte[FileSignature.Length];
        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            if (fs.Length < FileSignature.Length)
                return false;
            fs.Read(header, 0, header.Length);
        }

        // Compare byte by byte
        if (header.Length != FileSignature.Length)
            return false;

        for (int i = 0; i < FileSignature.Length; i++)
        {
            if (header[i] != FileSignature[i])
                return false;
        }

        return true;
    }


    private static string ReadPassword()
    {
        StringBuilder pwd = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            else if (key.Key == ConsoleKey.Backspace)
            {
                if (pwd.Length > 0)
                {
                    pwd.Remove(pwd.Length - 1, 1);
                    Console.Write("\b \b");
                }
            }
            else
            {
                pwd.Append(key.KeyChar);
                Console.Write("*");
            }
        }
        return pwd.ToString();
    }

    private static byte[] GetAesKey(string password)
    {
        SHA256 sha = SHA256.Create();
        return sha.ComputeHash(Encoding.UTF8.GetBytes(password));
    }

    private static void EncryptFile(string filePath, string password, bool makeBackup)
    {
        byte[] plainBytes = File.ReadAllBytes(filePath);
        byte[] key = GetAesKey(password);

        using (RijndaelManaged aes = new RijndaelManaged())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;

            using (MemoryStream ms = new MemoryStream())
            {
                // Write signature + IV
                ms.Write(FileSignature, 0, FileSignature.Length);
                ms.Write(aes.IV, 0, aes.IV.Length);

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, plainBytes.Length);
                    cs.FlushFinalBlock();
                }

                if (makeBackup)
                {
                    File.Copy(filePath, filePath + ".bak", true);
                }

                File.WriteAllBytes(filePath, ms.ToArray());
            }
        }
    }

    private static void DecryptFile(string filePath, string password)
    {
        byte[] cipherBytes = File.ReadAllBytes(filePath);
        byte[] key = GetAesKey(password);

        using (RijndaelManaged aes = new RijndaelManaged())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.Mode = CipherMode.CBC;

            // Extract signature + IV
            byte[] signature = new byte[FileSignature.Length];
            Array.Copy(cipherBytes, 0, signature, 0, signature.Length);

            byte[] iv = new byte[16];
            Array.Copy(cipherBytes, signature.Length, iv, 0, iv.Length);
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cipherBytes, signature.Length + iv.Length, cipherBytes.Length - signature.Length - iv.Length);
                    cs.FlushFinalBlock();
                }
                File.WriteAllBytes(filePath, ms.ToArray());
            }
        }
    }
}
