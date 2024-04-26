using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class ATM
{
    private static double balance = 0; // Initial balance
    private static Dictionary<string, (string hashedPassword, string accountNumber)> users = new Dictionary<string, (string, string)>();
    private static HashSet<string> usedAccountNumbers = new HashSet<string>();
    private static string loggedInUser = "";
    private const string dataFilePath = "userdata.txt";
    private const string keyFilePath = "key.txt";  //  File to store the encryption key

    static void Main(string[] args)
    {
        // GenerateAndSaveKey();   THIS IS NOT CURRENTLY WORKING....TROUBLESHOOTING BUG
        LoadUserData(); // Load user data from file
        Console.WriteLine("Welcome to the Newdle Bank ATM");

        int choice;
        do
        {
            if (loggedInUser == "")
            {
                Console.WriteLine("\n1. Login");
                Console.WriteLine("2. Create User");
                Console.WriteLine("3. Exit");
                Console.Write("Enter your choice: ");
            }
            else
            {
                Console.WriteLine("\n1. Check Balance");
                Console.WriteLine("2. Deposit");
                Console.WriteLine("3. Withdraw");
                Console.WriteLine("4. Sign Out");
                Console.WriteLine("5. Exit");
                Console.Write("Enter your choice: ");
            }

            if (int.TryParse(Console.ReadLine(), out choice))
            {
                switch (choice)
                {
                    case 1:
                        if (loggedInUser == "")
                            Login();
                        else
                            CheckBalance();
                        break;
                    case 2:
                        if (loggedInUser == "")
                            CreateUser();
                        else
                            Deposit();
                        break;
                    case 3:
                        if (loggedInUser == "")
                            return; // Exit the program
                        else
                            Withdraw();
                        break;
                    case 4:
                        if (loggedInUser != "")
                        {
                            loggedInUser = "";
                            Console.WriteLine("\nSigned out successfully.");
                        }
                        else
                        {
                            Console.WriteLine("Invalid choice. Please try again.");
                        }
                        break;
                    case 5:
                        Console.WriteLine("Exiting...");
                        SaveUserData(); // Save user data before exiting
                        return;
                    default:
                        Console.WriteLine("Invalid choice. Please try again.");
                        break;
                }
            }
            else
            {
                Console.WriteLine("Invalid input. Please enter a number.");
                Console.ReadLine(); // Clear buffer
            }

        } while (true); // Loop indefinitely until the user chooses to exit
    }

    static void LoadUserData()
    {
        if (File.Exists(dataFilePath))
        {
            string key = GetEncryptionKey();
            if (key == null)
            {
                Console.WriteLine("Encryption key not found.  Exiting.");
                Environment.Exit(1);
            }

            foreach (string line in File.ReadAllLines(dataFilePath))
            {
                string decryptedLine = DecryptString(line, key);
                string[] parts = decryptedLine.Split(',');
                if (parts.Length == 4)
                {
                    string username = parts[0];
                    string hashedPassword = parts[1];
                    string accountNumber = parts[2];
                    double accountBalance = double.Parse(parts[3]);
                    users.Add(username, (hashedPassword, accountNumber));
                    balance = accountBalance; // Update the global balance variable
                }
            }
        }
    }

    static void SaveUserData()
    {
        string key = GetEncryptionKey();
        if (key == null)
        {
            Console.WriteLine("Encryption key not found.  Exiting.");
            Environment.Exit(1);
        }

        using (StreamWriter writer = new StreamWriter(dataFilePath))
        {
            foreach (var user in users)
            {
                string encryptedLine = EncryptString($"{user.Key},{user.Value.hashedPassword},{user.Value.accountNumber},{balance}", key);
                writer.WriteLine(encryptedLine);
            }
        }
    }

    static void CreateUser()
    {
        Console.Write("\nEnter Username: ");
        string newUsername = Console.ReadLine();

        if (!users.ContainsKey(newUsername))
        {
            Console.Write("Enter Password: ");
            string newPassword = GetHiddenConsoleInput();
            string hashedPassword = HashPassword(newPassword);
            string accountNumber = GenerateUniqueAccountNumber();
            users.Add(newUsername, (hashedPassword, accountNumber));
            Console.WriteLine($"\nUser created successfully. Account number: {accountNumber}");
            SaveUserData(); // Save user data after creating a new user
        }
        else
        {
            Console.WriteLine("\nUsername already exists. Please choose a different username.");
        }
    }

    static string HashPassword(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            StringBuilder builder = new StringBuilder();
            foreach (byte b in hashedBytes)
            {
                builder.Append(b.ToString("x2"));
            }
            return builder.ToString();
        }
    }

    static void Login()
    {
        Console.Write("\nEnter Username: ");
        string inputUsername = Console.ReadLine();
        Console.Write("Enter Password: ");
        string inputPassword = GetHiddenConsoleInput();

        if (users.TryGetValue(inputUsername, out (string hashedPassword, string _) user) && HashPassword(inputPassword) == user.hashedPassword)
        {
            loggedInUser = inputUsername;
            Console.WriteLine("\nLogin successful.");
        }
        else
        {
            Console.WriteLine("\nInvalid username or password.");
        }
    }

    static string GetHiddenConsoleInput()
    {
        StringBuilder input = new StringBuilder();
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
                if (input.Length > 0)
                {
                    input.Remove(input.Length - 1, 1);
                    Console.Write("\b \b");  // Move cursor back, erase character, move cursor back again
                }
            }
            else
            {
                input.Append(key.KeyChar);
                Console.Write("*");
            }
        }
        return input.ToString();
    }

    static void CheckBalance()
    {
        Console.WriteLine($"\nYour current balance is: ${balance}");
    }

    static void Deposit()
    {
        Console.Write("\nEnter the amount to deposit: $");
        if (double.TryParse(Console.ReadLine(), out double amount) && amount > 0)
        {
            balance += amount;
            Console.WriteLine($"\n${amount} deposited successfully.");
        }
        else
        {
            Console.WriteLine("\nInvalid amount. Please enter a valid positive number.");
        }
    }

    static void Withdraw()
    {
        Console.Write("\nEnter the amount to withdraw: $");
        if (double.TryParse(Console.ReadLine(), out double amount) && amount > 0)
        {
            if (amount <= balance)
            {
                balance -= amount;
                Console.WriteLine($"\n${amount} withdrawn successfully.");
            }
            else
            {
                Console.WriteLine("\nInsufficient funds.");
            }
        }
        else
        {
            Console.WriteLine("\nInvalid amount. Please enter a valid positive number.");
        }
    }

    static string GenerateUniqueAccountNumber()
    {
        Random rnd = new Random();
        string accountNumber;
        do
        {
            accountNumber = rnd.Next(100000000, 999999999).ToString() + rnd.Next(100000000, 999999999).ToString();
        } while (!usedAccountNumbers.Add(accountNumber));
        return accountNumber;
    }

    static string EncryptString(string text, string key)
    {
        using (Aes aesAlg = Aes.Create())
        {
            // Ensure that the key length is correct
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] validKey = new byte[32];  // AES 256-bit key size
            Array.Copy(keyBytes, validKey, Math.Min(keyBytes.Length, validKey.Length));
            aesAlg.Key = validKey;

            aesAlg.IV = new byte[16]; // Initialization vector

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(text);
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }
    }

    static string DecryptString(string cipherText, string key)
    {
        using (Aes aesAlg = Aes.Create())
        {
            // Ensure that the key length is correct
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] validKey = new byte[32];  // AES 256-bit key size
            Array.Copy(keyBytes, validKey, Math.Min(keyBytes.Length, validKey.Length));
            aesAlg.Key = validKey;

            aesAlg.IV = new byte[16]; // Initialization vector

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }

    static string GetEncryptionKey()
    {
        if (File.Exists(keyFilePath))
        {
            return File.ReadAllText(keyFilePath);
        }
        else
        {
            Console.WriteLine("Encryption key not found.");
            return null;
        }
    }

    /*                                     NOT USING BELOW CODE AT THIS TIME!!!!
       static void GenerateAndSaveKey()
    {
        // Generate a secure random key
        byte[] keyBytes = new byte[32]; // 256 bits
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(keyBytes);
        }

        // Convert the byte array to a hexadecimal string
        StringBuilder keyBuilder = new StringBuilder();
        foreach (byte b in keyBytes)
        {
            keyBuilder.Append(b.ToString("x2"));
        }
        string key = keyBuilder.ToString();

        // Save the key to a file
        string keyFilePath = "key.txt";
        File.WriteAllText(keyFilePath, key);

        Console.WriteLine("Secure key generated and saved to key.txt");
    }*/
}
